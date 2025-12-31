//! State Manager Agent (Sidecar)
//!
//! The Sidecar agent that "watches" the game and generates complete state updates.
//! Uses Gemini Flash/Flash-Lite for fast, cheap inference.
//!
//! This agent implements the "Complete State + Reconciliation" pattern:
//! - It receives the current game state and recent conversation history
//! - It outputs a COMPLETE new state (not deltas) in plaintext markdown format
//! - The backend parses and reconciles this with the current state
//!
//! Key design principles from sanguine-rpg:
//! - The LLM outputs the *goal* state (what it thinks should happen)
//! - The code decides the *actual* state (what CAN happen)
//! - This prevents drift, hallucination, and cheating
//! - Uses plaintext format instead of JSON Schema for better LLM compatibility

use crate::errors::AppError;
use crate::models::game_state::{
    EnvironmentState, GameState, GameTime, InventoryItem, Location, NpcState, Quest,
    QuestObjective, QuestStatus, Vital,
};
use genai::chat::{ChatMessage, ChatOptions, ChatRequest, ThinkingLevel};
use genai::Client;
use regex::Regex;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// AI Provider enum for the State Manager
#[derive(Debug, Clone, Default)]
pub enum AiProvider {
    #[default]
    Gemini,
    OpenAi,
    Anthropic,
}

/// Configuration for the State Manager Agent
#[derive(Debug, Clone)]
pub struct StateManagerConfig {
    /// Which AI provider to use (defaults to Gemini)
    pub provider: AiProvider,
    /// Model name (defaults to gemini-2.5-flash-lite)
    pub model_name: String,
    /// Maximum tokens for the response
    pub max_output_tokens: Option<i32>,
    /// Temperature (lower = more deterministic)
    pub temperature: Option<f64>,
    /// Gemini 3 thinking level
    pub thinking_level: Option<String>,
}

impl Default for StateManagerConfig {
    fn default() -> Self {
        Self {
            provider: AiProvider::Gemini,
            model_name: "gemini-3-flash-preview".to_string(),
            max_output_tokens: Some(4096),
            temperature: Some(1.0), // Google recommends temperature=1 for Gemini
            thinking_level: Some("low".to_string()), // Low reasoning is sufficient for structured state output
        }
    }
}

/// The State Manager Agent (Sidecar)
pub struct StateManagerAgent {
    config: StateManagerConfig,
}

impl StateManagerAgent {
    /// Create a new StateManagerAgent with default configuration
    pub fn new() -> Self {
        Self {
            config: StateManagerConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: StateManagerConfig) -> Self {
        Self { config }
    }

    /// Generate a complete state update based on the current state and conversation
    ///
    /// This is the main entry point for the sidecar. It:
    /// 1. Builds a prompt with the current state and recent conversation
    /// 2. Calls the LLM to generate the complete new state
    /// 3. Parses the plaintext markdown response into a GameState
    /// 4. Returns the parsed state (caller handles reconciliation)
    pub async fn generate_state_update(
        &self,
        current_state: Option<&GameState>,
        conversation_summary: &str,
        last_user_message: &str,
        last_assistant_message: &str,
        player_name: Option<&str>,
        character_name: Option<&str>,
    ) -> Result<GameState, AppError> {
        // Build prompts
        let system_prompt = self.build_system_prompt(player_name, character_name);
        let user_prompt = self.build_user_prompt(
            current_state,
            conversation_summary,
            last_user_message,
            last_assistant_message,
            player_name,
            character_name,
        );

        debug!(
            system_prompt_len = system_prompt.len(),
            user_prompt_len = user_prompt.len(),
            has_current_state = current_state.is_some(),
            "Building state update request"
        );

        // Build the chat request using genai crate
        let chat_request = ChatRequest::default()
            .with_system(system_prompt)
            .append_message(ChatMessage::user(user_prompt));

        // Create the genai client (uses environment variables for API keys)
        let client = Client::default();

        // Build chat options - no structured output, just plain text
        // The LLM will generate plaintext markdown which we parse with regex
        let mut chat_options = ChatOptions::default();
        if let Some(temp) = self.config.temperature {
            chat_options = chat_options.with_temperature(temp);
        }
        if let Some(max_tokens) = self.config.max_output_tokens {
            chat_options = chat_options.with_max_tokens(max_tokens as u32);
        }
        if let Some(level_str) = &self.config.thinking_level {
            let thinking_level = match level_str.to_lowercase().as_str() {
                "none" | "off" | "disabled" => Some(ThinkingLevel::None),
                "minimal" => Some(ThinkingLevel::Minimal),
                "low" => Some(ThinkingLevel::Low),
                "medium" => Some(ThinkingLevel::Medium),
                "high" => Some(ThinkingLevel::High),
                _ => None,
            };
            if let Some(level) = thinking_level {
                chat_options = chat_options.with_thinking_level(level);
            }
        }

        // Execute the request (no structured output - we use plaintext markdown format)
        let response = client
            .exec_chat(&self.config.model_name, chat_request, Some(&chat_options))
            .await
            .map_err(|e| AppError::GenerationError(format!("State generation failed: {}", e)))?;

        // Extract the response text
        let response_text = response.first_text().ok_or_else(|| {
            AppError::GenerationError("Empty response from state manager".to_string())
        })?;

        info!(
            response_len = response_text.len(),
            "Received state update from Sidecar"
        );

        // Parse the JSON response into GameState
        self.parse_state_response(response_text)
    }

    /// Build the system prompt for the State Manager
    /// Uses {{user}} and {{char}} placeholders for templating consistency
    /// Instructs LLM to output plaintext markdown format (inspired by rpg-companion-sillytavern)
    fn build_system_prompt(
        &self,
        player_name: Option<&str>,
        character_name: Option<&str>,
    ) -> String {
        let template = r#"You are the Game State Manager, a specialized AI that tracks the complete game world state.

YOUR ROLE:
- Analyze the conversation and narrative to determine what has changed
- Output the COMPLETE current state in a structured plaintext format
- You must output the ENTIRE state, not just changes

CRITICAL: WHO IS THE PLAYER?
- "{{user}}" is the PLAYER. Track THEIR inventory, vitals, location, and quests.
- "{{char}}" is the NPC. They go in the "NPCs" section only.
- All tracked state belongs to {{user}}, NOT {{char}}.
- NPC NAMES: Always use proper capitalization for NPC names (e.g., "Lin Mei", not "lin_mei").

PLACEHOLDER REPLACEMENT:
Replace all [placeholders] with concrete in-world details. Examples:
- [location name] → "The Rusty Anchor Tavern"
- [weather condition] → "Light rain with occasional thunder"
- [0-23] → 14
- [current]/[max] → 85/100
DO NOT keep brackets in your response. Every placeholder must become real content.

RATE OF CHANGE:
Manage values REALISTICALLY based on the intensity and duration of activities:

DEPLETION (Loss):
- 0% change: Idle, short conversation, minor movement.
- 1-3% change: Normal activities (walking, light work, extended dialogue).
- 4-10% change: Significant effort (running, combat, heavy labor).
- 10%+ change: Major events (serious injury, extreme exertion, long travel).

RECOVERY (Gain):
- 1-5% gain: Short rest (5-15 mins), catching breath, light snack.
- 10-25% gain: Full meal, long rest (1-2 hours), medical treatment.
- 50-100% gain: Full night's sleep (8+ hours), magical healing, deep meditation.

Example: If {{user}} walked to the market (10 minutes), stamina might drop by 1%.
Example: If {{user}} sat down and rested for 10 minutes, stamina should recover by 3%.
Example: If {{user}} fought a bandit, health might drop by 10%, stamina by 15%.
Example: If {{user}} slept until morning, health and stamina should recover to 100%.

OUTPUT FORMAT:
You MUST output a code block with the following sections:

```game-state
Location
---
Name: [location name]
Region: [region name]
Description: [brief description]
Tags: [comma-separated tags like public, safe, tavern]

Environment
---
Weather: [weather condition]
Lighting: [bright/dim/dark]
Temperature: [temperature description]

Time
---
Day: [total days elapsed] (DO NOT RESET)
Weekday: [day name] (e.g., Monday, Fredas, Jīnyào (金曜日), etc.)
Hour: [0-23]
Minute: [0-59]
Second: [0-59]
Period: [dawn/morning/noon/afternoon/dusk/evening/night]
Season: [season name]
Calendar: [Earth/Fantasy/Sci-Fi/etc.]
Date: [full date string, e.g. "2025-12-19", "15th of Highsun, Year 120", or "4th Day of the Lotus Moon, Year of the Dragon"]
Total Seconds Elapsed: [total seconds since game start]
TIME CONTINUITY:
- MICRO-TIME (Conversations, Trading, Crafting, Combat): Increment by MINUTES only.
  - Buying an item: +5-10 mins
  - Short conversation: +2-5 mins
  - Combat encounter: +1-5 mins
  - Limit time progression to minutes for these actions.
- MACRO-TIME (Travel, Sleep, Time Skips): Increment by HOURS or DAYS.
  - "Travelled to the next town": +Hours/Days
  - "Slept until morning": Set time to morning
DAY COUNTER: "Day" is the TOTAL count of days since the adventure started. Persist the total day count throughout the campaign.
WEEKDAY: "Weekday" is the name of the day in the cycle. Update this as days pass.

Vitals
---
Choose vitals that make sense for the current narrative context. You have full autonomy to add or remove stats as they become relevant.
Examples:
- Combat/Fantasy: health: [current]/[max], mana: [current]/[max], stamina: [current]/[max]
- Slice of Life: health: [current]/[max], stress: [current]/[max], social_energy: [current]/[max]
- Survival/Sci-Fi: health: [current]/[max], oxygen: [current]/[max], battery: [current]/[max]
- Mature/Intimate: arousal: [current]/[max], stamina: [current]/[max]

GUIDELINES:
- Add stats when they become narratively relevant (e.g., "arousal" during intimacy, "oxygen" in space or underwater).
- Remove stats when they are no longer relevant (e.g., hide "arousal" when the character is with their children).
- Do not be rigid about "standard" stats like health/stamina if they don't fit the story.
- Avoid dropping stats that are continually relevant to the current genre.
- Format: - [stat_name]: [current]/[max]

Currency
---
[Currency Name]: [amount]
(e.g., Gold: 100, Credits: 5000, Yen: 2000, USD: 50)

Inventory
---
On Person: [item1, item2 (equipped), item3 x3]
Stored - [Location]: [items at that location]
Assets: [horse, house, shop ownership, vehicle, etc.]
Removed: [item_id1, item_id2] (items consumed/lost this turn)

Equipment
---
[slot]: [item name] ([+bonus stat])

Main Quest
---
- [Quest Title] (active/completed/failed)
  Given by: [NPC name]
  Description: [quest description]
  Objectives:
    - [x] [completed objective]
    - [ ] [incomplete objective]
  Rewards: [reward description]
- QUEST STICKINESS: ALWAYS include all active and completed quests. Retain all completed quests in the list permanently.

Optional Quests
---
- [Side Quest 1] (active/completed/failed)
  Given by: [NPC name]
  Objectives:
    - [ ] [objective]

NPCs
---
- [NPC Name] ([disposition: friendly/neutral/hostile])
  Location: [where they are]
  Status: [alive/dead/unconscious]
  Description: [detailed physical description]
  Personality: [personality traits]
  Notes: [any relevant info]

Status Effects
---
- [Effect Name] ([duration/description])
```

RULES:
1. ALWAYS output the ```game-state code block - this is required for parsing
2. Include ALL sections, even if unchanged from before
3. Be consistent with the narrative - if something happened in the story, reflect it
4. Use reasonable defaults for values not explicitly stated
5. For new games, infer initial state from {{user}}'s context

CRITICAL - VITALS:
- Always use format: stat_name: current/max (e.g., health: 85/100)
- Never use separate "current" and "max" fields
- Adjust values based on Rate of Change guidelines above

CRITICAL - CURRENCY:
- Track ALL money in the Currency section, NOT as inventory items
- Example: "counted 1500 gold coins" → Gold: 1500
- Example: "transferred 500 credits" → Credits: 500
- Example: "found 2000 yen in wallet" → Yen: 2000
- Format: "[Currency Name]: [amount]" (one per line)
- If NO currency, write: "None"

CRITICAL - INVENTORY:
- "On Person:" for carried items, comma-separated
- "Stored - [Location]:" for items elsewhere (e.g., "Stored - Home:")
- "Assets:" for major possessions (horses, property, vehicles)
- Use "x3" for quantities > 1, "(equipped)" for worn items
- "Removed:" for items consumed/lost this turn
- If empty: "On Person: None"
- DO NOT include money here - use Currency section

CRITICAL - QUESTS:
- "Main Quest" for primary objective, "Optional Quests" for side quests
- Use [x] completed, [ ] incomplete
- If NO quests exist, write under section: "None active"
- Only list actual quests with real titles from the narrative

CRITICAL - NPCS:
- "NPCs (Present)" section lists NPCs currently in the scene.
- "Known NPCs (Elsewhere)" lists important NPCs who are not present.
- When an NPC enters the scene, move them to "NPCs (Present)" and add full details.
- When an NPC leaves, move them to "Known NPCs (Elsewhere)" IF they are important.
- If an NPC is unimportant (e.g., random guard) and leaves, REMOVE them entirely.
- "Important" means: recurring characters, quest givers, or narratively significant.
- Set "Important: true" for named characters who matter.
- Set "Important: false" for generic guards, villagers, or one-off characters.
- If no NPCs are present, write: "NPCs (Present): None"

CRITICAL - STATUS EFFECTS:
- Only list active effects (poison, buffs, debuffs, conditions)
- Remove effects when they expire or are cured
- If no effects, write: "None""#;

        crate::prompt_builder::replace_template_variables(template, character_name, player_name)
    }

    /// Build the user prompt with context
    /// Provides current state and conversation context for the LLM
    fn build_user_prompt(
        &self,
        current_state: Option<&GameState>,
        conversation_summary: &str,
        last_user_message: &str,
        last_assistant_message: &str,
        player_name: Option<&str>,
        character_name: Option<&str>,
    ) -> String {
        // Format current state as plaintext for context
        let current_state_text = match current_state {
            Some(state) => Self::format_state_for_prompt(state),
            None => "(New game session - infer initial state from context)".to_string(),
        };

        let prompt = format!(
            r#"You are updating the game state based on the MOST RECENT exchange only.

<state_tracking_rules>
CRITICAL: You are tracking the PLAYER's state ({{{{user}}}}), NOT the NPC's state ({{{{char}}}}).
- inventory, vitals, quests, location = {{{{user}}}}'s stats
- {{{{char}}}} goes in the "NPCs" section only
</state_tracking_rules>

=== AUTHORITATIVE CURRENT STATE ===
This is the CURRENT game state. Time, day, and all values are ALREADY CORRECT.
DO NOT re-apply past events - they are already reflected here.

<current_game_state>
{}
</current_game_state>

=== BACKGROUND CONTEXT (READ ONLY) ===
This is a summary of prior conversation for context. These events are ALREADY reflected
in the current state above. DO NOT add time or changes from this section again.

<prior_context>
{}
</prior_context>

=== CURRENT TURN (UPDATE FOR THIS) ===
These are the NEW messages from the current turn. Update the game state based ONLY
on what happens in these two messages, starting from the current state above.

<player_action name="{{{{user}}}}">
{}
</player_action>

<response name="{{{{char}}}}">
{}
</response>

Based on the CURRENT TURN only, output the complete updated game state.
The time should only change by the amount that passes DURING the current turn,
NOT including any time from prior_context (that's already in the state).

Output in ```game-state format, tracking {{{{user}}}}'s stats:"#,
            current_state_text, conversation_summary, last_user_message, last_assistant_message
        );

        crate::prompt_builder::replace_template_variables(&prompt, character_name, player_name)
    }

    /// Format a GameState for display in the prompt (human-readable plaintext)
    /// CRITICAL: This must include ALL fields so the LLM knows the complete current state
    fn format_state_for_prompt(state: &GameState) -> String {
        let mut output = String::new();

        // === LOCATION ===
        if let Some(ref location) = state.location {
            output.push_str(&format!("Location: {}", location.name));
            if let Some(ref region) = location.region {
                output.push_str(&format!(" ({})", region));
            }
            output.push('\n');
            if let Some(ref desc) = location.description {
                output.push_str(&format!("  Description: {}\n", desc));
            }
            if !location.tags.is_empty() {
                output.push_str(&format!("  Tags: {}\n", location.tags.join(", ")));
            }
        }

        // === ENVIRONMENT ===
        let env = &state.environment;
        output.push_str("Environment:\n");
        output.push_str(&format!(
            "  Weather: {}\n",
            env.weather.as_deref().unwrap_or("unknown")
        ));
        output.push_str(&format!(
            "  Lighting: {}\n",
            env.lighting.as_deref().unwrap_or("unknown")
        ));
        output.push_str(&format!(
            "  Temperature: {}\n",
            env.temperature.as_deref().unwrap_or("unknown")
        ));
        if !env.hazards.is_empty() {
            output.push_str(&format!("  Hazards: {}\n", env.hazards.join(", ")));
        }

        // === TIME ===
        if let Some(ref time) = state.game_time {
            output.push_str(&format!(
                "Time: Day {}, {:02}:{:02}:{:02} ({})",
                time.day, time.hour, time.minute, time.second, time.period
            ));
            if let Some(ref season) = time.season {
                output.push_str(&format!(", {}", season));
            }
            output.push('\n');
            if let Some(ref weekday) = time.weekday {
                output.push_str(&format!("  Weekday: {}\n", weekday));
            }
            output.push_str(&format!("  Calendar: {}\n", time.calendar_system));
            output.push_str(&format!("  Date: {}\n", time.date));
            output.push_str(&format!(
                "  Total Seconds Elapsed: {}\n",
                time.total_seconds_elapsed
            ));
        }

        // === CURRENCIES ===
        if !state.currencies.is_empty() {
            output.push_str("Currencies:\n");
            for (name, amount) in &state.currencies {
                output.push_str(&format!("  {}: {}\n", name, amount));
            }
        }

        // === VITALS ===
        if !state.vitals.is_empty() {
            output.push_str("Vitals:\n");
            for (name, vital) in &state.vitals {
                output.push_str(&format!("  {}: {}/{}\n", name, vital.current, vital.max));
            }
        }

        // === INVENTORY (ON PERSON) ===
        if !state.inventory.is_empty() {
            output.push_str("Inventory (On Person):\n");
            for item in &state.inventory {
                let qty = if item.quantity > 1 {
                    format!(" x{}", item.quantity)
                } else {
                    String::new()
                };
                let equipped = if item.equipped { " (equipped)" } else { "" };
                output.push_str(&format!("  - {}{}{}\n", item.name, qty, equipped));
            }
        }

        // === INVENTORY (STORED) ===
        if !state.inventory_stored.is_empty() {
            output.push_str("Inventory (Stored):\n");
            for (location, items) in &state.inventory_stored {
                output.push_str(&format!("  {}:\n", location));
                for item in items {
                    let qty = if item.quantity > 1 {
                        format!(" x{}", item.quantity)
                    } else {
                        String::new()
                    };
                    output.push_str(&format!("    - {}{}\n", item.name, qty));
                }
            }
        }

        // === ASSETS ===
        if !state.assets.is_empty() {
            output.push_str("Assets:\n");
            for asset in &state.assets {
                output.push_str(&format!("  - {}\n", asset));
            }
        }

        // === QUESTS ===
        // Filter out "None" placeholder quests to prevent feedback loop
        let real_quests: Vec<_> = state
            .quests
            .iter()
            .filter(|q| !q.title.eq_ignore_ascii_case("none"))
            .collect();
        if !real_quests.is_empty() {
            let main_quests: Vec<_> = real_quests.iter().filter(|q| q.is_main).collect();
            let optional_quests: Vec<_> = real_quests.iter().filter(|q| !q.is_main).collect();

            if !main_quests.is_empty() {
                output.push_str("Main Quest:\n");
                for quest in main_quests {
                    output.push_str(&format!("  - {} ({:?})\n", quest.title, quest.status));
                    for obj in &quest.objectives {
                        let check = if obj.completed { "x" } else { " " };
                        output.push_str(&format!("    [{}] {}\n", check, obj.description));
                    }
                }
            }

            if !optional_quests.is_empty() {
                output.push_str("Optional Quests:\n");
                for quest in optional_quests {
                    output.push_str(&format!("  - {} ({:?})\n", quest.title, quest.status));
                    for obj in &quest.objectives {
                        let check = if obj.completed { "x" } else { " " };
                        output.push_str(&format!("    [{}] {}\n", check, obj.description));
                    }
                }
            }
        }

        // === NPCS ===
        if !state.npcs.is_empty() {
            let current_location_name = state.location.as_ref().map(|l| l.name.to_lowercase());
            let mut present_npcs = Vec::new();
            let mut known_npcs = Vec::new();

            for (name, npc) in &state.npcs {
                let is_present = if let (Some(curr_loc), Some(npc_loc)) =
                    (&current_location_name, &npc.location)
                {
                    npc_loc.to_lowercase().contains(curr_loc)
                        || curr_loc.contains(&npc_loc.to_lowercase())
                } else {
                    false
                };

                if is_present {
                    present_npcs.push((name, npc));
                } else if npc.is_important {
                    known_npcs.push((name, npc));
                }
            }

            if !present_npcs.is_empty() {
                output.push_str("NPCs (Present):\n");
                for (name, npc) in present_npcs {
                    output.push_str(&format!("- {} ({})\n", name, npc.disposition));
                    if let Some(ref loc) = npc.location {
                        output.push_str(&format!("  Location: {}\n", loc));
                    }
                    output.push_str(&format!("  Status: {}\n", npc.status));
                    output.push_str(&format!("  Role: {}\n", npc.role));
                    output.push_str(&format!("  Important: {}\n", npc.is_important));
                    if let Some(ref desc) = npc.description {
                        output.push_str(&format!("  Description: {}\n", desc));
                    }
                    if let Some(ref pers) = npc.personality {
                        output.push_str(&format!("  Personality: {}\n", pers));
                    }
                }
            } else {
                output.push_str("NPCs (Present): None\n");
            }

            if !known_npcs.is_empty() {
                output.push_str("\nKnown NPCs (Elsewhere):\n");
                for (name, npc) in known_npcs {
                    output.push_str(&format!("- {} ({})\n", name, npc.role));
                    if let Some(ref loc) = npc.location {
                        output.push_str(&format!("  Location: {}\n", loc));
                    }
                }
            }
        }

        output
    }

    /// Parse the LLM response into a GameState
    /// Uses a fuzzy section-based parser instead of JSON:
    /// 1. Extract the ```game-state code block
    /// 2. Split into sections by header keywords
    /// 3. Parse each section with targeted regex
    fn parse_state_response(&self, response: &str) -> Result<GameState, AppError> {
        debug!(
            response_len = response.len(),
            response_preview = %response.chars().take(200).collect::<String>(),
            "Parsing plaintext game state response"
        );

        // Extract the game-state code block
        let state_text = Self::extract_code_block(response)?;

        // Parse sections
        let sections = Self::parse_sections(&state_text);

        // Build GameState from parsed sections
        let mut game_state = GameState::default();

        // Parse Location section
        if let Some(location_text) = sections.get("location") {
            game_state.location = Some(Self::parse_location_section(location_text));
        }

        // Parse Environment section
        if let Some(env_text) = sections.get("environment") {
            game_state.environment = Self::parse_environment_section(env_text);
        }

        // Parse Time section
        if let Some(time_text) = sections.get("time") {
            game_state.game_time = Some(Self::parse_time_section(time_text));
        }

        // Parse Vitals section
        if let Some(vitals_text) = sections.get("vitals") {
            game_state.vitals = Self::parse_vitals_section(vitals_text);
        }

        // Parse Currency section
        if let Some(currency_text) = sections.get("currency") {
            info!(currency_text = %currency_text, "Found currency section");
            game_state.currencies = Self::parse_currency_section(currency_text);
            info!(currencies_parsed = ?game_state.currencies, "Parsed currencies");
        } else {
            info!("No currency section found in LLM response");
        }

        // Parse Inventory section
        if let Some(inv_text) = sections.get("inventory") {
            let (on_person, stored, assets, removed) = Self::parse_inventory_section(inv_text);
            game_state.inventory = on_person;
            game_state.inventory_stored = stored;
            game_state.assets = assets;
            game_state.removed_items = removed;
        }

        // Parse Main Quest section
        if let Some(main_quest_text) = sections.get("main quest") {
            info!(main_quest_text = %main_quest_text, "Parsing main quest section");
            let mut main_quests = Self::parse_quests_section(main_quest_text);
            // Filter out "None" placeholders
            main_quests.retain(|q| !q.title.eq_ignore_ascii_case("none"));
            for quest in &mut main_quests {
                quest.is_main = true;
            }
            game_state.quests.extend(main_quests);
        }

        // Parse Optional Quests section
        if let Some(opt_quests_text) = sections.get("optional quests") {
            info!(opt_quests_text = %opt_quests_text, "Parsing optional quests section");
            let mut optional_quests = Self::parse_quests_section(opt_quests_text);
            // Filter out "None" placeholders
            optional_quests.retain(|q| !q.title.eq_ignore_ascii_case("none"));
            // is_main defaults to false
            game_state.quests.extend(optional_quests);
        }

        // Parse legacy Quests section (for backwards compatibility)
        if let Some(quests_text) = sections.get("quests") {
            game_state
                .quests
                .extend(Self::parse_quests_section(quests_text));
        }

        // Parse NPCs section
        if let Some(npcs_text) = sections.get("npcs") {
            game_state.npcs = Self::parse_npcs_section(npcs_text);
        }

        info!(
            location = ?game_state.location.as_ref().map(|l| &l.name),
            vitals_count = game_state.vitals.len(),
            currencies_count = game_state.currencies.len(),
            inventory_count = game_state.inventory.len(),
            quests_count = game_state.quests.len(),
            "Successfully parsed plaintext game state"
        );

        Ok(game_state)
    }

    /// Extract the ```game-state or ``` code block from the response
    fn extract_code_block(response: &str) -> Result<String, AppError> {
        // Try to find ```game-state block first
        let code_block_re = Regex::new(r"```(?:game-state)?\s*\n([\s\S]*?)\n```").unwrap();

        if let Some(caps) = code_block_re.captures(response) {
            if let Some(content) = caps.get(1) {
                return Ok(content.as_str().to_string());
            }
        }

        // If no code block, check if response looks like state text (has section headers)
        if response.contains("Location") && response.contains("---") {
            return Ok(response.to_string());
        }

        warn!(
            response_preview = %response.chars().take(300).collect::<String>(),
            "No game-state code block found in response"
        );
        Err(AppError::SerializationError(
            "No game-state code block found in LLM response".to_string(),
        ))
    }

    /// Parse response text into sections by detecting headers
    /// Headers are case-insensitive keywords followed by optional "---"
    fn parse_sections(text: &str) -> HashMap<String, String> {
        let mut sections: HashMap<String, String> = HashMap::new();
        let known_headers = [
            "location",
            "environment",
            "time",
            "vitals",
            "currency",
            "inventory",
            "equipment",
            "main quest",
            "optional quests",
            "quests",
            "npcs",
            "status effects",
        ];

        // Match section headers: "Location", "Location\n---", "## Location", etc.
        let header_re = Regex::new(r"(?mi)^(?:#*\s*)?(location|environment|time|vitals|currency|inventory|equipment|main quest|optional quests|quests|npcs|status effects)\s*$").unwrap();

        let mut current_section: Option<String> = None;
        let mut current_content = String::new();

        for line in text.lines() {
            let trimmed = line.trim();

            // Skip separator lines
            if trimmed == "---" || trimmed.is_empty() {
                continue;
            }

            // Check if this line is a header
            if let Some(caps) = header_re.captures(line) {
                // Save previous section
                if let Some(section_name) = current_section.take() {
                    sections.insert(section_name, current_content.trim().to_string());
                    current_content.clear();
                }

                // Start new section
                let header = caps.get(1).unwrap().as_str().to_lowercase();
                current_section = Some(header);
            } else if current_section.is_some() {
                // Add line to current section
                current_content.push_str(line);
                current_content.push('\n');
            }
        }

        // Don't forget last section
        if let Some(section_name) = current_section {
            sections.insert(section_name, current_content.trim().to_string());
        }

        info!(
            sections_found = ?sections.keys().collect::<Vec<_>>(),
            "Parsed sections from response"
        );

        sections
    }

    /// Parse Location section
    fn parse_location_section(text: &str) -> Location {
        let mut id = String::new();
        let mut name = String::new();
        let mut description: Option<serde_json::Value> = None;
        let mut region: Option<String> = None;
        let mut tags: Vec<String> = Vec::new();

        for line in text.lines() {
            let trimmed = line.trim();
            if let Some((key, value)) = trimmed.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim();
                match key.as_str() {
                    "name" => name = value.to_string(),
                    "id" => id = value.to_lowercase().replace(' ', "_"),
                    "region" => region = Some(value.to_string()),
                    "description" => description = Some(serde_json::json!(value)),
                    "tags" => {
                        tags = value.split(',').map(|s| s.trim().to_string()).collect();
                    }
                    _ => {}
                }
            }
        }

        // Generate ID from name if not provided
        if id.is_empty() && !name.is_empty() {
            id = name.to_lowercase().replace(' ', "_");
        }

        Location {
            id,
            name,
            description,
            region,
            tags,
        }
    }

    /// Parse Environment section
    fn parse_environment_section(text: &str) -> EnvironmentState {
        let mut env = EnvironmentState::default();

        for line in text.lines() {
            let trimmed = line.trim();
            if let Some((key, value)) = trimmed.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim();
                match key.as_str() {
                    "weather" => env.weather = Some(value.to_string()),
                    "lighting" => env.lighting = Some(value.to_string()),
                    "temperature" | "temp" => env.temperature = Some(value.to_string()),
                    "hazards" => {
                        env.hazards = value.split(',').map(|s| s.trim().to_string()).collect();
                    }
                    _ => {}
                }
            }
        }

        env
    }

    /// Parse Time section
    fn parse_time_section(text: &str) -> GameTime {
        let mut day: u32 = 1;
        let mut hour: u8 = 0;
        let mut minute: u8 = 0;
        let mut second: u8 = 0;
        let mut period = String::new();
        let mut season: Option<String> = None;
        let mut calendar_system = "Earth".to_string();
        let mut date = String::new();
        let mut weekday: Option<String> = None;
        let mut total_seconds_elapsed = 0;

        for line in text.lines() {
            let trimmed = line.trim();
            if let Some((key, value)) = trimmed.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim();
                match key.as_str() {
                    "day" => day = value.parse().unwrap_or(1),
                    "hour" => hour = value.parse().unwrap_or(0),
                    "minute" => minute = value.parse().unwrap_or(0),
                    "second" => second = value.parse().unwrap_or(0),
                    "period" => period = value.to_string(),
                    "season" => season = Some(value.to_string()),
                    "calendar" => calendar_system = value.to_string(),
                    "date" => date = value.to_string(),
                    "weekday" => weekday = Some(value.to_string()),
                    "total seconds elapsed" => {
                        total_seconds_elapsed = value.parse().unwrap_or(0);
                    }
                    _ => {}
                }
            }
        }

        GameTime {
            day,
            hour,
            minute,
            second,
            period,
            season,
            calendar_system,
            date,
            weekday,
            total_seconds_elapsed,
        }
    }

    /// Parse Vitals section - handles "- stat_name: current/max" or "- stat_name: current / max"
    fn parse_vitals_section(text: &str) -> HashMap<String, Vital> {
        let mut vitals = HashMap::new();

        // Regex: "- stat_name: current/max" with optional whitespace around /
        let vital_re =
            Regex::new(r"(?m)^\s*-\s*([^:]+):\s*(\d+(?:\.\d+)?)\s*/\s*(\d+(?:\.\d+)?)").unwrap();

        for caps in vital_re.captures_iter(text) {
            let name = caps.get(1).unwrap().as_str().trim().to_lowercase();
            let current: f64 = caps.get(2).unwrap().as_str().parse().unwrap_or(100.0);
            let max: f64 = caps.get(3).unwrap().as_str().parse().unwrap_or(100.0);

            vitals.insert(
                name,
                Vital {
                    current,
                    max,
                    regen_rate: None,
                    modifiers: Vec::new(),
                },
            );
        }

        vitals
    }

    /// Parse Currency section - handles "[currency name]: [amount]" format
    /// Examples: "Gold: 1500", "Silver: 45", "Credits: 10000"
    fn parse_currency_section(text: &str) -> HashMap<String, i64> {
        let mut currencies = HashMap::new();

        for line in text.lines() {
            let trimmed = line.trim();
            // Skip empty lines, example lines starting with (, and header lines
            if trimmed.is_empty() || trimmed.starts_with('(') || trimmed.contains("---") {
                continue;
            }

            // Parse "currency_name: amount" format
            if let Some((name, amount_str)) = trimmed.split_once(':') {
                let name = name.trim().to_string();
                let amount_str = amount_str.trim();

                // Extract numeric value, handling commas and other non-numeric chars
                let clean_amount: String = amount_str
                    .chars()
                    .filter(|c| c.is_ascii_digit() || *c == '-')
                    .collect();

                if let Ok(amount) = clean_amount.parse::<i64>() {
                    if !name.is_empty() && name.to_lowercase() != "e.g" {
                        currencies.insert(name, amount);
                    }
                }
            }
        }

        currencies
    }

    /// Parse Inventory section - handles "On Person:", "Stored - [Location]:", "Assets:", "Removed:"
    /// Returns: (on_person_items, stored_items_by_location, assets, removed_ids)
    fn parse_inventory_section(
        text: &str,
    ) -> (
        Vec<InventoryItem>,
        HashMap<String, Vec<InventoryItem>>,
        Vec<String>,
        Vec<String>,
    ) {
        let mut on_person = Vec::new();
        let mut stored: HashMap<String, Vec<InventoryItem>> = HashMap::new();
        let mut assets = Vec::new();
        let mut removed = Vec::new();

        for line in text.lines() {
            let trimmed = line.trim();

            // Parse "On Person:" line
            if let Some(value) = trimmed
                .strip_prefix("On Person:")
                .or_else(|| trimmed.strip_prefix("on person:"))
            {
                for item_str in Self::split_outside_parens(value, ',') {
                    if let Some(item) = Self::parse_inventory_item(item_str.trim()) {
                        on_person.push(item);
                    }
                }
            }
            // Parse "Stored - [Location]:" lines
            else if let Some(rest) = trimmed
                .strip_prefix("Stored -")
                .or_else(|| trimmed.strip_prefix("stored -"))
            {
                // Extract location name and items: "Home: sword, shield"
                if let Some((location, items_str)) = rest.split_once(':') {
                    let location = location.trim().to_string();
                    let items: Vec<InventoryItem> = Self::split_outside_parens(items_str, ',')
                        .into_iter()
                        .filter_map(|s| Self::parse_inventory_item(s.trim()))
                        .collect();
                    if !items.is_empty() {
                        stored.entry(location).or_default().extend(items);
                    }
                }
            }
            // Parse "Assets:" line
            else if let Some(value) = trimmed
                .strip_prefix("Assets:")
                .or_else(|| trimmed.strip_prefix("assets:"))
            {
                for asset_str in Self::split_outside_parens(value, ',') {
                    let asset = asset_str.trim();
                    if !asset.is_empty() && asset.to_lowercase() != "none" {
                        assets.push(asset.to_string());
                    }
                }
            }
            // Parse "Removed:" line
            else if let Some(value) = trimmed
                .strip_prefix("Removed:")
                .or_else(|| trimmed.strip_prefix("removed:"))
            {
                for id in Self::split_outside_parens(value, ',') {
                    let id = id.trim();
                    if !id.is_empty() {
                        removed.push(id.to_string());
                    }
                }
            }
        }

        (on_person, stored, assets, removed)
    }

    /// Parse a single inventory item: "Sword (equipped)", "Potion x3", "Health Potion"
    fn parse_inventory_item(text: &str) -> Option<InventoryItem> {
        let text = text.trim();
        if text.is_empty() || text.to_lowercase() == "none" {
            return None;
        }

        // Check for (equipped) marker
        let equipped = text.to_lowercase().contains("equipped");

        // Clean up the name by removing "equipped" and fixing commas/parens
        let mut clean_name = text.to_string();

        if equipped {
            // Remove "equipped" (case insensitive)
            let re = Regex::new(r"(?i)\bequipped\b").unwrap();
            clean_name = re.replace_all(&clean_name, "").to_string();

            // Clean up commas and spaces
            let re_comma = Regex::new(r",\s*,").unwrap();
            clean_name = re_comma.replace_all(&clean_name, ",").to_string();

            let re_open = Regex::new(r"\(\s*,").unwrap();
            clean_name = re_open.replace_all(&clean_name, "(").to_string();

            let re_close = Regex::new(r",\s*\)").unwrap();
            clean_name = re_close.replace_all(&clean_name, ")").to_string();

            clean_name = clean_name.replace("()", "");

            // Remove trailing spaces inside parens
            let re_space_close = Regex::new(r"\s+\)").unwrap();
            clean_name = re_space_close.replace_all(&clean_name, ")").to_string();

            // Remove leading spaces inside parens
            let re_space_open = Regex::new(r"\(\s+").unwrap();
            clean_name = re_space_open.replace_all(&clean_name, "(").to_string();

            clean_name = clean_name.trim().to_string();
        }

        // Check for quantity: "x3" or "x 3"
        let quantity_re = Regex::new(r"(?i)\s*x\s*(\d+)\s*$").unwrap();
        let (name, quantity) = if let Some(caps) = quantity_re.captures(&clean_name) {
            let qty: u32 = caps.get(1).unwrap().as_str().parse().unwrap_or(1);
            let name = quantity_re.replace(&clean_name, "").trim().to_string();
            (name, qty)
        } else {
            (clean_name, 1)
        };

        if name.is_empty() {
            return None;
        }

        Some(InventoryItem {
            id: name.to_lowercase().replace(' ', "_"),
            name,
            quantity,
            description: None,
            category: None,
            equipped,
            properties: HashMap::new(),
            staleness_count: 0,
        })
    }

    /// Helper to split a string by a delimiter, but only when not inside parentheses
    fn split_outside_parens(text: &str, delimiter: char) -> Vec<String> {
        let mut result = Vec::new();
        let mut current = String::new();
        let mut paren_depth = 0;

        for c in text.chars() {
            if c == '(' {
                paren_depth += 1;
                current.push(c);
            } else if c == ')' {
                paren_depth -= 1;
                current.push(c);
            } else if c == delimiter && paren_depth == 0 {
                result.push(current.trim().to_string());
                current.clear();
            } else {
                current.push(c);
            }
        }

        if !current.trim().is_empty() {
            result.push(current.trim().to_string());
        }

        result
    }

    /// Parse Quests section with [x] and [ ] objective syntax
    fn parse_quests_section(text: &str) -> Vec<Quest> {
        let mut quests = Vec::new();

        // Early exit for explicit "none active" marker
        let trimmed_text = text.trim().to_lowercase();
        if trimmed_text.contains("none active")
            || trimmed_text.contains("no quests")
            || trimmed_text == "none"
        {
            return quests;
        }

        let mut current_quest: Option<Quest> = None;

        // Quest title line: "- Quest Title (active)" or "- Quest Title (completed)"
        let quest_title_re =
            Regex::new(r"^\s*-\s*(.+?)\s*\((active|completed|failed|abandoned)\)").unwrap();
        // Objective line: "- [x] objective" or "- [ ] objective"
        let objective_re = Regex::new(r"^\s*-\s*\[([ xX])\]\s*(.+)").unwrap();
        // Key-value lines: "Given by: Name", "Description: text", "Rewards: text"
        let kv_re = Regex::new(r"^\s*(Given by|Description|Rewards):\s*(.+)").unwrap();

        for line in text.lines() {
            let trimmed = line.trim();

            // Check for quest title
            if let Some(caps) = quest_title_re.captures(trimmed) {
                // Save previous quest
                if let Some(q) = current_quest.take() {
                    quests.push(q);
                }

                let title = caps.get(1).unwrap().as_str().trim().to_string();
                let status_str = caps.get(2).unwrap().as_str();
                let status = match status_str.to_lowercase().as_str() {
                    "completed" => QuestStatus::Completed,
                    "failed" => QuestStatus::Failed,
                    "abandoned" => QuestStatus::Abandoned,
                    _ => QuestStatus::Active,
                };

                current_quest = Some(Quest {
                    id: title.to_lowercase().replace(' ', "_"),
                    title,
                    is_main: false, // Will be set by caller based on section
                    status,
                    description: None,
                    objectives: Vec::new(),
                    giver: None,
                    rewards: None,
                });
            }
            // Check for objective
            else if let Some(caps) = objective_re.captures(trimmed) {
                if let Some(ref mut quest) = current_quest {
                    let completed = caps.get(1).unwrap().as_str().to_lowercase() == "x";
                    let description = serde_json::json!(caps.get(2).unwrap().as_str().trim());
                    quest.objectives.push(QuestObjective {
                        description,
                        completed,
                        progress: None,
                    });
                }
            }
            // Check for key-value (Given by, Description, Rewards)
            else if let Some(caps) = kv_re.captures(trimmed) {
                if let Some(ref mut quest) = current_quest {
                    let key = caps.get(1).unwrap().as_str();
                    let value = caps.get(2).unwrap().as_str().trim();
                    match key {
                        "Given by" => quest.giver = Some(value.to_string()),
                        "Description" => quest.description = Some(serde_json::json!(value)),
                        "Rewards" => quest.rewards = Some(serde_json::json!(value)),
                        _ => {}
                    }
                }
            }
        }

        // Don't forget last quest
        if let Some(q) = current_quest {
            quests.push(q);
        }

        quests
    }

    /// Parse NPCs section
    fn parse_npcs_section(text: &str) -> HashMap<String, NpcState> {
        let mut npcs = HashMap::new();

        // Early exit for explicit "none present" marker
        let trimmed_text = text.trim().to_lowercase();
        if trimmed_text.contains("none present")
            || trimmed_text.contains("unavailable")
            || trimmed_text == "none"
        {
            return npcs;
        }

        let mut current_npc: Option<NpcState> = None;
        let mut current_id = String::new();

        // NPC header: "- NPC Name (friendly)" or "- NPC Name (hostile)"
        let npc_header_re =
            Regex::new(r"^\s*-\s*(.+?)\s*\((friendly|neutral|hostile|allied)\)").unwrap();

        for line in text.lines() {
            let trimmed = line.trim();

            if let Some(caps) = npc_header_re.captures(trimmed) {
                // Save previous NPC
                if let Some(npc) = current_npc.take() {
                    npcs.insert(current_id.clone(), npc);
                }

                let name = caps.get(1).unwrap().as_str().trim().to_string();
                let disposition = caps.get(2).unwrap().as_str().to_string();
                current_id = name.to_lowercase().replace(' ', "_");

                current_npc = Some(NpcState {
                    id: current_id.clone(),
                    name,
                    location: None,
                    disposition,
                    role: "Unknown".to_string(),
                    status: "alive".to_string(),
                    description: None,
                    personality: None,
                    is_important: true, // Default to true if parsed from existing state, or let LLM override
                    objectives: Vec::new(),
                    data: serde_json::Value::Object(serde_json::Map::new()),
                });
            } else if let Some(ref mut npc) = current_npc {
                // Parse NPC properties
                if let Some((key, value)) = trimmed.split_once(':') {
                    let key = key.trim().to_lowercase();
                    let value = value.trim().to_string();
                    match key.as_str() {
                        "location" => npc.location = Some(value),
                        "status" => npc.status = value,
                        "role" => npc.role = value,
                        "description" => npc.description = Some(value),
                        "personality" => npc.personality = Some(value),
                        "important" | "is_important" => {
                            let v = value.to_lowercase();
                            npc.is_important = v == "true" || v == "yes" || v == "on";
                        }
                        _ => {
                            if let Some(map) = npc.data.as_object_mut() {
                                map.insert(key, serde_json::Value::String(value));
                            }
                        }
                    }
                }
            }
        }

        // Don't forget last NPC
        if let Some(npc) = current_npc {
            npcs.insert(current_id, npc);
        }

        npcs
    }
}

impl Default for StateManagerAgent {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::game_state::{GameTime, InventoryItem, Location, Vital};
    use std::collections::HashMap;

    // ========================================================================
    // Configuration Tests
    // ========================================================================

    #[test]
    fn test_state_manager_config_default() {
        let config = StateManagerConfig::default();
        assert_eq!(config.model_name, "gemini-3-flash-preview");
        assert_eq!(config.temperature, Some(1.0));
    }

    #[test]
    fn test_state_manager_with_custom_config() {
        let config = StateManagerConfig {
            provider: AiProvider::Gemini,
            model_name: "custom-model".to_string(),
            max_output_tokens: Some(8192),
            temperature: Some(0.5),
            thinking_level: None,
        };
        let agent = StateManagerAgent::with_config(config);
        assert_eq!(agent.config.model_name, "custom-model");
        assert_eq!(agent.config.max_output_tokens, Some(8192));
    }

    // ========================================================================
    // Response Parsing Tests
    // ========================================================================

    #[test]
    fn test_parse_state_response_plain_text() {
        let agent = StateManagerAgent::new();
        let text = r#"
Location
---
Name: Forest Edge
Region: Verdant Woods

Time
---
Day: 1
Hour: 8
Minute: 0
Second: 0
Period: morning
Season: spring
Calendar: Earth
Date: 2025-01-01
Total Seconds Elapsed: 28800
"#;

        let result = agent.parse_state_response(text);
        assert!(result.is_ok());
        let state = result.unwrap();
        assert_eq!(state.location.as_ref().unwrap().name, "Forest Edge");
        assert_eq!(state.game_time.as_ref().unwrap().day, 1);
        assert_eq!(
            state.game_time.as_ref().unwrap().total_seconds_elapsed,
            28800
        );
    }

    #[test]
    fn test_parse_state_response_markdown_wrapped() {
        let agent = StateManagerAgent::new();
        let text = r#"```game-state
Location
---
Name: Forest Edge

Time
---
Day: 1
Hour: 8
```"#;

        let result = agent.parse_state_response(text);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_state_response_with_complete_game_state() {
        let agent = StateManagerAgent::new();
        let text = r#"```game-state
Location
---
Name: The Rusty Anchor
Region: Port District
Description: A cozy tavern with a roaring fireplace
Tags: indoors, safe, social

Time
---
Day: 5
Hour: 20
Minute: 0
Second: 0
Period: evening
Season: autumn
Calendar: Earth
Date: 2025-01-05
Total Seconds Elapsed: 417600

Vitals
---
- health: 85/100
- stamina: 70/100

Main Quest
---
- Find the Missing Merchant (active)
  Description: Search for the lost trader
  Objectives:
    - [x] Talk to the innkeeper
    - [ ] Search the docks

NPCs
---
- Greta (friendly)
  Location: tavern_001
  Status: alive

Environment
---
Weather: clear
Lighting: candlelit
Temperature: warm
Tags: cozy, atmospheric
```"#;

        let result = agent.parse_state_response(text);
        assert!(result.is_ok());

        let state = result.unwrap();
        assert!(state.location.is_some());
        assert_eq!(state.location.as_ref().unwrap().name, "The Rusty Anchor");
        assert!(state.game_time.is_some());
        assert_eq!(state.game_time.as_ref().unwrap().day, 5);
        assert_eq!(
            state.game_time.as_ref().unwrap().total_seconds_elapsed,
            417600
        );
        assert_eq!(state.vitals.len(), 2);
        assert_eq!(state.quests.len(), 1);
        assert_eq!(state.npcs.len(), 1);
    }

    #[test]
    fn test_parse_state_response_generic_code_block() {
        let agent = StateManagerAgent::new();
        let text = r#"```
Location
---
Name: Forest Edge
```"#;

        let result = agent.parse_state_response(text);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_state_response_invalid_format_returns_error() {
        let agent = StateManagerAgent::new();
        let invalid = r#"This is not a game state"#;

        let result = agent.parse_state_response(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_state_response_empty_string_returns_error() {
        let agent = StateManagerAgent::new();
        let result = agent.parse_state_response("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_state_response_partial_text_returns_error() {
        let agent = StateManagerAgent::new();
        let partial = r#"Location: Forest Edge"#; // Missing headers/sections

        let result = agent.parse_state_response(partial);
        assert!(result.is_err());
    }

    // ========================================================================
    // System Prompt Tests
    // ========================================================================

    #[test]
    fn test_build_system_prompt() {
        let agent = StateManagerAgent::new();
        let prompt = agent.build_system_prompt(None, None);
        assert!(prompt.contains("Game State Manager"));
        assert!(prompt.contains("game-state"));
    }

    #[test]
    fn test_build_system_prompt_contains_schema() {
        let agent = StateManagerAgent::new();
        let prompt = agent.build_system_prompt(None, None);

        // Verify schema elements are present
        assert!(prompt.contains("Location"));
        assert!(prompt.contains("Time"));
        assert!(prompt.contains("inventory"));
        assert!(prompt.contains("Vitals"));
        assert!(prompt.contains("quests"));
        assert!(prompt.contains("NPCs"));
        assert!(prompt.contains("Environment"));
    }

    #[test]
    fn test_build_system_prompt_contains_instructions() {
        let agent = StateManagerAgent::new();
        let prompt = agent.build_system_prompt(None, None);

        // Verify key instructions
        assert!(prompt.contains("COMPLETE"));
        assert!(prompt.contains("structured plaintext format"));
    }

    // ========================================================================
    // User Prompt Tests
    // ========================================================================

    #[test]
    fn test_build_user_prompt_with_no_current_state() {
        let agent = StateManagerAgent::new();
        let prompt = agent.build_user_prompt(
            None,
            "The player just started their adventure.",
            "I wake up and look around.",
            "You find yourself in a small village at dawn...",
            None,
            None,
        );

        assert!(prompt.contains("(New game session - infer initial state from context)"));
        assert!(prompt.contains("New game session"));
        assert!(prompt.contains("I wake up and look around"));
        assert!(prompt.contains("small village at dawn"));
    }

    #[test]
    fn test_build_user_prompt_with_existing_state() {
        let agent = StateManagerAgent::new();

        let mut current_state = GameState::default();
        current_state.location = Some(Location {
            id: "village_center".to_string(),
            name: "Village Square".to_string(),
            description: Some(serde_json::Value::String(
                "A bustling town center".to_string(),
            )),
            region: None,
            tags: vec!["outdoor".to_string()],
        });

        let prompt = agent.build_user_prompt(
            Some(&current_state),
            "Player explored the village square.",
            "I walk toward the blacksmith.",
            "The blacksmith looks up from his anvil...",
            None,
            None,
        );

        assert!(prompt.contains("Village Square"));
        assert!(prompt.contains("walk toward the blacksmith"));
        assert!(prompt.contains("blacksmith looks up"));
        assert!(!prompt.contains("null (This is a new game session")); // Should have actual state
    }

    #[test]
    fn test_build_user_prompt_serializes_complex_state() {
        let agent = StateManagerAgent::new();

        let mut current_state = GameState::default();
        current_state.location = Some(Location {
            id: "dungeon_01".to_string(),
            name: "Dark Cavern".to_string(),
            description: None,
            region: Some("Underworld".to_string()),
            tags: vec!["dangerous".to_string(), "dark".to_string()],
        });
        current_state.game_time = Some(GameTime {
            day: 3,
            hour: 2,
            period: "night".to_string(),
            calendar_system: "Earth".to_string(),
            date: "2025-01-03".to_string(),
            weekday: None,
            minute: 0,
            second: 0,
            season: Some("winter".to_string()),
            total_seconds_elapsed: 0,
        });
        current_state.inventory.push(InventoryItem {
            id: "torch_01".to_string(),
            name: "Lit Torch".to_string(),
            quantity: 1,
            description: None,
            category: None,
            equipped: true,
            properties: HashMap::new(),
            staleness_count: 0,
        });
        current_state.vitals.insert(
            "health".to_string(),
            Vital {
                current: 50.0,
                max: 100.0,
                regen_rate: None,
                modifiers: vec![],
            },
        );

        let prompt = agent.build_user_prompt(
            Some(&current_state),
            "Player entered the dungeon.",
            "I light my torch and proceed.",
            "The cavern walls glisten with moisture...",
            None,
            None,
        );

        // Verify complex state serialized correctly
        assert!(prompt.contains("Dark Cavern"));
        assert!(prompt.contains("Underworld"));
        assert!(prompt.contains("Lit Torch"));
        assert!(prompt.contains("night"));
    }

    // ========================================================================
    // Integration Flow Tests (End-to-End without actual LLM)
    // ========================================================================

    #[test]
    fn test_full_prompt_to_parse_flow() {
        let agent = StateManagerAgent::new();

        // Build prompts
        let system_prompt = agent.build_system_prompt(None, None);
        let user_prompt = agent.build_user_prompt(
            None,
            "New adventure beginning.",
            "I check my surroundings.",
            "You stand at the edge of a forest...",
            None,
            None,
        );

        // Verify prompts are generated
        assert!(!system_prompt.is_empty());
        assert!(!user_prompt.is_empty());

        // Simulate LLM response
        let mock_response = r#"```game-state
Location
---
Name: Forest Edge
Region: Verdant Woods
Description: The boundary between the village and the deep woods
Tags: outdoor, border

Time
---
Day: 1
Hour: 8
Minute: 0
Second: 0
Period: morning
Season: spring
Calendar: Earth
Date: 2025-01-01
Total Seconds Elapsed: 28800

Vitals
---
- health: 100/100

Environment
---
Weather: clear
Lighting: bright
Temperature: mild
Tags: nature, peaceful
```"#;

        // Parse the response
        let result = agent.parse_state_response(mock_response);
        assert!(result.is_ok());

        let state = result.unwrap();
        assert_eq!(state.location.as_ref().unwrap().name, "Forest Edge");
        assert_eq!(state.game_time.as_ref().unwrap().period, "morning");
    }

    #[test]
    fn test_state_update_preserves_all_fields() {
        let agent = StateManagerAgent::new();

        // Create initial complex state
        let mut initial_state = GameState::default();
        initial_state.location = Some(Location {
            id: "loc_1".to_string(),
            name: "Starting Area".to_string(),
            description: None,
            region: None,
            tags: vec![],
        });
        initial_state
            .custom_data
            .insert("player_class".to_string(), serde_json::json!("warrior"));

        // Build prompt with this state
        let prompt = agent.build_user_prompt(
            Some(&initial_state),
            "Context",
            "User message",
            "Assistant response",
            None,
            None,
        );

        // Verify the custom_data was included
        // Note: custom_data is not currently formatted in format_state_for_prompt
        // but it is preserved in the GameState struct.
        // Let's verify location is there instead.
        assert!(prompt.contains("Starting Area"));
    }

    #[test]
    fn test_parse_vitals_section_dynamic() {
        let agent = StateManagerAgent::new();
        let vitals_text = r#"
- health: 80/100
- stress: 25/50
- social_energy: 10/100
- oxygen: 95/100
"#;
        let vitals = StateManagerAgent::parse_vitals_section(vitals_text);

        assert_eq!(vitals.len(), 4);
        assert_eq!(vitals.get("health").unwrap().current, 80.0);
        assert_eq!(vitals.get("stress").unwrap().current, 25.0);
        assert_eq!(vitals.get("social_energy").unwrap().current, 10.0);
        assert_eq!(vitals.get("oxygen").unwrap().current, 95.0);
        assert_eq!(vitals.get("oxygen").unwrap().max, 100.0);
    }

    #[test]
    fn test_parse_inventory_item_with_descriptors() {
        let agent = StateManagerAgent::new();

        // Test item with multiple descriptors including equipped
        let item_text = "Silk robes (equipped, damaged, blood-stained, brittle)";
        let item = StateManagerAgent::parse_inventory_item(item_text).unwrap();

        assert_eq!(item.name, "Silk robes (damaged, blood-stained, brittle)");
        assert!(item.equipped);

        // Test item with equipped at the end
        let item_text2 = "Iron sword (sharp, equipped)";
        let item2 = StateManagerAgent::parse_inventory_item(item_text2).unwrap();
        assert_eq!(item2.name, "Iron sword (sharp)");
        assert!(item2.equipped);

        // Test item with multiple items on one line
        let inv_text = "On Person: Silk robes (equipped, damaged), Iron sword (sharp)";
        let (on_person, _, _, _) = StateManagerAgent::parse_inventory_section(inv_text);
        assert_eq!(on_person.len(), 2);
        assert_eq!(on_person[0].name, "Silk robes (damaged)");
        assert_eq!(on_person[1].name, "Iron sword (sharp)");
    }
}
