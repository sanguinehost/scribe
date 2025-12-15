//! State Manager Agent (Sidecar)
//!
//! The Sidecar agent that "watches" the game and generates complete state updates.
//! Uses Gemini Flash/Flash-Lite for fast, cheap inference.
//!
//! This agent implements the "Complete State + Reconciliation" pattern:
//! - It receives the current game state and recent conversation history
//! - It outputs a COMPLETE new state (not deltas)
//! - The backend reconciles this with the current state
//!
//! Key design principles from sanguine-rpg:
//! - The LLM outputs the *goal* state (what it thinks should happen)
//! - The code decides the *actual* state (what CAN happen)
//! - This prevents drift, hallucination, and cheating

use crate::errors::AppError;
use crate::models::game_state::GameState;
use genai::chat::{ChatMessage, ChatRequest};
use genai::Client;
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
}

impl Default for StateManagerConfig {
    fn default() -> Self {
        Self {
            provider: AiProvider::Gemini,
            model_name: "gemini-2.5-flash-lite".to_string(),
            max_output_tokens: Some(4096),
            temperature: Some(0.3), // Lower temp for more consistent state output
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

    /// Create a new StateManagerAgent with custom configuration
    pub fn with_config(config: StateManagerConfig) -> Self {
        Self { config }
    }

    /// Generate a complete game state update based on conversation history
    ///
    /// # Arguments
    /// * `current_state` - The current game state (may be None for new sessions)
    /// * `conversation_summary` - A summary of recent conversation for context
    /// * `last_user_message` - The most recent user message
    /// * `last_assistant_message` - The most recent assistant/narrative response
    ///
    /// # Returns
    /// A `Result<GameState, AppError>` containing the LLM's suggested complete new state
    pub async fn generate_state_update(
        &self,
        current_state: Option<&GameState>,
        conversation_summary: &str,
        last_user_message: &str,
        last_assistant_message: &str,
    ) -> Result<GameState, AppError> {
        let system_prompt = self.build_system_prompt();
        let user_prompt = self.build_user_prompt(
            current_state,
            conversation_summary,
            last_user_message,
            last_assistant_message,
        );

        debug!(
            model = %self.config.model_name,
            "Generating state update via Sidecar"
        );

        // Build the chat request using genai crate
        let chat_request = ChatRequest::default()
            .with_system(system_prompt)
            .append_message(ChatMessage::user(user_prompt));

        // Create the genai client (uses environment variables for API keys)
        let client = Client::default();

        // Execute the request
        let response = client
            .exec_chat(&self.config.model_name, chat_request, None)
            .await
            .map_err(|e| AppError::GenerationError(format!("State generation failed: {}", e)))?;

        // Extract the response text
        let response_text = response.first_content_text_as_str().ok_or_else(|| {
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
    fn build_system_prompt(&self) -> String {
        r#"You are the Game State Manager, a specialized AI that tracks and outputs the complete game world state.

YOUR ROLE:
- Analyze the conversation and narrative to determine what has changed
- Output the COMPLETE current state of the game world as valid JSON
- You must output the ENTIRE state, not just changes

OUTPUT FORMAT:
You MUST output a valid JSON object matching this schema:
{
  "location": {
    "id": "string",
    "name": "string",
    "description": "string (optional)",
    "region": "string (optional)",
    "tags": ["string"]
  },
  "game_time": {
    "day": number,
    "hour": number (0-23),
    "period": "dawn|morning|noon|afternoon|dusk|evening|night",
    "season": "string (optional)"
  },
  "inventory": [
    {
      "id": "string",
      "name": "string",
      "quantity": number,
      "description": "string (optional)",
      "category": "weapon|armor|consumable|quest|misc (optional)",
      "equipped": boolean,
      "properties": {}
    }
  ],
  "vitals": {
    "health": {"current": number, "max": number, "regen_rate": number (optional), "modifiers": []},
    "stamina": {"current": number, "max": number, ...}
  },
  "quests": [
    {
      "id": "string",
      "title": "string",
      "status": "active|completed|failed|abandoned",
      "description": "string (optional)",
      "objectives": [{"description": "string", "completed": boolean, "progress": "string (optional)"}],
      "giver": "string (optional)",
      "rewards": "string (optional)"
    }
  ],
  "npcs": {
    "npc_id": {
      "id": "string",
      "name": "string",
      "location": "string (optional)",
      "disposition": "hostile|neutral|friendly|allied",
      "status": "alive|dead|unconscious|absent",
      "objectives": [],
      "data": {}
    }
  },
  "environment": {
    "weather": "string (optional)",
    "lighting": "bright|dim|dark (optional)",
    "temperature": "string (optional)",
    "hazards": [],
    "tags": []
  },
  "custom_data": {}
}

RULES:
1. ALWAYS output valid JSON only - no markdown, no explanation, just the JSON object
2. Include ALL parts of the state, even if unchanged from before
3. Be consistent with the narrative - if something happened in the story, reflect it in state
4. Use reasonable defaults for values not explicitly stated in the narrative
5. For new games, infer initial state from the character and setting"#
            .to_string()
    }

    /// Build the user prompt with context
    fn build_user_prompt(
        &self,
        current_state: Option<&GameState>,
        conversation_summary: &str,
        last_user_message: &str,
        last_assistant_message: &str,
    ) -> String {
        let current_state_json = match current_state {
            Some(state) => serde_json::to_string_pretty(state).unwrap_or_else(|_| "{}".to_string()),
            None => {
                "null (This is a new game session, infer initial state from context)".to_string()
            }
        };

        format!(
            r#"Based on the following context, output the COMPLETE updated game state as JSON.

CURRENT STATE:
{}

RECENT CONTEXT:
{}

LAST USER MESSAGE:
{}

LAST NARRATIVE RESPONSE:
{}

Now output the complete updated game state as a single JSON object:"#,
            current_state_json, conversation_summary, last_user_message, last_assistant_message
        )
    }

    /// Parse the LLM response into a GameState
    fn parse_state_response(&self, response: &str) -> Result<GameState, AppError> {
        // Try to extract JSON if wrapped in markdown code blocks
        let json_str = if response.contains("```json") {
            response
                .split("```json")
                .nth(1)
                .and_then(|s| s.split("```").next())
                .unwrap_or(response)
                .trim()
        } else if response.contains("```") {
            response.split("```").nth(1).unwrap_or(response).trim()
        } else {
            response.trim()
        };

        serde_json::from_str(json_str).map_err(|e| {
            warn!(
                error = %e,
                response_preview = %json_str.chars().take(200).collect::<String>(),
                "Failed to parse state response"
            );
            AppError::SerializationError(format!("Failed to parse state JSON: {}", e))
        })
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
    use crate::models::game_state::{
        EnvironmentState, GameTime, InventoryItem, Location, NpcState, Quest, QuestObjective,
        QuestStatus, Vital,
    };
    use std::collections::HashMap;

    // ========================================================================
    // Configuration Tests
    // ========================================================================

    #[test]
    fn test_state_manager_config_default() {
        let config = StateManagerConfig::default();
        assert_eq!(config.model_name, "gemini-2.5-flash-lite");
        assert_eq!(config.temperature, Some(0.3));
    }

    #[test]
    fn test_state_manager_with_custom_config() {
        let config = StateManagerConfig {
            provider: AiProvider::Gemini,
            model_name: "custom-model".to_string(),
            max_output_tokens: Some(8192),
            temperature: Some(0.5),
        };
        let agent = StateManagerAgent::with_config(config);
        assert_eq!(agent.config.model_name, "custom-model");
        assert_eq!(agent.config.max_output_tokens, Some(8192));
    }

    // ========================================================================
    // Response Parsing Tests
    // ========================================================================

    #[test]
    fn test_parse_state_response_plain_json() {
        let agent = StateManagerAgent::new();
        let json = r#"{"location": null, "game_time": null, "inventory": [], "vitals": {}, "quests": [], "npcs": {}, "environment": {"weather": null, "lighting": null, "temperature": null, "hazards": [], "tags": []}, "custom_data": {}}"#;

        let result = agent.parse_state_response(json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_state_response_markdown_wrapped() {
        let agent = StateManagerAgent::new();
        let json = r#"```json
{"location": null, "game_time": null, "inventory": [], "vitals": {}, "quests": [], "npcs": {}, "environment": {"weather": null, "lighting": null, "temperature": null, "hazards": [], "tags": []}, "custom_data": {}}
```"#;

        let result = agent.parse_state_response(json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_state_response_with_complete_game_state() {
        let agent = StateManagerAgent::new();
        let json = r#"```json
{
  "location": {
    "id": "tavern_001",
    "name": "The Rusty Anchor",
    "description": "A cozy tavern with a roaring fireplace",
    "region": "Port District",
    "tags": ["indoors", "safe", "social"]
  },
  "game_time": {
    "day": 5,
    "hour": 20,
    "period": "evening",
    "season": "autumn"
  },
  "inventory": [
    {
      "id": "sword_001",
      "name": "Steel Longsword",
      "quantity": 1,
      "description": "A trusty blade",
      "category": "weapon",
      "equipped": true,
      "properties": {}
    },
    {
      "id": "potion_health",
      "name": "Health Potion",
      "quantity": 3,
      "description": "Restores 50 HP",
      "category": "consumable",
      "equipped": false,
      "properties": {}
    }
  ],
  "vitals": {
    "health": {"current": 85, "max": 100, "regen_rate": 1, "modifiers": []},
    "stamina": {"current": 70, "max": 100, "regen_rate": 5, "modifiers": []}
  },
  "quests": [
    {
      "id": "quest_001",
      "title": "Find the Missing Merchant",
      "status": "active",
      "description": "Search for the lost trader",
      "objectives": [
        {"description": "Talk to the innkeeper", "completed": true, "progress": null},
        {"description": "Search the docks", "completed": false, "progress": "0/3 areas checked"}
      ],
      "giver": "Town Guard",
      "rewards": "50 gold"
    }
  ],
  "npcs": {
    "bartender_001": {
      "id": "bartender_001",
      "name": "Greta",
      "location": "tavern_001",
      "disposition": "friendly",
      "status": "alive",
      "objectives": [],
      "data": {}
    }
  },
  "environment": {
    "weather": "clear",
    "lighting": "candlelit",
    "temperature": "warm",
    "hazards": [],
    "tags": ["cozy", "atmospheric"]
  },
  "custom_data": {
    "player_reputation": "neutral",
    "discovered_locations": 3
  }
}
```"#;

        let result = agent.parse_state_response(json);
        assert!(result.is_ok());

        let state = result.unwrap();
        assert!(state.location.is_some());
        assert_eq!(state.location.as_ref().unwrap().name, "The Rusty Anchor");
        assert!(state.game_time.is_some());
        assert_eq!(state.game_time.as_ref().unwrap().day, 5);
        assert_eq!(state.inventory.len(), 2);
        assert_eq!(state.quests.len(), 1);
        assert_eq!(state.npcs.len(), 1);
    }

    #[test]
    fn test_parse_state_response_generic_code_block() {
        let agent = StateManagerAgent::new();
        // Some LLMs wrap in ``` without json specifier
        let json = r#"```
{"location": null, "game_time": null, "inventory": [], "vitals": {}, "quests": [], "npcs": {}, "environment": {"weather": null, "lighting": null, "temperature": null, "hazards": [], "tags": []}, "custom_data": {}}
```"#;

        let result = agent.parse_state_response(json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_state_response_invalid_json_returns_error() {
        let agent = StateManagerAgent::new();
        let invalid_json = r#"{"location": broken json here}"#;

        let result = agent.parse_state_response(invalid_json);
        assert!(result.is_err());
        assert!(matches!(result, Err(AppError::SerializationError(_))));
    }

    #[test]
    fn test_parse_state_response_empty_string_returns_error() {
        let agent = StateManagerAgent::new();
        let result = agent.parse_state_response("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_state_response_partial_json_returns_error() {
        let agent = StateManagerAgent::new();
        let partial = r#"{"location": {"id": "test", "name": "Test""#; // Incomplete

        let result = agent.parse_state_response(partial);
        assert!(result.is_err());
    }

    // ========================================================================
    // System Prompt Tests
    // ========================================================================

    #[test]
    fn test_build_system_prompt() {
        let agent = StateManagerAgent::new();
        let prompt = agent.build_system_prompt();
        assert!(prompt.contains("Game State Manager"));
        assert!(prompt.contains("JSON"));
    }

    #[test]
    fn test_build_system_prompt_contains_schema() {
        let agent = StateManagerAgent::new();
        let prompt = agent.build_system_prompt();

        // Verify schema elements are present
        assert!(prompt.contains("location"));
        assert!(prompt.contains("game_time"));
        assert!(prompt.contains("inventory"));
        assert!(prompt.contains("vitals"));
        assert!(prompt.contains("quests"));
        assert!(prompt.contains("npcs"));
        assert!(prompt.contains("environment"));
    }

    #[test]
    fn test_build_system_prompt_contains_instructions() {
        let agent = StateManagerAgent::new();
        let prompt = agent.build_system_prompt();

        // Verify key instructions
        assert!(prompt.contains("COMPLETE"));
        assert!(prompt.contains("valid JSON"));
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
        );

        assert!(prompt.contains("null"));
        assert!(prompt.contains("new game session"));
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
            description: Some("A bustling town center".to_string()),
            region: None,
            tags: vec!["outdoor".to_string()],
        });

        let prompt = agent.build_user_prompt(
            Some(&current_state),
            "Player explored the village square.",
            "I walk toward the blacksmith.",
            "The blacksmith looks up from his anvil...",
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
            season: Some("winter".to_string()),
        });
        current_state.inventory.push(InventoryItem {
            id: "torch_01".to_string(),
            name: "Lit Torch".to_string(),
            quantity: 1,
            description: None,
            category: None,
            equipped: true,
            properties: HashMap::new(),
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
        let system_prompt = agent.build_system_prompt();
        let user_prompt = agent.build_user_prompt(
            None,
            "New adventure beginning.",
            "I check my surroundings.",
            "You stand at the edge of a forest...",
        );

        // Verify prompts are generated
        assert!(!system_prompt.is_empty());
        assert!(!user_prompt.is_empty());

        // Simulate LLM response
        let mock_response = r#"```json
{
  "location": {
    "id": "forest_edge",
    "name": "Forest Edge",
    "description": "The boundary between the village and the deep woods",
    "region": "Verdant Woods",
    "tags": ["outdoor", "border"]
  },
  "game_time": {
    "day": 1,
    "hour": 8,
    "period": "morning",
    "season": "spring"
  },
  "inventory": [],
  "vitals": {
    "health": {"current": 100, "max": 100, "regen_rate": 1, "modifiers": []}
  },
  "quests": [],
  "npcs": {},
  "environment": {
    "weather": "clear",
    "lighting": "bright",
    "temperature": "mild",
    "hazards": [],
    "tags": ["nature", "peaceful"]
  },
  "custom_data": {}
}
```"#;

        // Parse the response
        let result = agent.parse_state_response(mock_response);
        assert!(result.is_ok());

        let state = result.unwrap();
        assert_eq!(state.location.as_ref().unwrap().id, "forest_edge");
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
        );

        // Verify the custom_data was included
        assert!(prompt.contains("player_class"));
        assert!(prompt.contains("warrior"));
    }
}
