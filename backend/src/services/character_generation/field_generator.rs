use genai::chat::{ChatMessage as GenAiChatMessage, ChatRole, MessageContent};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, instrument};

use crate::{
    errors::AppError,
    services::{
        hybrid_token_counter::CountingMode, safety_utils::create_unrestricted_safety_settings,
    },
    AppState,
};

use super::{structured_output::*, types::*};

/// Helper struct for debug information
#[derive(Debug, Clone)]
struct DebugInfo {
    lorebook_context_included: bool,
    lorebook_entries_count: Option<usize>,
    query_text_used: Option<String>,
}

/// Helper struct for lorebook query results with debug info
#[derive(Debug, Clone)]
struct LorebookQueryResult {
    context: Option<String>,
    entries_count: Option<usize>,
    query_text_used: Option<String>,
}

/// Service for generating specific character fields with proper system prompts and structured output
pub struct FieldGenerator {
    state: Arc<AppState>,
}

// ============================================================================
// Prompt Engineering Constants
// ============================================================================

/// Base system prompt for all character generation tasks
/// Establishes expertise and explains critical {{char}}/{{user}} placeholder usage
const BASE_SYSTEM_PROMPT: &str = r#"You are an expert character designer for creative writing, role-playing games, and interactive fiction. Your expertise includes:
- Deep understanding of character psychology and motivation
- Crafting engaging, multi-dimensional personalities
- Creating immersive scenarios and settings
- Writing natural, character-appropriate dialogue
- Balancing detail with brevity

Focus on quality over quantity. Generate content that feels authentic and engaging.

CRITICAL PLACEHOLDER USAGE:
- {{char}} = The AI character being created by this card (the one you're writing)
- {{user}} = The human player/user (the person using the chatbot)

Examples:
- For a character card about "Alice": {{char}} = Alice, {{user}} = the player talking to Alice
- For a narrator/GM card: {{char}} = the narrator/GM, {{user}} = the player character in the story
- For a world/scenario card: {{char}} = the world/narrator, {{user}} = the player

NEVER mix them up or use them interchangeably. They refer to two different entities.
{{user}} is ALWAYS the human player, not the character you're creating."#;

/// Mode-specific instructions for generation
const MODE_INSTRUCTIONS_CREATE: &str = r#"Task: Generate NEW content from scratch.
- Start fresh, don't reference existing content
- Create original, creative content
- Ensure internal consistency
- Make it engaging and specific"#;

const MODE_INSTRUCTIONS_ENHANCE: &str = r#"Task: ENHANCE existing content while preserving its core.
- Keep the fundamental concept and tone
- Add depth, detail, and nuance
- Improve clarity and engagement
- Maintain consistency with existing content"#;

const MODE_INSTRUCTIONS_EXPAND: &str = r#"Task: EXPAND existing content with additional detail.
- Elaborate on what's already there
- Add new dimensions without contradicting existing content
- Increase richness and complexity
- Maintain the original voice and style"#;

const MODE_INSTRUCTIONS_REWRITE: &str = r#"Task: REWRITE existing content with a fresh perspective.
- Preserve core ideas but change expression
- Improve quality and engagement
- Fix any issues or inconsistencies
- May change style/tone if that improves quality"#;

/// Style-specific guidance with creative direction
const STYLE_PROMPT_TRAITS: &str = r#"Output Format: Write using clear, comma-separated trait lists.
- Use adjectives and short phrases
- Group related traits together
- Include both positive and nuanced traits
- Be specific rather than generic

Example: "Curious and analytical, tends to overthink situations, loyal to close friends but slow to trust, sarcastic humor as a defense mechanism""#;

const STYLE_PROMPT_NARRATIVE: &str = r#"Output Format: Write in flowing narrative prose.
- Use descriptive, literary language
- Create vivid imagery and atmosphere
- Show personality through actions and reactions
- Include sensory details when relevant
- Use paragraph breaks to separate ideas and improve readability
- Each paragraph should be 2-4 sentences

Example: "She moved through the world with quiet observation, her sharp mind always cataloging details others missed. Behind her sardonic wit lay a deep well of loyalty.

Years in the archives had taught her patience, but her restless curiosity still drove her to pursue every lead, no matter how obscure...""#;

const STYLE_PROMPT_PROFILE: &str = r#"Output Format: Write in structured profile format.
- Use clear headings, field labels, or bullet points to organize information
- Present factual, organized details about the subject
- Can include categories like physical traits, background, abilities, relationships, etc.
- Keep each section focused and concise
- Use "Field: Value" format where appropriate

Example: "Name: Elena Vasquez

Age: 28 | Height: 5'7\" | Build: Athletic

Background: Former military intelligence analyst turned private investigator. Grew up in border towns, fluent in English and Spanish.

Personality: Sharp-minded and perceptive, tends to trust her instincts. Patient when analyzing data but impulsive in the field. Dry sense of humor masks deep empathy for victims.

Skills: Expert in digital forensics, proficient in hand-to-hand combat, skilled interrogator.

Notable Traits: Always carries a worn leather notebook, drinks excessive coffee, has a photographic memory for faces.""#;
const STYLE_PROMPT_GROUP: &str = r#"Output Format: Write for group/party dynamics.
- Focus on interpersonal traits and relationships
- Highlight how character fits into team dynamics
- Note collaboration style and conflict patterns
- Include role within the group

Example: "Often takes on the mediator role, using humor to diffuse tension. Contributes strategic thinking but sometimes holds back due to self-doubt...""#;

const STYLE_PROMPT_WORLDBUILDING: &str = r#"Output Format: Write with world/setting integration.
- Connect character to broader world context
- Reference cultural, historical, or political elements
- Show how setting shapes the character
- Include faction/organization affiliations if relevant
- Use paragraph breaks to separate different aspects
- Each paragraph should focus on one aspect of the world/character relationship

Example: "Born in the aftermath of the Collapse, she carries the practical cynicism of the reconstruction era. Her technical skills were honed in the makeshift workshops that sprang up across the Reclaimed Zones.

Despite the scarcity of the early years, she maintained a fierce loyalty to the ideals of the Archives Council, believing knowledge was the only path to preventing another catastrophe...""#;

const STYLE_PROMPT_SYSTEM: &str = r#"Output Format: Write system instructions for AI behavior, game mechanics, or narrator guidelines.
- Focus on HOW the AI should behave, not WHO the character is
- Include game rules, world mechanics, or simulation guidelines
- Specify narrator responsibilities and constraints
- Define response formats, stat tracking, or procedural rules
- Use clear, directive language

Example: "{{char}} is the narrator. {{char}} will control all NPCs and world events. {{char}} will never control {{user}}'s actions. Random encounters occur every 3-5 messages. {{char}} will track stats at the end of each message.""#;

/// Field-specific context descriptions
const FIELD_CONTEXT_DESCRIPTION: &str = "The character's core definition - format and content vary widely based on creator intent. Can be: narrative description (appearance, personality, backstory), structured profile (stats, abilities), system instructions (narrator rules, AI behavior), world-building context, or any combination. May use XML-like tags, markdown sections, bullet points, or prose. Length ranges from brief (100 words) to extensive (3000+). This is the most versatile field - match the format to your vision.";

const FIELD_CONTEXT_PERSONALITY: &str = "Core personality traits, behavioral patterns, motivations, and psychological characteristics. How the character thinks, feels, and reacts. Can be left empty if personality details are already covered in the description field. When used, should focus on the character's mental/emotional makeup rather than physical traits or abilities.";

const FIELD_CONTEXT_SCENARIO: &str = "World state, character relationships, political situations, and context for the roleplay. Can include plot setup, faction dynamics, ongoing conflicts, and relationship histories. Often detailed and substantial (100-1000+ words) to establish rich context.";

const FIELD_CONTEXT_FIRST_MES: &str = "The opening scene/greeting that starts the roleplay. Should be a rich, immersive narrative (often 200-1000+ words) that establishes atmosphere, setting, character state, and situation. Use vivid sensory details, multiple paragraphs for readability, and a hook that invites user interaction. May include narration (in asterisks), dialogue, internal thoughts, environmental description, and current events. This sets the tone and quality bar for the entire roleplay. IMPORTANT: Use {{user}} consistently to refer to the player character throughout the greeting, and {{char}} to refer to the AI character/narrator you're creating.";

const FIELD_CONTEXT_ALTERNATE_GREETING: &str = "Alternative opening scenario with different mood, setting, or situation than the main greeting. Should be equally detailed and immersive (200-1000+ words) but offer variety - different time period, location, relationship dynamic, or crisis. Maintain character consistency while exploring different facets. Use multiple paragraphs and rich narrative detail.";

const FIELD_CONTEXT_SYSTEM_PROMPT: &str =
    "Technical instructions for AI behavior when playing this character. Clear and specific.";

const FIELD_CONTEXT_DEPTH_PROMPT: &str = "Additional character depth and background notes. Often called 'Character Notes' or 'Character Book'. Can include hidden lore, authorial commentary, design philosophy, or behind-the-scenes information that enriches the character without being directly shown. May include triggers, special mechanics, or contextual details the AI should know but not explicitly state.";

const FIELD_CONTEXT_MES_EXAMPLE: &str = "Example conversation exchanges demonstrating the character's dialogue style, actions, and personality. MUST follow this format: Multiple conversation examples separated by \"<START>\" tags. Each example shows back-and-forth dialogue between {{char}} (the character) and {{user}} (the player). Use {{char}}: and {{user}}: labels. Include actions in *asterisks*. Generate 2-3 distinct conversation examples showing different scenarios or moods.";

const FIELD_CONTEXT_TAGS: &str = "Categorization tags for the character. Short, specific keywords that help users discover and filter characters. Include genre, character type, setting, themes, and notable traits. Examples: fantasy, warrior, medieval, loyal, magic-user, slow-burn, adventure.";

// Lorebook entry field contexts (for generating lorebook content)
const FIELD_CONTEXT_ENTRY_CONTENT: &str = "Lorebook entry content. Factual, concise information about the specific topic indicated by the entry name and keywords. Write in an encyclopedic style focusing on: what it is, its significance in the world, key characteristics, relationships to other elements, and relevant history. Avoid unnecessary narrative flourishes - prioritize clarity and information density. Typically 50-300 words.";

const FIELD_CONTEXT_ENTRY_COMMENT: &str = "Commentary or metadata about the lorebook entry. Behind-the-scenes notes for the character creator: why this entry exists, how it should be used, what narrative purpose it serves, potential plot hooks, or authorial intent. This is internal documentation, not in-world information.";

/// Final guidelines for all generation tasks
const FINAL_GUIDELINES: &str = r#"Guidelines:
- Be concise but complete
- Avoid clichés and overused tropes
- Make every word count
- Use paragraph breaks (double newlines) to separate ideas and improve readability
- For longer content, break into 2-4 sentence paragraphs
- Output ONLY the generated content, no meta-commentary
- Do not include field labels or markdown headers in output"#;

#[allow(dead_code)]
impl FieldGenerator {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    /// Generate a specific character field using structured output
    #[instrument(skip_all, fields(field = ?request.field))]
    pub async fn generate_field(
        &self,
        request: FieldGenerationRequest,
        user_id: crate::db::DbId,
        session_dek: Option<&crate::auth::SessionDek>,
    ) -> Result<FieldGenerationResult, AppError> {
        let start_time = Instant::now();

        info!("Starting field generation for {:?}", request.field);

        // Determine the style to use
        let style = request.style.clone().unwrap_or(DescriptionStyle::Auto);

        // Build the system prompt specifically for character field generation
        let system_prompt =
            self.build_field_generation_system_prompt(&request.field, &request.mode, &style);

        // Build the user message with context and instructions, capturing debug info
        let (user_message, debug_info) = self
            .build_field_generation_user_message_with_debug(&request, user_id, session_dek)
            .await?;

        // Create a simple message for generation
        let messages = vec![GenAiChatMessage {
            role: ChatRole::User,
            content: MessageContent::Text(user_message.clone()),
            options: None,
        }];

        // Generate using the LLM with structured output
        let generated_output = self
            .generate_with_structured_output(
                &system_prompt,
                &messages,
                &get_field_generation_schema(),
                &request,
            )
            .await?;

        // Parse the structured output
        let mut field_output: CharacterFieldOutput =
            serde_json::from_value(generated_output.clone().into()).map_err(|e| {
                AppError::InternalServerErrorGeneric(format!(
                    "Failed to parse field generation output: {}",
                    e
                ))
            })?;

        // Post-process content for proper formatting
        field_output.content =
            self.post_process_content(&field_output.content, &request.field, &request.style);

        // Validate the output
        field_output.validate(&request.field)?;

        // Calculate metadata
        let generation_time = start_time.elapsed();
        let tokens_used = self.count_tokens(&system_prompt, &messages).await?;

        // Create debug info for troubleshooting
        let full_debug_info = super::types::GenerationDebugInfo {
            system_prompt: system_prompt.clone(),
            user_message: user_message.clone(),
            lorebook_context_included: debug_info.lorebook_context_included,
            lorebook_entries_count: debug_info.lorebook_entries_count,
            query_text_used: debug_info.query_text_used,
        };

        let metadata = GenerationMetadata {
            tokens_used,
            generation_time_ms: generation_time.as_millis() as u64,
            style_detected: Some(style.clone()),
            model_used: self.state.config.token_counter_default_model.clone(),
            timestamp: chrono::Utc::now().into(),
            debug_info: Some(full_debug_info),
        };

        info!(
            "Field generation completed in {}ms, {} tokens used",
            generation_time.as_millis(),
            tokens_used
        );

        Ok(FieldGenerationResult {
            content: field_output.content,
            style_used: style,
            metadata,
        })
    }

    /// Build system prompt specifically for character field generation with style examples
    pub fn build_field_generation_system_prompt(
        &self,
        field: &CharacterField,
        mode: &GenerationMode,
        style: &DescriptionStyle,
    ) -> String {
        let mut parts: Vec<String> = Vec::new();

        // 1. Base system prompt (character design expertise + placeholder usage)
        parts.push(BASE_SYSTEM_PROMPT.to_string());

        // 2. Field context (what this field is for)
        let field_name = field.display_name();
        parts.push(format!("\nField: {}", field_name));

        let field_context = match field {
            CharacterField::Description => FIELD_CONTEXT_DESCRIPTION,
            CharacterField::Personality => FIELD_CONTEXT_PERSONALITY,
            CharacterField::Scenario => FIELD_CONTEXT_SCENARIO,
            CharacterField::FirstMes => FIELD_CONTEXT_FIRST_MES,
            CharacterField::AlternateGreeting => FIELD_CONTEXT_ALTERNATE_GREETING,
            CharacterField::SystemPrompt => FIELD_CONTEXT_SYSTEM_PROMPT,
            CharacterField::DepthPrompt => FIELD_CONTEXT_DEPTH_PROMPT,
            CharacterField::MesExample => FIELD_CONTEXT_MES_EXAMPLE,
            CharacterField::Tags => FIELD_CONTEXT_TAGS,
            CharacterField::EntryContent => FIELD_CONTEXT_ENTRY_CONTENT,
            CharacterField::EntryComment => FIELD_CONTEXT_ENTRY_COMMENT,
        };
        parts.push(format!("Purpose: {}", field_context));

        // 3. Mode instructions (how to approach the generation task)
        let mode_instructions = match mode {
            GenerationMode::Create => MODE_INSTRUCTIONS_CREATE,
            GenerationMode::Enhance => MODE_INSTRUCTIONS_ENHANCE,
            GenerationMode::Expand => MODE_INSTRUCTIONS_EXPAND,
            GenerationMode::Rewrite => MODE_INSTRUCTIONS_REWRITE,
        };
        parts.push(format!("\n{}", mode_instructions));

        // 4. Style instructions (creative guidance)
        let style_prompt = match style {
            DescriptionStyle::Traits => STYLE_PROMPT_TRAITS,
            DescriptionStyle::Narrative => STYLE_PROMPT_NARRATIVE,
            DescriptionStyle::Profile => STYLE_PROMPT_PROFILE,
            DescriptionStyle::Group => STYLE_PROMPT_GROUP,
            DescriptionStyle::Worldbuilding => STYLE_PROMPT_WORLDBUILDING,
            DescriptionStyle::System => STYLE_PROMPT_SYSTEM,
            DescriptionStyle::Auto => {
                // For auto, choose default based on field
                match field {
                    CharacterField::Personality => STYLE_PROMPT_TRAITS,
                    CharacterField::FirstMes | CharacterField::AlternateGreeting => {
                        STYLE_PROMPT_NARRATIVE
                    }
                    CharacterField::Scenario => STYLE_PROMPT_WORLDBUILDING,
                    CharacterField::SystemPrompt | CharacterField::DepthPrompt => {
                        STYLE_PROMPT_SYSTEM
                    }
                    CharacterField::Description => STYLE_PROMPT_PROFILE,
                    _ => {
                        "Choose the most appropriate style based on the context and field type. Focus on creating engaging, well-structured content."
                    }
                }
            }
        };

        parts.push(format!("\n{}", style_prompt));

        // 5. Field-specific formatting requirements
        if matches!(
            field,
            CharacterField::FirstMes | CharacterField::AlternateGreeting
        ) {
            parts.push(r#"

CRITICAL FORMAT REQUIREMENTS for first messages and alternate greetings:

**NARRATIVE STYLE** (for character-driven roleplay):
- Start with compelling dialogue, action, or scene setting that immediately engages
- Include character thoughts and internal monologue to reveal personality
- Establish environment and situation through immersive sensory description
- Use multiple paragraphs (2-4 sentences each) for readability
- Mix dialogue, actions, descriptions, and internal thoughts
- Create a hook that naturally invites user interaction
- Use {{char}} to refer to this character and {{user}} to refer to the player

**SYSTEM/GAME STYLE** (for RPG/stat-based roleplay):
- Begin with rich narrative opening (2-3 paragraphs) establishing the scenario with vivid world-building
- Follow with CURRENT STATE section listing location, health, power level, status, etc.
- Include INVENTORY section with items, equipment, or resources
- Maintain character personality and voice within the structured format
- Each section should be clearly separated with double newlines

Choose the format that best matches the character's intended roleplay style and the request."#.to_string());
        }

        if matches!(field, CharacterField::MesExample) {
            parts.push(
                r#"

CRITICAL FORMAT REQUIREMENT for mes_example:

EVERY SINGLE conversation example MUST start with "<START>" on its own line.
This includes THE VERY FIRST EXAMPLE. Your output must literally begin with <START>.

Generate 2-3 conversation examples using this EXACT structure:

<START>
{{char}}: "Dialogue here." *Action in asterisks.*
{{user}}: "Response here." *Action.*
{{char}}: "Reply." *Action.*
{{user}}: "Final response."
{{char}}: *Reaction and closing.*

<START>
{{char}}: "Different scenario dialogue..." *Different action.*
{{user}}: "Response."
{{char}}: "Reply..."

<START>
{{char}}: "Third example..." *Action.*
[continue...]

CRITICAL: Your output MUST begin with the text "<START>" (not with dialogue or narration).
The first line of your output should be: <START>
Then the conversation begins on the next line.

Use {{char}}: for the AI character and {{user}}: for the player.
Actions go in *asterisks*.
Show different scenarios, moods, or personality aspects."#
                    .to_string(),
            );
        }

        // 6. Final guidelines
        parts.push(format!("\n{}", FINAL_GUIDELINES));

        parts.join("\n")
    }

    /// Build user message with context and generation request, including lorebook context
    async fn build_field_generation_user_message(
        &self,
        request: &FieldGenerationRequest,
        user_id: crate::db::DbId,
        session_dek: Option<&crate::auth::SessionDek>,
    ) -> Result<String, AppError> {
        let mut message = String::new();

        // Query lorebook for relevant context if lorebook_id is provided
        let lorebook_context = if let Some(lorebook_id) = request.lorebook_id {
            self.query_lorebook_context(user_id, lorebook_id, request, session_dek)
                .await?
        } else {
            None
        };

        // Special prompting for dialogue-based fields to ensure better structure
        match request.field {
            CharacterField::AlternateGreeting => {
                message.push_str("Create an alternate greeting for this character. This should be a rich, immersive opening scene that establishes a different scenario or mood than their main greeting.\n\n");
                message.push_str("CHOOSE APPROPRIATE FORMAT:\n");
                message.push_str("**NARRATIVE STYLE** (for character-driven roleplay):\n");
                message.push_str("- Start with compelling dialogue/action hook\n");
                message.push_str("- Include character thoughts and motivations\n");
                message.push_str("- Establish setting and context through immersive description\n");
                message.push_str("- Set up natural user interaction opportunities\n\n");
                message.push_str("**SYSTEM/GAME STYLE** (for RPG/stat-based roleplay):\n");
                message.push_str("- Rich narrative opening describing alternate scenario\n");
                message.push_str("- CURRENT STATE section reflecting the new situation\n");
                message.push_str("- INVENTORY section with scenario-appropriate items\n");
                message.push_str("- Maintain character personality within structured format\n\n");
                message.push_str(&format!(
                    "**Scenario/Request:** {}\n\n",
                    request.user_prompt
                ));
            }
            CharacterField::FirstMes => {
                message.push_str("Create a first message for this character. This should be a rich, immersive opening scene that introduces the character and establishes the roleplay context.\n\n");
                message.push_str("CHOOSE APPROPRIATE FORMAT:\n");
                message.push_str("**NARRATIVE STYLE** (for character-driven roleplay):\n");
                message
                    .push_str("- Start with compelling dialogue/action that shows personality\n");
                message
                    .push_str("- Include character thoughts, feelings, and background context\n");
                message.push_str(
                    "- Establish environment and situation through immersive description\n",
                );
                message
                    .push_str("- Mix dialogue, actions, descriptions, and internal monologue\n\n");
                message.push_str("**SYSTEM/GAME STYLE** (for RPG/stat-based roleplay):\n");
                message.push_str("- Rich narrative opening (2-3 paragraphs) with world-building\n");
                message.push_str("- CURRENT STATE section with location, health, status, etc.\n");
                message.push_str("- INVENTORY section with items and descriptions\n");
                message.push_str("- Use structured format for game-like mechanics\n\n");
                message.push_str(&format!("**Request:** {}\n\n", request.user_prompt));
            }
            _ => {
                message.push_str("Generate character content based on this request:\n\n");
                message.push_str(&format!("**User Request:** {}\n\n", request.user_prompt));

                // Add specific formatting instructions for profile style
                if let Some(style) = &request.style {
                    if matches!(style, DescriptionStyle::Profile) {
                        message.push_str("**FORMATTING REQUIREMENT:** For profile format, ensure each field is separated by \\n newline characters so they appear on separate lines when displayed.\n\n");
                    }
                }
            }
        }

        if let Some(context) = &request.character_context {
            message.push_str("**Character Context:**\n");

            if let Some(name) = &context.name {
                message.push_str(&format!("- Name: {}\n", name));
            }
            if let Some(desc) = &context.description {
                message.push_str(&format!("- Description: {}\n", desc));
            }
            if let Some(personality) = &context.personality {
                message.push_str(&format!("- Personality: {}\n", personality));
            }
            if let Some(scenario) = &context.scenario {
                message.push_str(&format!("- Scenario: {}\n", scenario));
            }
            if let Some(first_mes) = &context.first_mes {
                message.push_str(&format!("- First Message: {}\n", first_mes));
            }
            if let Some(mes_example) = &context.mes_example {
                message.push_str(&format!("- Message Examples: {}\n", mes_example));
            }
            if let Some(system_prompt) = &context.system_prompt {
                message.push_str(&format!("- System Instructions: {}\n", system_prompt));
            }
            if let Some(depth_prompt) = &context.depth_prompt {
                message.push_str(&format!("- Character Notes: {}\n", depth_prompt));
            }
            if let Some(tags) = &context.tags {
                if !tags.is_empty() {
                    message.push_str(&format!("- Tags: {}\n", tags.join(", ")));
                }
            }
            if let Some(persona) = &context.associated_persona {
                message.push_str(&format!("- User Persona: {}\n", persona));
            }

            // Include lorebook context if available
            if let Some(lorebook_entries) = &context.lorebook_entries {
                if !lorebook_entries.is_empty() {
                    message.push_str("\n**Relevant Lorebook Information:**\n");
                    for entry in lorebook_entries {
                        if entry.enabled {
                            message.push_str(&format!(
                                "- **{}**: {}\n",
                                entry.keys.join(", "),
                                entry.content
                            ));
                        }
                    }
                }
            }

            // Special instructions for alternate greetings
            if matches!(request.field, CharacterField::AlternateGreeting) {
                message.push_str("\n**Instructions for Alternate Greeting:**\n");
                message
                    .push_str("- Write ONLY what the character would say, in quotes if dialogue\n");
                message.push_str("- Use the character's name, personality, and speaking style\n");
                message.push_str(
                    "- Make it different from their main first message (create variety)\n",
                );
                message.push_str("- Consider the specific scenario/request above\n");
                message.push_str("- Stay in character - you ARE this character speaking\n");
                if let Some(context) = &request.character_context {
                    if let Some(first_mes) = &context.first_mes {
                        message.push_str(&format!(
                            "- Make it distinct from their main greeting: {}\n",
                            first_mes
                        ));
                    }
                }
            }

            message.push('\n');
        }

        if let Some(options) = &request.generation_options {
            if let Some(creativity) = &options.creativity_level {
                message.push_str(&format!("**Creativity Level:** {}\n", creativity));
            }
            if let Some(max_length) = options.max_length {
                message.push_str(&format!("**Maximum Length:** {} characters\n", max_length));
            }
        }

        match request.field {
            CharacterField::AlternateGreeting => {
                message.push_str("\nGenerate the alternate greeting as a rich, immersive scene. Choose between narrative style (dialogue, thoughts, descriptions) or system/game style (narrative + CURRENT STATE + INVENTORY sections). Stay true to the character's personality while creating a different scenario from their main greeting.");
            }
            CharacterField::FirstMes => {
                message.push_str("\nGenerate the first message as a rich, immersive introduction. Choose between narrative style (dialogue, actions, thoughts) or system/game style (narrative + CURRENT STATE + INVENTORY sections). Create a compelling opening that draws the user into the roleplay and matches the character's intended format.");
            }
            _ => {
                let mut final_instruction = format!(
                    "\nPlease generate a high-quality {} that matches the specified style and incorporates the user's request while maintaining consistency with any provided character context and lorebook information.",
                    request.field.display_name().to_lowercase()
                );

                // Add specific formatting requirement for profile style
                if let Some(style) = &request.style {
                    if matches!(style, DescriptionStyle::Profile) {
                        final_instruction.push_str(" CRITICAL: Include \\n newline characters between each field so the profile displays with proper line breaks.");
                    }
                }

                message.push_str(&final_instruction);
            }
        }

        // Add lorebook context if available
        if let Some(context) = lorebook_context {
            if !context.is_empty() {
                message.push_str(&format!("\n\n**Relevant World Information:**\n{}", context));
            }
        }

        Ok(message)
    }

    /// Build user message with context and generation request, including lorebook context, and capture debug info
    async fn build_field_generation_user_message_with_debug(
        &self,
        request: &FieldGenerationRequest,
        user_id: crate::db::DbId,
        session_dek: Option<&crate::auth::SessionDek>,
    ) -> Result<(String, DebugInfo), AppError> {
        let mut message = String::new();
        let mut debug_info = DebugInfo {
            lorebook_context_included: false,
            lorebook_entries_count: None,
            query_text_used: None,
        };

        // Query lorebook for relevant context if lorebook_id is provided
        let lorebook_context = if let Some(lorebook_id) = request.lorebook_id {
            let query_result = self
                .query_lorebook_context_with_debug(user_id, lorebook_id, request, session_dek)
                .await?;
            debug_info.lorebook_context_included = query_result.context.is_some();
            debug_info.lorebook_entries_count = query_result.entries_count;
            debug_info.query_text_used = query_result.query_text_used;
            query_result.context
        } else {
            None
        };

        // [Copy all the message building logic from the original method]
        // Special prompting for dialogue-based fields to ensure better structure
        match request.field {
            CharacterField::AlternateGreeting => {
                message.push_str("Create an alternate greeting for this character. This should be a rich, immersive opening scene that establishes a different scenario or mood than their main greeting.\n\n");
                message.push_str("CHOOSE APPROPRIATE FORMAT:\n");
                message.push_str("**NARRATIVE STYLE** (for character-driven roleplay):\n");
                message.push_str("- Start with compelling dialogue/action hook\n");
                message.push_str("- Include character thoughts and motivations\n");
                message.push_str("- Establish setting and context through immersive description\n");
                message.push_str("- Set up natural user interaction opportunities\n\n");
                message.push_str("**SYSTEM/GAME STYLE** (for RPG/stat-based roleplay):\n");
                message.push_str("- Rich narrative opening describing alternate scenario\n");
                message.push_str("- CURRENT STATE section reflecting the new situation\n");
                message.push_str("- INVENTORY section with scenario-appropriate items\n");
                message.push_str("- Maintain character personality within structured format\n\n");
                message.push_str(&format!(
                    "**Scenario/Request:** {}\n\n",
                    request.user_prompt
                ));
            }
            CharacterField::FirstMes => {
                message.push_str("Create a first message for this character. This should be a rich, immersive opening scene that introduces the character and establishes the roleplay context.\n\n");
                message.push_str("CHOOSE APPROPRIATE FORMAT:\n");
                message.push_str("**NARRATIVE STYLE** (for character-driven roleplay):\n");
                message
                    .push_str("- Start with compelling dialogue/action that shows personality\n");
                message
                    .push_str("- Include character thoughts, feelings, and background context\n");
                message.push_str(
                    "- Establish environment and situation through immersive description\n",
                );
                message.push_str("- Set up natural user interaction opportunities\n\n");
                message.push_str("**SYSTEM/GAME STYLE** (for RPG/stat-based roleplay):\n");
                message.push_str("- Rich narrative opening describing the scenario\n");
                message.push_str("- CURRENT STATE section with character status and situation\n");
                message.push_str("- INVENTORY section listing relevant items or equipment\n");
                message.push_str("- Maintain character personality within structured format\n\n");
                message.push_str(&format!("**User Request:** {}\n\n", request.user_prompt));
            }
            _ => {
                message.push_str(&format!("**User Request:** {}\n\n", request.user_prompt));
            }
        }

        // Add existing character context if available
        if let Some(context) = &request.character_context {
            message.push_str("**Existing Character Information:**\n");

            if let Some(name) = &context.name {
                message.push_str(&format!("- **Name:** {}\n", name));
            }
            if let Some(description) = &context.description {
                message.push_str(&format!("- **Description:** {}\n", description));
            }
            if let Some(personality) = &context.personality {
                message.push_str(&format!("- **Personality:** {}\n", personality));
            }
            if let Some(scenario) = &context.scenario {
                message.push_str(&format!("- **Scenario:** {}\n", scenario));
            }
            if let Some(first_mes) = &context.first_mes {
                message.push_str(&format!("- **First Message:** {}\n", first_mes));
            }
            if let Some(tags) = &context.tags {
                if !tags.is_empty() {
                    message.push_str(&format!("- **Tags:** {}\n", tags.join(", ")));
                }
            }
            if let Some(entries) = &context.lorebook_entries {
                if !entries.is_empty() {
                    message.push_str("- **Lorebook Entries:**\n");
                    for entry in entries {
                        message.push_str(&format!("  - **{}**: {}\n", entry.id, entry.content));
                        if !entry.keys.is_empty() {
                            message.push_str(&format!("    *Keys: {}*\n", entry.keys.join(", ")));
                        }
                    }
                }
            }
            if let Some(persona) = &context.associated_persona {
                message.push_str(&format!("- **Associated Persona:** {}\n", persona));
            }

            message.push('\n');
        }

        // Add generation options if specified
        if let Some(options) = &request.generation_options {
            if let Some(creativity) = &options.creativity_level {
                message.push_str(&format!("**Creativity Level:** {}\n", creativity));
            }
            if let Some(max_length) = options.max_length {
                message.push_str(&format!("**Maximum Length:** {} characters\n", max_length));
            }
        }

        match request.field {
            CharacterField::AlternateGreeting => {
                message.push_str("\nGenerate the alternate greeting as a rich, immersive scene. Choose between narrative style (dialogue, thoughts, descriptions) or system/game style (narrative + CURRENT STATE + INVENTORY sections). Stay true to the character's personality while creating a different scenario from their main greeting.");
            }
            CharacterField::FirstMes => {
                message.push_str("\nGenerate the first message as a rich, immersive introduction. Choose between narrative style (dialogue, actions, thoughts) or system/game style (narrative + CURRENT STATE + INVENTORY sections). Create a compelling opening that draws the user into the roleplay and matches the character's intended format.");
            }
            _ => {
                let mut final_instruction = format!(
                    "\nPlease generate a high-quality {} that matches the specified style and incorporates the user's request while maintaining consistency with any provided character context and lorebook information.",
                    request.field.display_name().to_lowercase()
                );

                // Add specific formatting requirement for profile style
                if let Some(style) = &request.style {
                    if matches!(style, DescriptionStyle::Profile) {
                        final_instruction.push_str(" CRITICAL: Include \\n newline characters between each field so the profile displays with proper line breaks.");
                    }
                }

                message.push_str(&final_instruction);
            }
        }

        // Add lorebook context if available
        if let Some(context) = lorebook_context {
            if !context.is_empty() {
                message.push_str(&format!("\n\n**Relevant World Information:**\n{}", context));
            }
        }

        Ok((message, debug_info))
    }

    /// Query lorebook for relevant context based on the character generation request (with debug info)
    async fn query_lorebook_context_with_debug(
        &self,
        user_id: crate::db::DbId,
        lorebook_id: crate::db::DbId,
        request: &FieldGenerationRequest,
        session_dek: Option<&crate::auth::SessionDek>,
    ) -> Result<LorebookQueryResult, AppError> {
        // Build query text from character name and field content
        let mut query_parts = Vec::new();

        // Add character name if available
        if let Some(context) = &request.character_context {
            if let Some(name) = &context.name {
                query_parts.push(name.clone());
            }
        }

        // Add user prompt content
        query_parts.push(request.user_prompt.clone());

        // Add specific field context for better matching
        match request.field {
            CharacterField::Description => {
                query_parts.push("character appearance personality".to_string())
            }
            CharacterField::Personality => {
                query_parts.push("personality traits behavior".to_string())
            }
            CharacterField::Scenario => {
                query_parts.push("setting location environment".to_string())
            }
            CharacterField::FirstMes | CharacterField::AlternateGreeting => {
                query_parts.push("introduction greeting dialogue".to_string())
            }
            _ => {}
        }

        let query_text = query_parts.join(" ");

        // Use the embedding service to retrieve relevant lorebook entries
        match self
            .state
            .embedding_pipeline_service
            .retrieve_relevant_chunks(
                self.state.clone(),
                user_id,
                None,                    // No chat session for character generation
                Some(vec![lorebook_id]), // Query the specific lorebook
                None,                    // No chronicle search for character generation
                &query_text,
                10,          // Limit to top 10 most relevant chunks
                session_dek, // SECURITY: Pass SessionDek for decrypting lorebook content
            )
            .await
        {
            Ok(chunks) => {
                if chunks.is_empty() {
                    return Ok(LorebookQueryResult {
                        context: None,
                        entries_count: Some(0),
                        query_text_used: Some(query_text),
                    });
                }

                // Format retrieved entries
                let mut formatted_entries = Vec::new();
                for chunk in &chunks {
                    match &chunk.metadata {
                        crate::services::embeddings::RetrievedMetadata::Lorebook(metadata) => {
                            if let Some(title) = &metadata.entry_title {
                                formatted_entries.push(format!("- **{}**: {}", title, chunk.text));
                            } else {
                                formatted_entries.push(format!("- {}", chunk.text));
                            }
                        }
                        _ => {
                            formatted_entries.push(format!("- {}", chunk.text));
                        }
                    }
                }

                let context = if formatted_entries.is_empty() {
                    None
                } else {
                    Some(formatted_entries.join("\n"))
                };

                Ok(LorebookQueryResult {
                    context,
                    entries_count: Some(chunks.len()),
                    query_text_used: Some(query_text),
                })
            }
            Err(e) => {
                // Log error but don't fail generation
                tracing::warn!(
                    "Failed to query lorebook context for character generation: {}",
                    e
                );
                Ok(LorebookQueryResult {
                    context: None,
                    entries_count: None,
                    query_text_used: Some(query_text),
                })
            }
        }
    }

    /// Query lorebook for relevant context based on the character generation request
    async fn query_lorebook_context(
        &self,
        user_id: crate::db::DbId,
        lorebook_id: crate::db::DbId,
        request: &FieldGenerationRequest,
        session_dek: Option<&crate::auth::SessionDek>,
    ) -> Result<Option<String>, AppError> {
        // Build query text from character name and field content
        let mut query_parts = Vec::new();

        // Add character name if available
        if let Some(context) = &request.character_context {
            if let Some(name) = &context.name {
                query_parts.push(name.clone());
            }
        }

        // Add user prompt content
        query_parts.push(request.user_prompt.clone());

        // Add specific field context for better matching
        match request.field {
            CharacterField::Description => {
                query_parts.push("character appearance personality".to_string())
            }
            CharacterField::Personality => {
                query_parts.push("personality traits behavior".to_string())
            }
            CharacterField::Scenario => {
                query_parts.push("setting location environment".to_string())
            }
            CharacterField::FirstMes | CharacterField::AlternateGreeting => {
                query_parts.push("introduction greeting dialogue".to_string())
            }
            _ => {}
        }

        let query_text = query_parts.join(" ");

        // Use the embedding service to retrieve relevant lorebook entries
        match self
            .state
            .embedding_pipeline_service
            .retrieve_relevant_chunks(
                self.state.clone(),
                user_id,
                None,                    // No chat session for character generation
                Some(vec![lorebook_id]), // Query the specific lorebook
                None,                    // No chronicle search for character generation
                &query_text,
                10,          // Limit to top 10 most relevant chunks
                session_dek, // SECURITY: Pass SessionDek for decrypting lorebook content
            )
            .await
        {
            Ok(chunks) => {
                if chunks.is_empty() {
                    Ok(None)
                } else {
                    // Format the retrieved lorebook entries for inclusion in the prompt
                    let mut context_parts = Vec::new();
                    for chunk in chunks {
                        if let crate::services::embeddings::RetrievedMetadata::Lorebook(
                            lorebook_meta,
                        ) = chunk.metadata
                        {
                            // Format entry with title if available
                            if let Some(title) = lorebook_meta.entry_title {
                                context_parts.push(format!("- **{}**: {}", title, chunk.text));
                            } else {
                                context_parts.push(format!("- {}", chunk.text));
                            }
                        }
                    }

                    if context_parts.is_empty() {
                        Ok(None)
                    } else {
                        Ok(Some(context_parts.join("\n")))
                    }
                }
            }
            Err(e) => {
                // Log the error but don't fail generation - lorebook is optional context
                tracing::warn!(
                    "Failed to query lorebook context for character generation: {}",
                    e
                );
                Ok(None)
            }
        }
    }

    /// Post-process generated content to ensure proper formatting
    fn post_process_content(
        &self,
        content: &str,
        field: &CharacterField,
        style: &Option<DescriptionStyle>,
    ) -> String {
        let mut processed_content = content.to_string();

        // Handle profile format newlines
        if let Some(DescriptionStyle::Profile) = style {
            // If the content doesn't have proper newlines, try to fix common issues
            if !processed_content.contains('\n') && processed_content.contains("Age:") {
                // Replace common field transitions with newlines
                processed_content = processed_content
                    .replace("Age:", "\nAge:")
                    .replace("Height:", "\nHeight:")
                    .replace("Build:", "\nBuild:")
                    .replace("Hair:", "\nHair:")
                    .replace("Eyes:", "\nEyes:")
                    .replace("Personality:", "\nPersonality:")
                    .replace("Background:", "\nBackground:")
                    .replace("Notable:", "\nNotable:")
                    .replace("Skills:", "\nSkills:")
                    .replace("Occupation:", "\nOccupation:")
                    .replace("Status:", "\nStatus:");

                // Clean up double newlines at the start
                if processed_content.starts_with('\n') {
                    processed_content = processed_content.trim_start_matches('\n').to_string();
                }
            }
        }

        // Handle system/game style formatting for first messages and alternate greetings
        if matches!(
            field,
            CharacterField::FirstMes | CharacterField::AlternateGreeting
        ) {
            // Ensure proper line spacing for CURRENT STATE and INVENTORY sections
            processed_content = processed_content
                .replace("CURRENT STATE:", "\n\nCURRENT STATE:")
                .replace("INVENTORY:", "\n\nINVENTORY:")
                .replace("Location:", "\nLocation:")
                .replace("Health:", "\nHealth:")
                .replace("Power Path:", "\nPower Path:")
                .replace("Attainment:", "\nAttainment:")
                .replace("Status:", "\nStatus:");
        }

        processed_content
    }

    /// Generate content using structured output following the main chat generation pattern
    async fn generate_with_structured_output(
        &self,
        system_prompt: &str,
        messages: &[GenAiChatMessage],
        schema: &crate::DbJson,
        request: &FieldGenerationRequest,
    ) -> Result<crate::DbJson, AppError> {
        use genai::chat::{
            ChatOptions as GenAiChatOptions, ChatResponseFormat, ChatRole, JsonSchemaSpec,
        };

        // Follow the same pattern as main chat generation
        let mut messages_vec: Vec<GenAiChatMessage> = messages.to_vec();

        // Add prefill message to establish generation context (following main chat pattern)
        let prefill_content = match &request.field {
            CharacterField::AlternateGreeting => {
                if let Some(context) = &request.character_context {
                    if let Some(name) = &context.name {
                        format!("I'll create an alternate greeting for {}, staying true to their character while offering a different scenario:", name)
                    } else {
                        "I'll create an alternate greeting for this character, staying true to their personality while offering a different scenario:".to_string()
                    }
                } else {
                    "I'll create an alternate greeting that offers a different conversation starter:".to_string()
                }
            },
            _ => "I'll generate the requested character content, focusing on quality and consistency with the provided context:".to_string()
        };

        let prefill_message = GenAiChatMessage {
            role: ChatRole::Assistant,
            content: MessageContent::Text(prefill_content),
            options: None,
        };
        messages_vec.push(prefill_message);

        // Build chat options similar to main generation
        let mut genai_chat_options = GenAiChatOptions::default();

        // Set temperature for creative generation
        genai_chat_options = genai_chat_options.with_temperature(0.8);

        // Set max tokens based on field complexity
        let max_tokens = match &request.field {
            CharacterField::FirstMes | CharacterField::AlternateGreeting => 4096, // Longer for rich, immersive scenes
            CharacterField::Description | CharacterField::Personality => 3072, // Medium for detailed descriptions
            _ => 2048, // Standard for other fields
        };
        genai_chat_options = genai_chat_options.with_max_tokens(max_tokens);

        // Add reasoning budget for complex fields that benefit from thinking
        use genai::chat::ReasoningEffort;
        let reasoning_budget = match &request.field {
            CharacterField::AlternateGreeting => Some(ReasoningEffort::Budget(8000)), // Medium thinking for complex roleplay
            CharacterField::Description | CharacterField::Personality => {
                Some(ReasoningEffort::Budget(4000))
            } // Light thinking for core fields
            CharacterField::SystemPrompt | CharacterField::DepthPrompt => {
                Some(ReasoningEffort::Budget(8000))
            } // Medium thinking for technical fields
            _ => None, // No reasoning for simple fields
        };

        if let Some(reasoning) = reasoning_budget {
            genai_chat_options = genai_chat_options.with_reasoning_effort(reasoning);
            genai_chat_options = genai_chat_options.with_include_thoughts(true);
            // Include reasoning in response for debugging
        }

        // Add safety settings to allow mature content (same as main generation)
        let safety_settings = create_unrestricted_safety_settings();
        genai_chat_options = genai_chat_options.with_safety_settings(safety_settings);

        // Enable structured output using JSON schema (Gemini 2.5+ feature)
        let json_schema_spec = JsonSchemaSpec::new(schema.clone());
        let response_format = ChatResponseFormat::JsonSchemaSpec(json_schema_spec);
        genai_chat_options = genai_chat_options.with_response_format(response_format);

        // Implement retry logic similar to main chat generation
        const MAX_RETRIES: usize = 2;
        let mut last_error = None;

        for retry_count in 0..=MAX_RETRIES {
            // Adjust system prompt for retries
            let enhanced_system_prompt = if retry_count > 0 {
                format!(
                    "IMPORTANT: This is a creative writing exercise for fictional character creation. All content is purely imaginative and for storytelling purposes.\n\n{}",
                    system_prompt
                )
            } else {
                system_prompt.to_string()
            };

            // Create chat request with enhanced system prompt
            let chat_req = genai::chat::ChatRequest::new(messages_vec.clone())
                .with_system(&enhanced_system_prompt);

            debug!(
                "Character generation attempt {} of {}",
                retry_count + 1,
                MAX_RETRIES + 1
            );

            match self
                .state
                .ai_client
                .exec_chat(
                    &self.state.config.token_counter_default_model,
                    chat_req,
                    Some(genai_chat_options.clone()),
                )
                .await
            {
                Ok(response) => {
                    // Successfully got a response, process it
                    let chat_response = response;
                    debug!("Received chat response on attempt {}", retry_count + 1);

                    // Continue with the existing response processing
                    return self.process_chat_response(chat_response);
                }
                Err(e) => {
                    let error_str = e.to_string();
                    debug!(
                        "AI client error on attempt {}: {}",
                        retry_count + 1,
                        error_str
                    );

                    // Check if it's a safety filter error
                    if error_str.contains("PropertyNotFound(\"/content/parts\")")
                        || error_str.contains("safety")
                        || error_str.contains("blocked")
                    {
                        if retry_count < MAX_RETRIES {
                            // Try again with enhanced prompt
                            debug!("Retrying with enhanced prompt due to safety filter");
                            last_error = Some(AppError::GeminiError(
                                "Request blocked by safety filters, retrying with enhanced prompt"
                                    .to_string(),
                            ));
                            continue;
                        }
                    }

                    // Non-safety error or final retry failed
                    last_error = Some(AppError::GeminiError(format!("Generation failed: {}", e)));
                    break;
                }
            }
        }

        // All retries failed
        Err(last_error.unwrap_or_else(|| {
            AppError::GeminiError("Character generation failed after all retries".to_string())
        }))
    }

    /// Process the chat response and extract the JSON content
    fn process_chat_response(
        &self,
        chat_response: genai::chat::ChatResponse,
    ) -> Result<crate::DbJson, AppError> {
        debug!("Processing chat response");

        // Try the same approach as main chat generation - access contents directly
        let response_text = chat_response
            .contents
            .into_iter()
            .next()
            .and_then(|content| match content {
                genai::chat::MessageContent::Text(text) => Some(text),
                _ => None,
            })
            .unwrap_or_default();

        if response_text.is_empty() {
            return Err(AppError::GeminiError(
                "No content in response - likely blocked by safety filters. Try a simpler prompt."
                    .to_string(),
            ));
        }

        debug!(
            "Received response from LLM: {} characters",
            response_text.len()
        );

        // Parse the structured JSON response
        match serde_json::from_str::<crate::DbJson>(&response_text) {
            Ok(json) => {
                debug!("Successfully parsed structured JSON response");
                Ok(json)
            }
            Err(e) => {
                debug!("Failed to parse as JSON, error: {}", e);
                debug!("Raw response: {}", response_text);

                // Fallback: wrap plain text response in expected structure
                debug!("Wrapping plain text response in expected structure");
                Ok(serde_json::json!({
                    "content": response_text,
                    "reasoning": "Generated as plain text response due to JSON parsing failure",
                    "style_applied": "auto",
                    "quality_score": 7
                })
                .into())
            }
        }
    }

    /// Count tokens for the generation request
    async fn count_tokens(
        &self,
        system_prompt: &str,
        messages: &[GenAiChatMessage],
    ) -> Result<usize, AppError> {
        let mut total_tokens = 0;

        // Count system prompt tokens
        total_tokens += self
            .state
            .token_counter
            .count_tokens(
                system_prompt,
                CountingMode::LocalOnly,
                Some(&self.state.config.token_counter_default_model),
            )
            .await?
            .total;

        // Count message tokens
        for message in messages {
            if let MessageContent::Text(text) = &message.content {
                total_tokens += self
                    .state
                    .token_counter
                    .count_tokens(
                        text,
                        CountingMode::LocalOnly,
                        Some(&self.state.config.token_counter_default_model),
                    )
                    .await?
                    .total;
            }
        }

        Ok(total_tokens)
    }

    /// Analyze the style of existing content using structured output
    #[instrument(skip_all)]
    pub async fn analyze_style(&self, content: &str) -> Result<StyleAnalysisOutput, AppError> {
        let start_time = Instant::now();

        info!(
            "Starting style analysis for content with {} characters",
            content.len()
        );

        // Build system prompt for style analysis
        let system_prompt = r#"You are an expert in analyzing character description styles for creative writing and roleplay.
Your task is to analyze the provided text and classify it into one of the following styles:

**Style Types:**

1. **traits**: Brief, punchy character traits and physical characteristics
   - Uses short sentences or fragments
   - Focuses on observable features
   - Example: "Tall. Athletic build. Green eyes. Former soldier. Quiet. Strategic thinker."

2. **narrative**: Story-like, flowing prose with complete sentences
   - Uses descriptive, flowing language
   - Tells a story or paints a picture
   - Example: "Captain Elena stands at the helm, her weathered hands gripping the wheel as storm clouds gather..."

3. **profile**: Structured biographical information with clear field labels
   - Uses "Field: Value" format
   - Organized like a character sheet
   - Example: "Name: Elena\nAge: 34\nOccupation: Ship Captain\nPersonality: Determined, fair but firm"

4. **group**: Multiple character descriptions using Characters() format
   - Defines multiple characters in one text
   - Uses Characters() notation
   - Example: "Characters(\"Captain, Engineer, Navigator\")\nCaptain(\"A former pirate...\")"

5. **worldbuilding**: Rich world context and lore with {{char}} placeholders
   - Establishes character within a larger fictional universe
   - Includes world lore and setting details
   - May use {{char}} notation
   - Example: "{{char}} is a Guardian of the Stellar Nexus, one of the ancient beings..."

6. **system**: AI behavior instructions with {{char}} and {{user}} placeholders
   - Defines what the AI will/won't do
   - Uses technical roleplay notation
   - Example: "{{char}} will generate random encounters. {{char}} will track {{user}}'s health and inventory."

Analyze the text carefully and identify which style it most closely matches. Provide specific indicators and helpful recommendations."#;

        // Build user message with the content to analyze
        let user_message = format!(
            r#"Analyze this character description and classify its style:

**Content to Analyze:**
{}

Provide a detailed analysis including:
- The detected style (one of: traits, narrative, profile, group, worldbuilding, system)
- Your confidence level (0.0 to 1.0)
- Specific features that indicate this style
- Recommendations for improving or enhancing the content"#,
            content
        );

        // Create messages for generation
        let messages = vec![GenAiChatMessage {
            role: ChatRole::User,
            content: MessageContent::Text(user_message),
            options: None,
        }];

        // Create a dummy request for compatibility with generate_with_structured_output
        let dummy_request = FieldGenerationRequest {
            field: CharacterField::Description, // Doesn't matter for analysis
            mode: GenerationMode::Create,       // Doesn't matter for analysis
            user_prompt: String::new(),
            style: None,
            character_context: None,
            generation_options: None,
            lorebook_id: None,
        };

        // Generate using the LLM with structured output
        let generated_output = self
            .generate_with_structured_output(
                &system_prompt,
                &messages,
                &get_style_analysis_schema(),
                &dummy_request,
            )
            .await?;

        // Parse the structured output
        let style_analysis: StyleAnalysisOutput =
            serde_json::from_value(generated_output.clone().into()).map_err(|e| {
                AppError::InternalServerErrorGeneric(format!(
                    "Failed to parse style analysis output: {}",
                    e
                ))
            })?;

        let generation_time = start_time.elapsed();
        info!(
            "Style analysis completed in {}ms with style: {:?}, confidence: {}",
            generation_time.as_millis(),
            style_analysis.detected_style,
            style_analysis.confidence
        );

        Ok(style_analysis)
    }
}
