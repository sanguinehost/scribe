use std::sync::Arc;
use std::time::Instant;
use genai::chat::{ChatMessage as GenAiChatMessage, ChatRole, MessageContent};
use tracing::{debug, info, instrument};

use crate::{
    AppState,
    errors::AppError,
    services::hybrid_token_counter::CountingMode,
};

use super::{
    types::*,
    structured_output::*,
};

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

impl FieldGenerator {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    /// Generate a specific character field using structured output
    #[instrument(skip_all, fields(field = ?request.field))]
    pub async fn generate_field(&self, request: FieldGenerationRequest, user_id: uuid::Uuid) -> Result<FieldGenerationResult, AppError> {
        let start_time = Instant::now();
        
        info!("Starting field generation for {:?}", request.field);

        // Determine the style to use
        let style = request.style.clone().unwrap_or(DescriptionStyle::Auto);
        
        // Build the system prompt specifically for character field generation
        let system_prompt = self.build_field_generation_system_prompt(&request.field, &style);
        
        // Build the user message with context and instructions, capturing debug info
        let (user_message, debug_info) = self.build_field_generation_user_message_with_debug(&request, user_id).await?;
        
        // Create a simple message for generation
        let messages = vec![
            GenAiChatMessage {
                role: ChatRole::User,
                content: MessageContent::Text(user_message.clone()),
                options: None,
            }
        ];

        // Generate using the LLM with structured output
        let generated_output = self.generate_with_structured_output(
            &system_prompt,
            &messages,
            &get_field_generation_schema(),
            &request,
        ).await?;

        // Parse the structured output
        let mut field_output: CharacterFieldOutput = serde_json::from_value(generated_output)
            .map_err(|e| AppError::InternalServerErrorGeneric(
                format!("Failed to parse field generation output: {}", e)
            ))?;
        
        // Post-process content for proper formatting
        field_output.content = self.post_process_content(&field_output.content, &request.field, &request.style);

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
            timestamp: chrono::Utc::now(),
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
    fn build_field_generation_system_prompt(&self, field: &CharacterField, style: &DescriptionStyle) -> String {
        let field_name = field.display_name();
        
        // Base instruction with field-specific guidance
        let base_instruction = match field {
            CharacterField::AlternateGreeting => {
                "You are a helpful assistant that creates character content for creative writing. Generate an alternate greeting that provides a different starting scenario or mood from the character's main first message. This should be a rich, immersive opening scene that establishes context and invites interaction.".to_string()
            },
            CharacterField::FirstMes => {
                "You are a helpful assistant that creates character content for creative writing. Generate a first message that serves as the opening scene for roleplay. This should be a rich, immersive introduction that establishes the character, setting, and situation while inviting user interaction.".to_string()
            },
            _ => {
                format!(
                    "You are a helpful assistant that creates character content for creative writing. Generate a {} based on the user's request.",
                    field_name.to_lowercase()
                )
            }
        };

        // Add style-specific guidance and examples
        let style_guidance = match (field, style) {
            // Special handling for first messages - focus on rich, immersive openings
            (CharacterField::FirstMes, _) => {
                r#"Create a rich, immersive opening scene that introduces the character and establishes the roleplay context. Choose the appropriate structure based on the character type:

**For Narrative/Character-Driven Roleplay:**
1. **Opening Hook**: Start with compelling dialogue, action, or scene setting
2. **Character Introduction**: Show personality through actions, thoughts, and speech
3. **Setting/Context**: Establish the environment and situation
4. **Character Voice**: Include internal thoughts that reveal motivations and background
5. **User Integration**: Set up the scenario to invite user interaction
6. **Proper Length**: Multiple paragraphs that create immersion and establish the world

**For System/Game-Style Roleplay:**
1. **Rich Narrative Opening**: Detailed world-building and character situation (2-3 paragraphs)
2. **CURRENT STATE Section**: Character stats, health, location, status
3. **INVENTORY Section**: Listed items with descriptions

Example Game-Style Format:
```
[Rich narrative paragraph describing situation and world]

CURRENT STATE:
Location: [Current location]
Health: [Health status and condition]
Power Path: [Character's abilities/class]
Attainment: [Power level/rank]
Status: [Current situation/goals]

INVENTORY (Carried):
[List of items with descriptions]
```

Choose the format that best matches the character's setting and intended roleplay style."#
            },
            // Special handling for alternate greetings - focus on rich, immersive openings
            (CharacterField::AlternateGreeting, _) => {
                r#"Create a rich, immersive opening scene that establishes context, character voice, and user interaction. Choose the appropriate structure based on the character type:

**For Narrative/Character-Driven Roleplay:**
1. **Opening Hook**: Start with dialogue, action, or compelling scene setting
2. **Scene/Context**: Establish where this is happening and what's going on  
3. **Character Voice**: Show personality through thoughts, actions, and speech
4. **User Integration**: Set up the scenario for user interaction
5. **Proper Length**: Multiple paragraphs that create immersion

**For System/Game-Style Roleplay:**
1. **Rich Narrative Opening**: Detailed alternate scenario with world-building (2-3 paragraphs)
2. **CURRENT STATE Section**: Updated character stats reflecting the new situation
3. **INVENTORY Section**: Items relevant to this specific scenario

Make this distinct from their main greeting by using a different scenario, mood, or situation while maintaining the character's core personality and the appropriate format style."#
            },
            // Regular field generation with existing style examples
            (_, DescriptionStyle::Profile) => {
                r#"Use structured profile format with clear field labels separated by newlines. IMPORTANT: Include \n newline characters between each field. Example:
Name: Captain Elena Vasquez\nAge: 34\nHeight: 5'8"\nBuild: Athletic, weathered from years at sea\nHair: Dark brown, usually tied back\nEyes: Steel gray\nPersonality: Determined, fair but firm, distrusts authority\nBackground: Former naval officer turned independent trader\nNotable: Has a mysterious treasure map hidden in her cabin

Each field should be on its own line with proper newline separation for readability."#
            },
            (_, DescriptionStyle::Traits) => {
                r#"Use short, punchy sentences and fragments. Focus on observable traits. Example:
Tall. Lean build. Silver hair, piercing green eyes. Former military sniper. Calm under pressure. Doesn't talk much. Prefers action over words. Methodical. Patient. Excellent marksman. Haunted by past missions. Drinks black coffee. Wears dark clothing."#
            },
            (_, DescriptionStyle::Narrative) => {
                r#"Write in flowing, story-like prose with complete sentences. Example:
Captain Elena Vasquez stands at the helm of her merchant vessel, weathered hands gripping the wheel as storm clouds gather on the horizon. Twenty years of sailing treacherous waters have carved lines of determination into her sun-bronzed face, while her steel-gray eyes reflect the wisdom earned through countless adventures."#
            },
            (_, DescriptionStyle::Group) => {
                r#"Use the Characters() format for multiple characters. Example:
Characters("Captain Zara, Chief Engineer Bolt, Navigator Iris")
Captain Zara("A former pirate turned legitimate salvager. Fiery red hair, cybernetic left arm, sharp tongue. Excellent pilot and negotiator.")
Chief Engineer Bolt("A gruff, bearded engineer who can fix anything. Missing his right leg from a reactor explosion. Drinks too much but never when on duty.")
Navigator Iris("A young prodigy with enhanced neural implants. Quiet and analytical, but has moments of surprising insight.")"#
            },
            (_, DescriptionStyle::Worldbuilding) => {
                r#"Establish the character as part of a larger fictional universe. Include world lore and context. Example:
{{char}} is a Guardian of the Stellar Nexus, one of the ancient beings who maintain the cosmic balance between the seven dimensional realms. In the current age known as the Twilight Convergence, the barriers between dimensions have grown thin, allowing creatures and energies to bleed through."#
            },
            (_, DescriptionStyle::System) => {
                r#"Create behavioral instructions for AI roleplay. Define what the character will/won't do. Example:
{{char}} is an adaptive survival simulation that responds to {{user}}'s choices in a post-apocalyptic wasteland. {{char}} will generate random encounters, manage resource scarcity, and track {{user}}'s health, hunger, and sanity levels. {{char}} will never guarantee {{user}}'s safety - death is a real possibility."#
            },
            (_, DescriptionStyle::Auto) => {
                "Choose the most appropriate style based on the context and field type. Focus on creating engaging, well-structured content."
            },
        };

        let json_instruction = if matches!(style, DescriptionStyle::Profile) {
            format!("You must respond with a JSON object containing:\n- content: The generated {} in profile format with \\n newline characters between each field for proper formatting\n- reasoning: Brief explanation of your creative choices\n- style_applied: The style you used\n- quality_score: Your assessment of the content quality (1-10)", field_name.to_lowercase())
        } else {
            format!("You must respond with a JSON object containing:\n- content: The generated {} in the specified style\n- reasoning: Brief explanation of your creative choices\n- style_applied: The style you used\n- quality_score: Your assessment of the content quality (1-10)", field_name.to_lowercase())
        };
        
        format!("{}\n\n{}\n\n{}", base_instruction, style_guidance, json_instruction)
    }

    /// Build user message with context and generation request, including lorebook context
    async fn build_field_generation_user_message(&self, request: &FieldGenerationRequest, user_id: uuid::Uuid) -> Result<String, AppError> {
        let mut message = String::new();

        // Query lorebook for relevant context if lorebook_id is provided
        let lorebook_context = if let Some(lorebook_id) = request.lorebook_id {
            self.query_lorebook_context(user_id, lorebook_id, request).await?
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
                message.push_str(&format!("**Scenario/Request:** {}\n\n", request.user_prompt));
            },
            CharacterField::FirstMes => {
                message.push_str("Create a first message for this character. This should be a rich, immersive opening scene that introduces the character and establishes the roleplay context.\n\n");
                message.push_str("CHOOSE APPROPRIATE FORMAT:\n");
                message.push_str("**NARRATIVE STYLE** (for character-driven roleplay):\n");
                message.push_str("- Start with compelling dialogue/action that shows personality\n");
                message.push_str("- Include character thoughts, feelings, and background context\n");
                message.push_str("- Establish environment and situation through immersive description\n");
                message.push_str("- Mix dialogue, actions, descriptions, and internal monologue\n\n");
                message.push_str("**SYSTEM/GAME STYLE** (for RPG/stat-based roleplay):\n");
                message.push_str("- Rich narrative opening (2-3 paragraphs) with world-building\n");
                message.push_str("- CURRENT STATE section with location, health, status, etc.\n");
                message.push_str("- INVENTORY section with items and descriptions\n");
                message.push_str("- Use structured format for game-like mechanics\n\n");
                message.push_str(&format!("**Request:** {}\n\n", request.user_prompt));
            },
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
                            message.push_str(&format!("- **{}**: {}\n", 
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
                message.push_str("- Write ONLY what the character would say, in quotes if dialogue\n");
                message.push_str("- Use the character's name, personality, and speaking style\n");
                message.push_str("- Make it different from their main first message (create variety)\n");
                message.push_str("- Consider the specific scenario/request above\n");
                message.push_str("- Stay in character - you ARE this character speaking\n");
                if let Some(context) = &request.character_context {
                    if let Some(first_mes) = &context.first_mes {
                        message.push_str(&format!("- Make it distinct from their main greeting: {}\n", first_mes));
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
            },
            CharacterField::FirstMes => {
                message.push_str("\nGenerate the first message as a rich, immersive introduction. Choose between narrative style (dialogue, actions, thoughts) or system/game style (narrative + CURRENT STATE + INVENTORY sections). Create a compelling opening that draws the user into the roleplay and matches the character's intended format.");
            },
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
    async fn build_field_generation_user_message_with_debug(&self, request: &FieldGenerationRequest, user_id: uuid::Uuid) -> Result<(String, DebugInfo), AppError> {
        let mut message = String::new();
        let mut debug_info = DebugInfo {
            lorebook_context_included: false,
            lorebook_entries_count: None,
            query_text_used: None,
        };

        // Query lorebook for relevant context if lorebook_id is provided
        let lorebook_context = if let Some(lorebook_id) = request.lorebook_id {
            let query_result = self.query_lorebook_context_with_debug(user_id, lorebook_id, request).await?;
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
                message.push_str(&format!("**Scenario/Request:** {}\n\n", request.user_prompt));
            },
            CharacterField::FirstMes => {
                message.push_str("Create a first message for this character. This should be a rich, immersive opening scene that introduces the character and establishes the roleplay context.\n\n");
                message.push_str("CHOOSE APPROPRIATE FORMAT:\n");
                message.push_str("**NARRATIVE STYLE** (for character-driven roleplay):\n");
                message.push_str("- Start with compelling dialogue/action that shows personality\n");
                message.push_str("- Include character thoughts, feelings, and background context\n");
                message.push_str("- Establish environment and situation through immersive description\n");
                message.push_str("- Set up natural user interaction opportunities\n\n");
                message.push_str("**SYSTEM/GAME STYLE** (for RPG/stat-based roleplay):\n");
                message.push_str("- Rich narrative opening describing the scenario\n");
                message.push_str("- CURRENT STATE section with character status and situation\n");
                message.push_str("- INVENTORY section listing relevant items or equipment\n");
                message.push_str("- Maintain character personality within structured format\n\n");
                message.push_str(&format!("**User Request:** {}\n\n", request.user_prompt));
            },
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
            },
            CharacterField::FirstMes => {
                message.push_str("\nGenerate the first message as a rich, immersive introduction. Choose between narrative style (dialogue, actions, thoughts) or system/game style (narrative + CURRENT STATE + INVENTORY sections). Create a compelling opening that draws the user into the roleplay and matches the character's intended format.");
            },
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
    async fn query_lorebook_context_with_debug(&self, user_id: uuid::Uuid, lorebook_id: uuid::Uuid, request: &FieldGenerationRequest) -> Result<LorebookQueryResult, AppError> {
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
            CharacterField::Description => query_parts.push("character appearance personality".to_string()),
            CharacterField::Personality => query_parts.push("personality traits behavior".to_string()),
            CharacterField::Scenario => query_parts.push("setting location environment".to_string()),
            CharacterField::FirstMes | CharacterField::AlternateGreeting => query_parts.push("introduction greeting dialogue".to_string()),
            _ => {}
        }
        
        let query_text = query_parts.join(" ");
        
        // Use the embedding service to retrieve relevant lorebook entries
        match self.state.embedding_pipeline_service.retrieve_relevant_chunks(
            self.state.clone(),
            user_id,
            None, // No chat session for character generation
            Some(vec![lorebook_id]), // Query the specific lorebook
            &query_text,
            10, // Limit to top 10 most relevant chunks
        ).await {
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
                tracing::warn!("Failed to query lorebook context for character generation: {}", e);
                Ok(LorebookQueryResult {
                    context: None,
                    entries_count: None,
                    query_text_used: Some(query_text),
                })
            }
        }
    }

    /// Query lorebook for relevant context based on the character generation request
    async fn query_lorebook_context(&self, user_id: uuid::Uuid, lorebook_id: uuid::Uuid, request: &FieldGenerationRequest) -> Result<Option<String>, AppError> {
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
            CharacterField::Description => query_parts.push("character appearance personality".to_string()),
            CharacterField::Personality => query_parts.push("personality traits behavior".to_string()),
            CharacterField::Scenario => query_parts.push("setting location environment".to_string()),
            CharacterField::FirstMes | CharacterField::AlternateGreeting => query_parts.push("introduction greeting dialogue".to_string()),
            _ => {}
        }
        
        let query_text = query_parts.join(" ");
        
        // Use the embedding service to retrieve relevant lorebook entries
        match self.state.embedding_pipeline_service.retrieve_relevant_chunks(
            self.state.clone(),
            user_id,
            None, // No chat session for character generation
            Some(vec![lorebook_id]), // Query the specific lorebook
            &query_text,
            10, // Limit to top 10 most relevant chunks
        ).await {
            Ok(chunks) => {
                if chunks.is_empty() {
                    Ok(None)
                } else {
                    // Format the retrieved lorebook entries for inclusion in the prompt
                    let mut context_parts = Vec::new();
                    for chunk in chunks {
                        if let crate::services::embeddings::RetrievedMetadata::Lorebook(lorebook_meta) = chunk.metadata {
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
                tracing::warn!("Failed to query lorebook context for character generation: {}", e);
                Ok(None)
            }
        }
    }
    
    /// Post-process generated content to ensure proper formatting
    fn post_process_content(&self, content: &str, field: &CharacterField, style: &Option<DescriptionStyle>) -> String {
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
        if matches!(field, CharacterField::FirstMes | CharacterField::AlternateGreeting) {
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
        schema: &serde_json::Value,
        request: &FieldGenerationRequest,
    ) -> Result<serde_json::Value, AppError> {
        use genai::chat::{ChatOptions as GenAiChatOptions, HarmBlockThreshold, HarmCategory, SafetySetting, ChatResponseFormat, JsonSchemaSpec, ChatRole};
        
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
            CharacterField::Description | CharacterField::Personality => 3072,    // Medium for detailed descriptions
            _ => 2048, // Standard for other fields
        };
        genai_chat_options = genai_chat_options.with_max_tokens(max_tokens);
        
        // Add reasoning budget for complex fields that benefit from thinking
        use genai::chat::ReasoningEffort;
        let reasoning_budget = match &request.field {
            CharacterField::AlternateGreeting => Some(ReasoningEffort::Budget(8000)), // Medium thinking for complex roleplay
            CharacterField::Description | CharacterField::Personality => Some(ReasoningEffort::Budget(4000)), // Light thinking for core fields
            CharacterField::SystemPrompt | CharacterField::DepthPrompt => Some(ReasoningEffort::Budget(8000)), // Medium thinking for technical fields
            _ => None, // No reasoning for simple fields
        };
        
        if let Some(reasoning) = reasoning_budget {
            genai_chat_options = genai_chat_options.with_reasoning_effort(reasoning);
            genai_chat_options = genai_chat_options.with_include_thoughts(true); // Include reasoning in response for debugging
        }
        
        // Add safety settings to allow mature content (same as main generation)
        let safety_settings = vec![
            SafetySetting::new(HarmCategory::Harassment, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::HateSpeech, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::SexuallyExplicit, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::DangerousContent, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::CivicIntegrity, HarmBlockThreshold::BlockNone),
        ];
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
            let chat_req = genai::chat::ChatRequest::new(messages_vec.clone()).with_system(&enhanced_system_prompt);
            
            debug!("Character generation attempt {} of {}", retry_count + 1, MAX_RETRIES + 1);
            
            match self.state.ai_client
                .exec_chat(&self.state.config.token_counter_default_model, chat_req, Some(genai_chat_options.clone()))
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
                    debug!("AI client error on attempt {}: {}", retry_count + 1, error_str);
                    
                    // Check if it's a safety filter error
                    if error_str.contains("PropertyNotFound(\"/content/parts\")") 
                        || error_str.contains("safety") 
                        || error_str.contains("blocked") {
                        
                        if retry_count < MAX_RETRIES {
                            // Try again with enhanced prompt
                            debug!("Retrying with enhanced prompt due to safety filter");
                            last_error = Some(AppError::GeminiError(
                                "Request blocked by safety filters, retrying with enhanced prompt".to_string()
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
        Err(last_error.unwrap_or_else(|| AppError::GeminiError("Character generation failed after all retries".to_string())))
    }
    
    /// Process the chat response and extract the JSON content
    fn process_chat_response(&self, chat_response: genai::chat::ChatResponse) -> Result<serde_json::Value, AppError> {
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
            return Err(AppError::GeminiError("No content in response - likely blocked by safety filters. Try a simpler prompt.".to_string()));
        }

        debug!("Received response from LLM: {} characters", response_text.len());

        // Parse the structured JSON response
        match serde_json::from_str::<serde_json::Value>(&response_text) {
            Ok(json) => {
                debug!("Successfully parsed structured JSON response");
                Ok(json)
            },
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
                }))
            }
        }
    }

    /// Count tokens for the generation request
    async fn count_tokens(&self, system_prompt: &str, messages: &[GenAiChatMessage]) -> Result<usize, AppError> {
        let mut total_tokens = 0;

        // Count system prompt tokens
        total_tokens += self.state.token_counter
            .count_tokens(system_prompt, CountingMode::LocalOnly, Some(&self.state.config.token_counter_default_model))
            .await?
            .total;

        // Count message tokens
        for message in messages {
            if let MessageContent::Text(text) = &message.content {
                total_tokens += self.state.token_counter
                    .count_tokens(text, CountingMode::LocalOnly, Some(&self.state.config.token_counter_default_model))
                    .await?
                    .total;
            }
        }

        Ok(total_tokens)
    }
}