use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Supported character field types for generation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CharacterField {
    Description,
    Personality,
    FirstMes,
    Scenario,
    MesExample,
    SystemPrompt,
    DepthPrompt,
    Tags,
    AlternateGreeting,
    EntryContent,
    EntryComment,
}

impl CharacterField {
    /// Get the display name for the field
    pub fn display_name(&self) -> &'static str {
        match self {
            CharacterField::Description => "Description",
            CharacterField::Personality => "Personality",
            CharacterField::FirstMes => "First Message",
            CharacterField::Scenario => "Scenario",
            CharacterField::MesExample => "Message Examples",
            CharacterField::SystemPrompt => "System Instructions",
            CharacterField::DepthPrompt => "Character Notes",
            CharacterField::Tags => "Tags",
            CharacterField::AlternateGreeting => "Alternate Greeting",
            CharacterField::EntryContent => "Entry Content",
            CharacterField::EntryComment => "Entry Comment",
        }
    }

    /// Get the field name as used in the database
    pub fn db_field_name(&self) -> &'static str {
        match self {
            CharacterField::Description => "description",
            CharacterField::Personality => "personality",
            CharacterField::FirstMes => "first_mes",
            CharacterField::Scenario => "scenario",
            CharacterField::MesExample => "mes_example",
            CharacterField::SystemPrompt => "system_prompt",
            CharacterField::DepthPrompt => "depth_prompt",
            CharacterField::Tags => "tags",
            CharacterField::AlternateGreeting => "alternate_greeting",
            CharacterField::EntryContent => "entry_content",
            CharacterField::EntryComment => "entry_comment",
        }
    }
}

/// Character description styles supported by the generator
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DescriptionStyle {
    Traits,
    Narrative,
    Profile,
    Group,
    Worldbuilding,
    System,
    Auto, // Auto-detect based on content
}

impl DescriptionStyle {
    pub fn as_str(&self) -> &'static str {
        match self {
            DescriptionStyle::Traits => "traits",
            DescriptionStyle::Narrative => "narrative",
            DescriptionStyle::Profile => "profile",
            DescriptionStyle::Group => "group",
            DescriptionStyle::Worldbuilding => "worldbuilding",
            DescriptionStyle::System => "system",
            DescriptionStyle::Auto => "auto",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            DescriptionStyle::Traits => "Character Traits",
            DescriptionStyle::Narrative => "Narrative Description",
            DescriptionStyle::Profile => "Profile Format",
            DescriptionStyle::Group => "Group Characters",
            DescriptionStyle::Worldbuilding => "World-Building/Lore",
            DescriptionStyle::System => "System Instructions",
            DescriptionStyle::Auto => "Auto-detect",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            DescriptionStyle::Traits => "Brief, punchy traits and physical characteristics",
            DescriptionStyle::Narrative => "Story-like description with background and context",
            DescriptionStyle::Profile => "Organized data fields with biographical information",
            DescriptionStyle::Group => "Multiple character definitions with Characters() format",
            DescriptionStyle::Worldbuilding => {
                "Rich world context with character as part of larger narrative universe"
            }
            DescriptionStyle::System => {
                "Behavioral rules and interaction guidelines for AI roleplay"
            }
            DescriptionStyle::Auto => "Automatically detect the best style based on context",
        }
    }
}

/// Request for generating a specific character field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldGenerationRequest {
    pub field: CharacterField,
    pub mode: GenerationMode,
    pub style: Option<DescriptionStyle>,
    pub user_prompt: String,
    pub character_context: Option<CharacterContext>,
    pub generation_options: Option<GenerationOptions>,
    pub lorebook_id: Option<crate::db::DbId>, // Optional lorebook to query for relevant context
}

/// Request for generating a complete character
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullCharacterRequest {
    pub concept: String,
    pub style_preferences: Option<StylePreferences>,
    pub generation_options: Option<GenerationOptions>,
}

/// Request for enhancing existing character content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancementRequest {
    pub field: CharacterField,
    pub current_content: String,
    pub enhancement_instructions: String,
    pub character_context: Option<CharacterContext>,
    pub generation_options: Option<GenerationOptions>,
}

/// Character context for generation (what we know about the character so far)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CharacterContext {
    pub name: Option<String>,
    pub description: Option<String>,
    pub personality: Option<String>,
    pub scenario: Option<String>,
    pub first_mes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub mes_example: Option<String>,
    pub system_prompt: Option<String>,
    pub depth_prompt: Option<String>,
    pub alternate_greetings: Option<Vec<String>>,
    pub lorebook_entries: Option<Vec<LorebookEntry>>,
    pub associated_persona: Option<String>, // User persona information
}

/// Lorebook entry for providing context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LorebookEntry {
    pub id: String,
    pub keys: Vec<String>,
    pub content: String,
    pub priority: Option<i32>,
    pub enabled: bool,
}

/// Style preferences for character generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StylePreferences {
    pub description_style: Option<DescriptionStyle>,
    pub tone: Option<String>,   // "casual", "formal", "poetic", etc.
    pub length: Option<String>, // "brief", "detailed", "extensive"
    pub focus: Option<String>,  // "appearance", "personality", "background", etc.
}

/// Options for controlling generation behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationOptions {
    pub creativity_level: Option<String>, // "conservative", "medium", "creative"
    pub include_metadata: Option<bool>,
    pub max_length: Option<usize>,
    pub temperature: Option<f32>,
}

/// Metadata about the generation process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationMetadata {
    pub tokens_used: usize,
    pub generation_time_ms: u64,
    pub style_detected: Option<DescriptionStyle>,
    pub model_used: String,
    pub timestamp: crate::DbTimestamp,
    pub debug_info: Option<GenerationDebugInfo>,
}

/// Debug information for generation troubleshooting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationDebugInfo {
    pub system_prompt: String,
    pub user_message: String,
    pub lorebook_context_included: bool,
    pub lorebook_entries_count: Option<usize>,
    pub query_text_used: Option<String>,
}

/// Result of field generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldGenerationResult {
    pub content: String,
    pub style_used: DescriptionStyle,
    pub metadata: GenerationMetadata,
}

/// Result of full character generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullCharacterResult {
    pub name: String,
    pub description: String,
    pub personality: Option<String>,
    pub scenario: Option<String>,
    pub first_mes: String,
    pub mes_example: Option<String>,
    pub system_prompt: Option<String>,
    pub depth_prompt: Option<String>,
    pub tags: Vec<String>,
    pub metadata: GenerationMetadata,
}

/// Result of enhancement operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancementResult {
    pub enhanced_content: String,
    pub changes_made: Vec<String>,
    pub metadata: GenerationMetadata,
}

/// Generation strategy enum for different types of operations
#[derive(Debug, Clone)]
pub enum GenerationStrategy {
    FieldSpecific(FieldGenerationRequest),
    FullCharacter(FullCharacterRequest),
    Enhancement(EnhancementRequest),
}

/// Tool call interface for ScribeAssistant mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CharacterGenerationToolCall {
    pub tool_name: String,
    pub parameters: crate::DbJson,
    pub request_id: Option<String>,
}

/// Response from tool call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CharacterGenerationToolResponse {
    pub success: bool,
    pub result: Option<crate::DbJson>,
    pub error: Option<String>,
    pub request_id: Option<String>,
}

// ============================================================================
// API Types matching character-editor's TypeScript interface
// These provide a unified API surface compatible with the character-editor frontend
// ============================================================================

/// Generation mode for character field operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GenerationMode {
    /// Create new content from scratch
    Create,
    /// Enhance existing content with improvements
    Enhance,
    /// Expand existing content with more details
    Expand,
    /// Rewrite existing content in a different style/tone
    Rewrite,
}

impl GenerationMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            GenerationMode::Create => "create",
            GenerationMode::Enhance => "enhance",
            GenerationMode::Expand => "expand",
            GenerationMode::Rewrite => "rewrite",
        }
    }
}

/// Unified generation request matching character-editor's API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiGenerationRequest {
    /// Name of the character field to generate (e.g., "description", "personality")
    pub field_name: String,
    /// Current field value (for enhance/expand/rewrite modes)
    pub field_value: Option<String>,
    /// Character context for generation
    pub character_context: Option<CharacterContext>,
    /// Generation mode (create, enhance, expand, rewrite)
    pub mode: GenerationMode,
    /// Description style preference
    pub style: Option<DescriptionStyle>,
    /// User's generation prompt/instructions
    pub user_prompt: Option<String>,
    /// Maximum tokens for generation
    pub max_tokens: Option<u32>,
    /// Temperature for generation (0.0-1.0)
    pub temperature: Option<f32>,
    /// Lorebook ID for context retrieval
    pub lorebook_id: Option<crate::db::DbId>,
}

/// Unified generation response matching character-editor's API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiGenerationResponse {
    /// Generated content
    pub content: String,
    /// Metadata about the generation
    pub metadata: ApiGenerationMetadata,
}

/// Streaming generation chunk matching character-editor's API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiGenerationChunk {
    /// Content chunk (empty when done=true)
    pub content: String,
    /// Whether this is the final chunk
    pub done: bool,
    /// Metadata (only present in final chunk when done=true)
    pub metadata: Option<ApiGenerationMetadata>,
}

/// Generation metadata matching character-editor's API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiGenerationMetadata {
    /// Model used for generation
    pub model: String,
    /// Total tokens used (input + output)
    pub tokens_used: usize,
    /// Cost in USD
    pub cost: f64,
    /// Generation time in milliseconds
    pub generation_time_ms: u64,
    /// Reason generation finished (e.g., "stop", "length")
    pub finish_reason: Option<String>,
    /// Detected or applied style
    pub style_detected: Option<DescriptionStyle>,
    /// System prompt used (for debugging)
    pub system_prompt: Option<String>,
    /// User prompt used (for debugging)
    pub user_prompt: Option<String>,
    /// Whether lorebook context was included
    pub lorebook_context_included: Option<bool>,
    /// Number of lorebook entries used
    pub lorebook_entries_count: Option<usize>,
    /// Query text used for lorebook search
    pub query_text_used: Option<String>,
}

impl From<&GenerationMetadata> for ApiGenerationMetadata {
    fn from(metadata: &GenerationMetadata) -> Self {
        ApiGenerationMetadata {
            model: metadata.model_used.clone(),
            tokens_used: metadata.tokens_used,
            cost: 0.0, // Will be calculated based on token pricing
            generation_time_ms: metadata.generation_time_ms,
            finish_reason: Some("stop".to_string()),
            style_detected: metadata.style_detected.clone(),
            system_prompt: metadata
                .debug_info
                .as_ref()
                .map(|d| d.system_prompt.clone()),
            user_prompt: metadata.debug_info.as_ref().map(|d| d.user_message.clone()),
            lorebook_context_included: metadata
                .debug_info
                .as_ref()
                .map(|d| d.lorebook_context_included),
            lorebook_entries_count: metadata
                .debug_info
                .as_ref()
                .and_then(|d| d.lorebook_entries_count),
            query_text_used: metadata
                .debug_info
                .as_ref()
                .and_then(|d| d.query_text_used.clone()),
        }
    }
}

impl ApiGenerationRequest {
    /// Convert API request to internal FieldGenerationRequest
    /// Maps from camelCase API format to internal snake_case format
    pub fn to_field_generation_request(&self) -> Result<FieldGenerationRequest, String> {
        // Parse field name string to CharacterField enum
        let field = match self.field_name.to_lowercase().as_str() {
            "description" => CharacterField::Description,
            "personality" => CharacterField::Personality,
            "first_mes" | "firstmes" | "firstmessage" => CharacterField::FirstMes,
            "scenario" => CharacterField::Scenario,
            "mes_example" | "mesexample" | "messageexample" => CharacterField::MesExample,
            "system_prompt" | "systemprompt" => CharacterField::SystemPrompt,
            "depth_prompt" | "depthprompt" => CharacterField::DepthPrompt,
            "tags" => CharacterField::Tags,
            "alternate_greeting" | "alternategreeting" => CharacterField::AlternateGreeting,
            "entry_content" | "entrycontent" => CharacterField::EntryContent,
            "entry_comment" | "entrycomment" => CharacterField::EntryComment,
            _ => return Err(format!("Unknown field name: {}", self.field_name)),
        };

        // Build user prompt based on mode and field value
        let user_prompt = match self.mode {
            GenerationMode::Create => {
                // For create mode, use the provided prompt or generate a default
                self.user_prompt.clone().unwrap_or_else(|| {
                    format!(
                        "Generate a {} for the character",
                        field.display_name().to_lowercase()
                    )
                })
            }
            GenerationMode::Enhance => {
                // For enhance mode, include the existing content
                if let Some(field_value) = &self.field_value {
                    self.user_prompt.clone().unwrap_or_else(|| {
                        format!(
                            "Enhance this {}: {}",
                            field.display_name().to_lowercase(),
                            field_value
                        )
                    })
                } else {
                    return Err(format!(
                        "field_value is required for {} mode",
                        self.mode.as_str()
                    ));
                }
            }
            GenerationMode::Expand => {
                // For expand mode, add more details to existing content
                if let Some(field_value) = &self.field_value {
                    self.user_prompt.clone().unwrap_or_else(|| {
                        format!(
                            "Expand this {} with more details: {}",
                            field.display_name().to_lowercase(),
                            field_value
                        )
                    })
                } else {
                    return Err(format!(
                        "field_value is required for {} mode",
                        self.mode.as_str()
                    ));
                }
            }
            GenerationMode::Rewrite => {
                // For rewrite mode, rewrite the content in a different style
                if let Some(field_value) = &self.field_value {
                    let style_note = if let Some(ref style) = self.style {
                        format!(" in {} style", style.name())
                    } else {
                        String::new()
                    };
                    self.user_prompt.clone().unwrap_or_else(|| {
                        format!(
                            "Rewrite this {}{}: {}",
                            field.display_name().to_lowercase(),
                            style_note,
                            field_value
                        )
                    })
                } else {
                    return Err(format!(
                        "field_value is required for {} mode",
                        self.mode.as_str()
                    ));
                }
            }
        };

        // Create generation options if any parameters are provided
        let generation_options = if self.max_tokens.is_some() || self.temperature.is_some() {
            Some(GenerationOptions {
                temperature: self.temperature.map(|t| t as f32),
                max_length: self.max_tokens.map(|t| t as usize),
                creativity_level: None,
                include_metadata: Some(true),
            })
        } else {
            None
        };

        Ok(FieldGenerationRequest {
            field,
            mode: self.mode.clone(),
            style: self.style.clone(),
            user_prompt,
            character_context: self.character_context.clone(),
            generation_options,
            lorebook_id: self.lorebook_id,
        })
    }
}

// ============================================================================
// Lorebook Generation API Types
// ============================================================================

/// Request for generating a single lorebook entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LorebookGenerationRequest {
    /// User's prompt/instructions for the lorebook entry
    pub prompt: String,
    /// Generation mode (create, enhance, expand, rewrite)
    pub mode: Option<GenerationMode>,
    /// Description style preference
    pub style: Option<DescriptionStyle>,
    /// Character context for generation
    pub character_context: Option<CharacterContext>,
    /// World context or existing lorebook entries to maintain consistency
    pub world_context: Option<String>,
    /// Optional existing lorebook ID to query for related entries
    pub lorebook_id: Option<crate::db::DbId>,
    /// Maximum tokens for generation
    pub max_tokens: Option<u32>,
    /// Temperature for generation (0.0-1.0)
    pub temperature: Option<f32>,
}

/// Request for generating multiple lorebook entries in batch
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchLorebookGenerationRequest {
    /// User's prompt/instructions for the batch generation
    pub prompt: String,
    /// Number of entries to generate
    pub count: usize,
    /// Generation mode (create, enhance, expand, rewrite)
    pub mode: Option<GenerationMode>,
    /// Description style preference
    pub style: Option<DescriptionStyle>,
    /// Character context for generation
    pub character_context: Option<CharacterContext>,
    /// World context or existing lorebook entries to maintain consistency
    pub world_context: Option<String>,
    /// Optional existing lorebook ID to query for related entries
    pub lorebook_id: Option<crate::db::DbId>,
    /// Maximum tokens for generation
    pub max_tokens: Option<u32>,
    /// Temperature for generation (0.0-1.0)
    pub temperature: Option<f32>,
}

/// Response for single lorebook entry generation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LorebookGenerationResponse {
    /// Generated entry name/title
    pub name: String,
    /// Generated entry content
    pub content: String,
    /// Generated entry keys
    pub keys: Vec<String>,
    /// Optional category
    pub category: Option<String>,
    /// Metadata about the generation
    pub metadata: ApiGenerationMetadata,
}

/// Response for batch lorebook entries generation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchLorebookGenerationResponse {
    /// Array of generated lorebook entries
    pub entries: Vec<LorebookGenerationResponse>,
    /// Metadata about the generation
    pub metadata: ApiGenerationMetadata,
}

// ============================================================================
// Scribe Assistant API Types
// ============================================================================

/// A single message in a conversation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantMessage {
    /// Role of the message sender ("user" or "assistant")
    pub role: String,
    /// Content of the message
    pub content: String,
}

/// Request for Scribe assistant chat
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScribeAssistantRequest {
    /// Current user message
    pub message: String,
    /// Conversation history (optional, for context)
    pub conversation_history: Option<Vec<AssistantMessage>>,
    /// Character context (optional, if asking about a specific character)
    pub character_context: Option<CharacterContext>,
    /// Maximum tokens for generation
    pub max_tokens: Option<u32>,
    /// Temperature for generation (0.0-1.0)
    pub temperature: Option<f32>,
}

/// Response from Scribe assistant
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScribeAssistantResponse {
    /// Assistant's response message
    pub message: String,
    /// Metadata about the generation
    pub metadata: ApiGenerationMetadata,
}
