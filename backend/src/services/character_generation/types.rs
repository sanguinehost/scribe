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
            DescriptionStyle::Worldbuilding => "Rich world context with character as part of larger narrative universe",
            DescriptionStyle::System => "Behavioral rules and interaction guidelines for AI roleplay",
            DescriptionStyle::Auto => "Automatically detect the best style based on context",
        }
    }
}

/// Request for generating a specific character field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldGenerationRequest {
    pub field: CharacterField,
    pub style: Option<DescriptionStyle>,
    pub user_prompt: String,
    pub character_context: Option<CharacterContext>,
    pub generation_options: Option<GenerationOptions>,
    pub lorebook_id: Option<Uuid>, // Optional lorebook to query for relevant context
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
    pub tone: Option<String>, // "casual", "formal", "poetic", etc.
    pub length: Option<String>, // "brief", "detailed", "extensive"
    pub focus: Option<String>, // "appearance", "personality", "background", etc.
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
    pub timestamp: chrono::DateTime<chrono::Utc>,
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
    pub parameters: serde_json::Value,
    pub request_id: Option<String>,
}

/// Response from tool call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CharacterGenerationToolResponse {
    pub success: bool,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
    pub request_id: Option<String>,
}