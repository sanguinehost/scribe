// cli/src/lib.rs

// Declare modules
pub mod client;
pub mod error;
pub mod handlers;
pub mod io;
pub mod chat; // Ensure chat module is declared if it exists and is needed by handlers/main
pub mod test_helpers; // Added test_helpers module

// Re-export items needed by main.rs and tests
pub use clap::{Parser, Subcommand, Args as ClapArgs};
pub use uuid::Uuid;
pub use error::CliError; // Ensure CliError is available for MenuResult

// --- Menu Navigation Enums and Types ---

/// Enum to manage the current state of the interactive menu in main.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)] // Added PartialEq, Eq for potential future use
pub enum MenuState {
    MainMenu,
    UserManagement,
    CharacterManagement,
    ChatManagement,
    AccountSettings,
    PersonaManagement,
    LorebookManagement,
}

/// Enum to manage navigation results from menu handlers in main.rs
#[derive(Debug, Clone, PartialEq, Eq)] // Added PartialEq, Eq for potential future use
pub enum MenuNavigation {
    GoTo(MenuState),
    ReturnToMainMenu,
    Logout,
    Quit,
}

/// Helper type alias for results from menu handling functions in main.rs
pub type MenuResult = Result<MenuNavigation, CliError>;


// --- Clap Argument Structs ---

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct CliArgs {
    #[clap(subcommand)]
    pub command: Option<Commands>,

    /// Base URL of the Scribe backend server
    #[arg(
        short,
        long,
        global = true,
        env = "SCRIBE_BASE_URL",
        default_value = "https://127.0.0.1:8080"
    )]
    pub base_url: url::Url, // Made field public for main.rs
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Manage characters
    Character(CharacterArgs),
    /// Manage chat sessions
    Chat(ChatArgs),
    /// Manage user personas
    Persona(PersonaArgs),
}

#[derive(ClapArgs, Debug)]
pub struct CharacterArgs {
    #[clap(subcommand)]
    pub command: CharacterCommand,
}

#[derive(Subcommand, Debug)]
pub enum CharacterCommand {
    /// Create a new character manually
    Create(CharacterCreateArgs),
    /// Edit an existing character
    Edit(CharacterEditArgs),
}

#[derive(ClapArgs, Debug, Default, Clone)] // Added Default and Clone for test helpers
pub struct CharacterCreateArgs {
    /// Character's name
    #[arg(long, required_unless_present("interactive"))]
    pub name: Option<String>,
    /// Character's description
    #[arg(long, required_unless_present("interactive"))]
    pub description: Option<String>,
    /// Character's first message
    #[arg(long, name = "first-mes", required_unless_present("interactive"))]
    pub first_mes: Option<String>,
    /// Character's personality
    #[arg(long)]
    pub personality: Option<String>,
    /// Character's scenario
    #[arg(long)]
    pub scenario: Option<String>,
    /// Character's system prompt
    #[arg(long, name = "system-prompt")]
    pub system_prompt: Option<String>,
    /// Character's creator notes
    #[arg(long, name = "creator-notes")]
    pub creator_notes: Option<String>,
    /// Comma-separated tags (e.g., "tag1,tag2,tag3")
    #[arg(long, value_parser = parse_comma_separated_list)]
    pub tags: Option<Vec<String>>,
    /// Comma-separated alternate greetings
    #[arg(long, name = "alternate-greetings", value_parser = parse_comma_separated_list)]
    pub alternate_greetings: Option<Vec<String>>,
    #[arg(long)]
    pub creator: Option<String>,
    #[arg(long, name="character-version")]
    pub character_version: Option<String>,
    
    /// Run in interactive wizard mode (prompts for all fields)
    #[arg(long, short, default_value_t = false)]
    pub interactive: bool,
}

#[derive(ClapArgs, Debug, Default, Clone)] // Added Default and Clone
pub struct CharacterEditArgs {
    /// The UUID of the character to edit
    #[arg(long, required_unless_present("interactive"))]
    pub id: Option<Uuid>,
    /// New name for the character
    #[arg(long)]
    pub name: Option<String>,
    /// New description for the character
    #[arg(long)]
    pub description: Option<String>,
    /// New first message for the character
    #[arg(long, name = "first-mes")]
    pub first_mes: Option<String>,
    #[arg(long)]
    pub personality: Option<String>,
    #[arg(long)]
    pub scenario: Option<String>,
    #[arg(long, name = "system-prompt")]
    pub system_prompt: Option<String>,
    
    /// Run in interactive wizard mode (prompts for ID and then fields to edit)
    #[arg(long, short, default_value_t = false)]
    pub interactive: bool,
}

#[derive(ClapArgs, Debug)]
pub struct ChatArgs {
    #[clap(subcommand)]
    pub command: ChatCommand,
}

#[derive(Subcommand, Debug)]
pub enum ChatCommand {
    /// Override character fields for a specific chat session
    EditCharacter(ChatEditCharacterArgs),
}

#[derive(ClapArgs, Debug, Default, Clone)] // Added Default and Clone
pub struct ChatEditCharacterArgs {
    /// The UUID of the chat session
    #[arg(long, name = "session-id", required_unless_present("interactive"))]
    pub session_id: Option<Uuid>,
    /// The name of the character field to override (e.g., "description", "personality")
    #[arg(long, required_unless_present("interactive"))]
    pub field: Option<String>,
    /// The new value for the specified field in this chat
    #[arg(long, required_unless_present("interactive"))]
    pub value: Option<String>,

    /// Run in interactive wizard mode
    #[arg(long, short, default_value_t = false)]
    pub interactive: bool,
}

// --- User Persona Commands ---

#[derive(ClapArgs, Debug)]
pub struct PersonaArgs {
    #[clap(subcommand)]
    pub command: PersonaCommand,
}

#[derive(Subcommand, Debug)]
pub enum PersonaCommand {
    /// Create a new user persona
    Create(PersonaCreateArgs),
    /// List all user personas
    List,
    /// Get details of a specific user persona
    Get(PersonaGetArgs),
    /// Update an existing user persona
    Update(PersonaUpdateArgs),
    /// Delete a user persona
    Delete(PersonaDeleteArgs),
    /// Set a user persona as the default for new chats
    SetDefault(PersonaSetDefaultArgs),
    /// Clear the default user persona
    ClearDefault(PersonaClearDefaultArgs),
}

#[derive(ClapArgs, Debug, Default, Clone)]
pub struct PersonaCreateArgs {
    /// Persona's name (required)
    #[arg(long)]
    pub name: String,
    /// Persona's description (required)
    #[arg(long)]
    pub description: String,
    /// Persona's specification (e.g., "user_persona_v1")
    #[arg(long)]
    pub spec: Option<String>,
    /// Version of the persona specification
    #[arg(long, name = "spec-version")]
    pub spec_version: Option<String>,
    /// Persona's personality
    #[arg(long)]
    pub personality: Option<String>,
    /// Persona's scenario
    #[arg(long)]
    pub scenario: Option<String>,
    /// Persona's first message
    #[arg(long, name = "first-mes")]
    pub first_mes: Option<String>,
    /// Persona's message example
    #[arg(long, name = "mes-example")]
    pub mes_example: Option<String>,
    /// Persona's system prompt
    #[arg(long, name = "system-prompt")]
    pub system_prompt: Option<String>,
    /// Persona's post history instructions
    #[arg(long, name = "post-history-instructions")]
    pub post_history_instructions: Option<String>,
    /// Comma-separated tags (e.g., "tag1,tag2,tag3")
    #[arg(long, value_parser = parse_comma_separated_list)]
    pub tags: Option<Vec<String>>,
    /// Avatar URL or identifier for the persona
    #[arg(long)]
    pub avatar: Option<String>,
    // No interactive flag for persona creation for now, assuming direct args.
    // If an interactive wizard is desired later, it can be added.
}

#[derive(ClapArgs, Debug, Default, Clone)]
pub struct PersonaUpdateArgs {
    /// The UUID of the persona to update (required)
    #[arg(long)]
    pub id: Uuid,
    /// New name for the persona
    #[arg(long)]
    pub name: Option<String>,
    /// New description for the persona
    #[arg(long)]
    pub description: Option<String>,
    /// New specification for the persona
    #[arg(long)]
    pub spec: Option<String>,
    /// New version of the persona specification
    #[arg(long, name = "spec-version")]
    pub spec_version: Option<String>,
    /// New personality for the persona
    #[arg(long)]
    pub personality: Option<String>,
    /// New scenario for the persona
    #[arg(long)]
    pub scenario: Option<String>,
    /// New first message for the persona
    #[arg(long, name = "first-mes")]
    pub first_mes: Option<String>,
    /// New message example for the persona
    #[arg(long, name = "mes-example")]
    pub mes_example: Option<String>,
    /// New system prompt for the persona
    #[arg(long, name = "system-prompt")]
    pub system_prompt: Option<String>,
    /// New post history instructions for the persona
    #[arg(long, name = "post-history-instructions")]
    pub post_history_instructions: Option<String>,
    /// New comma-separated tags (e.g., "tag1,tag2,tag3")
    #[arg(long, value_parser = parse_comma_separated_list)]
    pub tags: Option<Vec<String>>,
    /// New avatar URL or identifier for the persona
    #[arg(long)]
    pub avatar: Option<String>,
}

#[derive(ClapArgs, Debug)]
pub struct PersonaGetArgs {
    /// The UUID of the persona to retrieve
    #[arg()] // Positional argument
    pub id: Uuid,
}

#[derive(ClapArgs, Debug)]
pub struct PersonaDeleteArgs {
    /// The UUID of the persona to delete
    #[arg()] // Positional argument
    pub id: Uuid,
}

#[derive(ClapArgs, Debug, Default, Clone)]
pub struct PersonaSetDefaultArgs {
    /// The UUID of the persona to set as default. If not provided, interactive selection will be used.
    #[arg(long)]
    pub id: Option<Uuid>,
}

#[derive(ClapArgs, Debug, Default, Clone)]
pub struct PersonaClearDefaultArgs {
    // No arguments needed for clearing the default
}


// Helper function for parsing comma-separated lists
pub fn parse_comma_separated_list(s: &str) -> Result<Vec<String>, String> {
    Ok(s.split(',').map(|item| item.trim().to_string()).collect())
}