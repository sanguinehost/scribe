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

// Helper function for parsing comma-separated lists
pub fn parse_comma_separated_list(s: &str) -> Result<Vec<String>, String> {
    Ok(s.split(',').map(|item| item.trim().to_string()).collect())
}