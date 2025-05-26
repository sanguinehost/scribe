// backend/src/services/chat/mod.rs

pub mod types;
pub mod session_management;
pub mod message_handling;
pub mod generation;
pub mod settings;
pub mod overrides;

// Re-export key functions/types if desired, or allow users to import from submodules directly.
// Example:
// pub use types::{GenerationDataWithUnsavedUserMessage, ScribeSseEvent};
// pub use session_management::{create_session_and_maybe_first_message, list_sessions_for_user, get_chat_session_by_id};
// pub use message_handling::{get_messages_for_session, save_message};
// pub use generation::{get_session_data_for_generation, stream_ai_response_and_save_message};
// pub use settings::{get_session_settings, update_session_settings};
// pub use overrides::{set_character_override};