// Declare modules
pub mod admin;
pub mod auth;
pub mod health;
pub mod characters;
pub mod chat;
pub mod model;
pub mod start_chat;
pub mod streaming;
pub mod chat_config; // Add the chat configuration module

// For tests
#[cfg(test)]
pub mod test_helpers;

// Re-export public API
pub use self::admin::{
    handle_list_all_users_action,
    handle_view_user_details_action,
    handle_change_user_role_action,
    handle_lock_unlock_user_action,
};
pub use self::auth::{handle_login_action, handle_registration_action};
pub use self::health::handle_health_check_action;
pub use self::characters::{handle_upload_character_action, handle_view_character_details_action, select_character};
pub use self::chat::{handle_list_chat_sessions_action, handle_view_chat_history_action, handle_resume_chat_session_action};
pub use self::model::handle_model_settings_action;
pub use self::start_chat::handle_start_chat_action;
pub use self::streaming::handle_stream_test_action;
pub use self::chat_config::handle_chat_config_action;