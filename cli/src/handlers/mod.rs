// Declare modules
pub mod admin;
pub mod auth;
pub mod characters;
pub mod chat;
pub mod chat_config; // Add the chat configuration module
pub mod chat_management; // Add the chat management module
pub mod chat_overrides; // Add the chat overrides module
pub mod default_settings;
pub mod health;
pub mod model;
pub mod lorebooks; // Added lorebooks module
pub mod start_chat;
pub mod streaming; // Add the default settings module
pub mod user_personas;

// For tests
// pub mod test_helpers; // Moved to lib.rs

// Re-export public API
pub use self::admin::{
    handle_change_user_role_action, handle_list_all_users_action, handle_lock_unlock_user_action,
    handle_view_user_details_action,
};
pub use self::auth::{handle_login_action, handle_registration_action};
pub use self::characters::{handle_upload_character_action, handle_view_character_details_action};
pub use self::chat::{
    handle_list_chat_sessions_action, handle_resume_chat_session_action,
    handle_view_chat_history_action,
};
pub use self::chat_config::handle_chat_config_action;
pub use self::chat_management::handle_delete_chat_session_action;
pub use self::chat_overrides::{
    handle_chat_edit_character_oneliner, handle_chat_edit_character_wizard,
};
pub use self::default_settings::handle_default_settings_action;
pub use self::health::handle_health_check_action;
pub use self::model::handle_model_settings_action;
pub use self::start_chat::handle_start_chat_action;
pub use self::lorebooks::handle_lorebook_management_menu; // Added lorebook handler
pub use self::user_personas::{
    handle_persona_create_action, handle_persona_list_action, handle_persona_get_action,
    handle_persona_update_action, handle_persona_delete_action,
};
