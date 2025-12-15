// Backend-specific model modules
#[cfg(feature = "postgres-backend")]
#[path = "../models_pg"]
mod backend_models {
    pub mod character_assets;
    pub mod character_card;
    pub mod chats;
    pub mod user_assets;
    pub mod users;
}

#[cfg(feature = "sqlite-backend")]
#[path = "../models_sqlite"]
mod backend_models {
    pub mod character_assets;
    pub mod character_card;
    pub mod chats;
    pub mod user_assets;
    pub mod users;
}

// Unified model modules (backend-agnostic)
pub mod agent_context_analysis;
// DEPRECATED: array_types module replaced by db::DbStringArray
// pub mod array_types;
pub mod auth;
pub mod character_dto;
pub mod characters;
pub mod chat_override;
pub mod chronicle;
pub mod chronicle_event;
#[cfg(feature = "payment")]
pub mod credit;
pub mod documents;
pub mod email_verification;
pub mod game_state;
pub mod lorebook_dtos;
pub mod lorebooks;
#[cfg(feature = "payment")]
pub mod payment;
pub mod sql_types;
pub mod template_preferences;
pub mod usage;
pub mod user_personas;
pub mod user_settings;

// Re-export backend-specific modules for qualified imports (e.g., models::users::User)
pub use backend_models::{character_assets, character_card, chats, user_assets, users};

// Re-export backend-specific types for convenience (e.g., models::User)
pub use backend_models::character_assets::{CharacterAsset, NewCharacterAsset};
pub use backend_models::character_card::*;
pub use backend_models::chats::*;
pub use backend_models::user_assets::{NewUserAsset, UserAsset};
pub use backend_models::users::*;

// Re-export unified models
pub use agent_context_analysis::*;
// Type alias for backwards compatibility - OptionalStringArray is now DbStringArray
pub use crate::db::DbStringArray as OptionalStringArray;
pub use auth::*;
pub use character_dto::*;
pub use characters::*;
pub use chat_override::*;
pub use chronicle::*;
pub use chronicle_event::*;
#[cfg(feature = "payment")]
pub use credit::*;
pub use documents::*;
pub use email_verification::*;
pub use lorebook_dtos::*;
pub use lorebooks::*;
#[cfg(feature = "payment")]
pub use payment::*;
pub use template_preferences::*;
pub use usage::*;
pub use user_personas::*;
pub use user_settings::*;
