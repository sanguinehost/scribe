// backend/src/models_sqlite/mod.rs
// SQLite-specific model definitions

pub mod character_assets;
pub mod character_card;
pub mod chats;
pub mod user_assets;
pub mod users;

// Re-export all public types from each module
pub use character_assets::{CharacterAsset, NewCharacterAsset};
pub use character_card::{
    Asset, CharacterCardDataV3, CharacterCardV3, Decorator, DecoratorPosition, DecoratorRole,
    DecoratorUiPromptType, LorebookEntryPosition, NewCharacter, NewCharacterAsset as CardNewCharacterAsset,
    SillyTavernCharacterBook, StandaloneLorebook,
};
pub use chats::*;
pub use user_assets::{NewUserAsset, UserAsset};
pub use users::*;
