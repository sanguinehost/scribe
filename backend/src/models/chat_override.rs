use crate::schema::chat_character_overrides;
use chrono::{DateTime, Utc};
use diesel::{AsChangeset, Identifiable, Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::fmt;

#[derive(Queryable, Selectable, Identifiable, AsChangeset, Serialize, Deserialize)]
#[diesel(table_name = chat_character_overrides)]
#[diesel(primary_key(id))]
pub struct ChatCharacterOverride {
    pub id: Uuid,
    pub chat_session_id: Uuid,
    pub original_character_id: Uuid,
    #[diesel(column_name = field_name)]
    pub field_name: String,
    pub overridden_value: Vec<u8>,
    pub overridden_value_nonce: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Custom Debug implementation to redact sensitive fields
impl fmt::Debug for ChatCharacterOverride {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChatCharacterOverride")
            .field("id", &self.id)
            .field("chat_session_id", &self.chat_session_id)
            .field("original_character_id", &self.original_character_id)
            .field("field_name", &self.field_name)
            .field("overridden_value", &"[REDACTED]")
            .field("overridden_value_nonce", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Insertable, Serialize, Deserialize, Debug)]
#[diesel(table_name = chat_character_overrides)]
pub struct NewChatCharacterOverride {
    pub id: Uuid,
    pub chat_session_id: Uuid,
    pub original_character_id: Uuid,
    pub field_name: String,
    pub overridden_value: Vec<u8>,
    pub overridden_value_nonce: Vec<u8>,
    // created_at and updated_at will be set by the database
}

#[derive(AsChangeset, Debug)]
#[diesel(table_name = chat_character_overrides)]
pub struct UpdateChatCharacterOverride<'a> {
    pub overridden_value: Option<&'a [u8]>,
    pub overridden_value_nonce: Option<&'a [u8]>,
    // updated_at will be set by the database trigger
}

// DTO for creating/updating an override via API
#[derive(Serialize, Deserialize, Debug, validator::Validate, Clone)]
pub struct CharacterOverrideDto {
    #[validate(length(min = 1, max = 255))]
    pub field_name: String,
    #[validate(length(min = 1))] // Assuming value shouldn't be empty, adjust if needed
    pub value: String, // This will be encrypted before storing as Vec<u8>
} 