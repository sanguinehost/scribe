use crate::schema::chat_character_overrides;
use crate::DbDateTime;
use chrono::Utc;
use diesel::{AsChangeset, Identifiable, Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use std::fmt;
use crate::DbUuid as Uuid;

#[derive(Queryable, Selectable, Identifiable, AsChangeset, Serialize, Deserialize)]
#[diesel(table_name = chat_character_overrides)]
#[diesel(primary_key(id))]
pub struct ChatCharacterOverride {
    pub id: crate::DbUuid,
    pub chat_session_id: crate::DbUuid,
    pub original_character_id: crate::DbUuid,
    #[diesel(column_name = field_name)]
    pub field_name: String,
    pub overridden_value: Vec<u8>,
    pub overridden_value_nonce: Vec<u8>,
    pub created_at: DbDateTime,
    pub updated_at: DbDateTime,
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
#[cfg_attr(feature = "postgres-backend", diesel(check_for_backend(diesel::pg::Pg)))]
#[cfg_attr(feature = "sqlite-backend", diesel(check_for_backend(diesel::sqlite::Sqlite)))]
pub struct NewChatCharacterOverride {
    pub id: crate::DbUuid,
    pub chat_session_id: crate::DbUuid,
    pub original_character_id: crate::DbUuid,
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
