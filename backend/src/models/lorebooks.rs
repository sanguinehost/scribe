use crate::models::chats::Chat;
use crate::models::users::User;
use crate::schema::{chat_session_lorebooks, lorebook_entries, lorebooks};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// --------------------
// --- Lorebook Model ---
// --------------------

#[derive(
    Queryable, Selectable, Identifiable, Associations, Serialize, Deserialize, Debug, Clone, PartialEq, Default,
)]
#[diesel(table_name = lorebooks)]
#[diesel(belongs_to(User))]
pub struct Lorebook {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub source_format: String,
    pub is_public: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Insertable, Debug, Clone)]
#[diesel(table_name = lorebooks)]
pub struct NewLorebook {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub source_format: String,
    pub is_public: bool,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

// -------------------------
// --- LorebookEntry Model ---
// -------------------------

#[derive(
    Queryable, Selectable, Identifiable, Associations, Serialize, Deserialize, Debug, Clone, PartialEq, AsChangeset,
)]
#[diesel(table_name = lorebook_entries, treat_none_as_null = true)]
#[diesel(belongs_to(Lorebook))]
#[diesel(belongs_to(User))]
pub struct LorebookEntry {
    pub id: Uuid,
    pub lorebook_id: Uuid,
    pub user_id: Uuid,
    pub original_sillytavern_uid: Option<i32>,
    pub entry_title_ciphertext: Vec<u8>,
    pub entry_title_nonce: Vec<u8>,
    pub keys_text_ciphertext: Vec<u8>,
    pub keys_text_nonce: Vec<u8>,
    pub content_ciphertext: Vec<u8>,
    pub content_nonce: Vec<u8>,
    pub comment_ciphertext: Option<Vec<u8>>,
    pub comment_nonce: Option<Vec<u8>>,
    pub is_enabled: bool,
    pub is_constant: bool,
    pub insertion_order: i32,
    pub placement_hint: Option<String>,
    pub sillytavern_metadata_ciphertext: Option<Vec<u8>>,
    pub sillytavern_metadata_nonce: Option<Vec<u8>>,
    pub name: Option<String>, // As per schema.rs, might be deprecated in favor of encrypted title
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Insertable, Debug, Clone)]
#[diesel(table_name = lorebook_entries)]
pub struct NewLorebookEntry {
    pub id: Uuid,
    pub lorebook_id: Uuid,
    pub user_id: Uuid,
    pub original_sillytavern_uid: Option<i32>,
    pub entry_title_ciphertext: Vec<u8>,
    pub entry_title_nonce: Vec<u8>,
    pub keys_text_ciphertext: Vec<u8>,
    pub keys_text_nonce: Vec<u8>,
    pub content_ciphertext: Vec<u8>,
    pub content_nonce: Vec<u8>,
    pub comment_ciphertext: Option<Vec<u8>>,
    pub comment_nonce: Option<Vec<u8>>,
    pub is_enabled: bool,
    pub is_constant: bool,
    pub insertion_order: i32,
    pub placement_hint: Option<String>,
    pub sillytavern_metadata_ciphertext: Option<Vec<u8>>,
    pub sillytavern_metadata_nonce: Option<Vec<u8>>,
    pub name: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

// --------------------------------
// --- ChatSessionLorebook Model ---
// --------------------------------

#[derive(
    Queryable,
    Selectable,
    Identifiable,
    Associations,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
)]
#[diesel(table_name = chat_session_lorebooks)]
#[diesel(primary_key(chat_session_id, lorebook_id))]
#[diesel(belongs_to(Chat, foreign_key = chat_session_id))]
#[diesel(belongs_to(Lorebook, foreign_key = lorebook_id))]
#[diesel(belongs_to(User, foreign_key = user_id))]
pub struct ChatSessionLorebook {
    pub chat_session_id: Uuid,
    pub lorebook_id: Uuid,
    pub user_id: Uuid,
}

#[derive(Insertable, Debug, Clone)]
#[diesel(table_name = chat_session_lorebooks)]
pub struct NewChatSessionLorebook {
    pub chat_session_id: Uuid,
    pub lorebook_id: Uuid,
    pub user_id: Uuid,
}