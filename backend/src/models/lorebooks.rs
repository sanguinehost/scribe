use crate::models::characters::Character;
use crate::models::chats::Chat;
use crate::models::users::User;
use crate::schema::{character_lorebooks, chat_session_lorebooks, lorebook_entries, lorebooks};
use chrono::{DateTime, Utc};
use diesel::{Queryable, Insertable, Identifiable, AsChangeset, Selectable, Associations, PgConnection, QueryResult, QueryDsl, ExpressionMethods, RunQueryDsl, JoinOnDsl};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// --------------------
// --- Lorebook Model ---
// --------------------

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
    Eq,
    Default,
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
    Queryable,
    Selectable,
    Identifiable,
    Associations,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    AsChangeset,
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
    Eq,
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
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ChatSessionLorebook {
    /// Retrieves a list of active lorebook IDs for a given chat session.
    ///
    /// # Arguments
    ///
    /// * `conn` - A mutable reference to the database connection.
    /// * `session_id_param` - The UUID of the chat session.
    ///
    /// # Returns
    ///
    /// A `QueryResult` containing an `Option<Vec<Uuid>>`.
    /// Returns `Ok(Some(Vec<Uuid>))` if lorebooks are found.
    /// Returns `Ok(None)` if no lorebooks are found for the session.
    /// Returns `Err` if there's a database query error.
    ///
    /// # Errors
    /// Returns `QueryResult` error if the database query fails
    pub fn get_active_lorebook_ids_for_session(
        conn: &mut PgConnection,
        session_id_param: Uuid,
    ) -> QueryResult<Option<Vec<Uuid>>> {
        use crate::schema::chat_session_lorebooks::dsl::{chat_session_id, chat_session_lorebooks, lorebook_id};

        let ids = chat_session_lorebooks
            .filter(chat_session_id.eq(session_id_param))
            .select(lorebook_id)
            .load::<Uuid>(conn)?;

        Ok(if ids.is_empty() { None } else { Some(ids) })
    }

    /// Retrieves comprehensive list of active lorebook IDs for a given chat session.
    /// This includes:
    /// 1. Lorebooks explicitly linked to the chat session (owned by the user)
    /// 2. Lorebooks linked to the character being used in this session (owned by the user)
    /// 3. TODO: Global/public lorebooks (if applicable)
    ///
    /// SECURITY: Only returns lorebooks that belong to the specified user to prevent
    /// cross-user access vulnerabilities.
    ///
    /// # Arguments
    ///
    /// * `conn` - A mutable reference to the database connection.
    /// * `session_id_param` - The UUID of the chat session.
    /// * `character_id_param` - The UUID of the character being used in this session.
    /// * `user_id_param` - The UUID of the user (only lorebooks owned by this user will be returned).
    ///
    /// # Returns
    ///
    /// A `QueryResult` containing an `Option<Vec<Uuid>>`.
    /// Returns `Ok(Some(Vec<Uuid>))` if lorebooks are found.
    /// Returns `Ok(None)` if no lorebooks are found.
    /// Returns `Err` if there's a database query error.
    ///
    /// # Errors
    /// Returns `QueryResult` error if the database query fails
    pub fn get_comprehensive_active_lorebook_ids(
        conn: &mut PgConnection,
        session_id_param: Uuid,
        character_id_param: Uuid,
        user_id_param: Uuid,
    ) -> QueryResult<Option<Vec<Uuid>>> {
        use crate::schema::{
            chat_session_lorebooks::dsl::{
                chat_session_id, 
                chat_session_lorebooks, 
                lorebook_id as session_lorebook_id
            },
            character_lorebooks::dsl::{
                character_id, 
                character_lorebooks, 
                lorebook_id as character_lorebook_id
            },
            lorebooks::dsl::{
                lorebooks,
                id as lorebook_table_id,
                user_id as lorebook_user_id
            },
        };

        // Get session-linked lorebook IDs that belong to the user
        let session_lorebook_ids = chat_session_lorebooks
            .inner_join(lorebooks.on(session_lorebook_id.eq(lorebook_table_id)))
            .filter(chat_session_id.eq(session_id_param))
            .filter(lorebook_user_id.eq(user_id_param))
            .select(session_lorebook_id)
            .load::<Uuid>(conn)?;

        // Get character-linked lorebook IDs that belong to the user
        let character_lorebook_ids = character_lorebooks
            .inner_join(lorebooks.on(character_lorebook_id.eq(lorebook_table_id)))
            .filter(character_id.eq(character_id_param))
            .filter(lorebook_user_id.eq(user_id_param))
            .select(character_lorebook_id)
            .load::<Uuid>(conn)?;

        // Combine and deduplicate
        let mut combined_ids = session_lorebook_ids;
        for char_lorebook_id in character_lorebook_ids {
            if !combined_ids.contains(&char_lorebook_id) {
                combined_ids.push(char_lorebook_id);
            }
        }

        // TODO: Add globally activated lorebooks when the schema is updated
        // This will require adding an `is_always_active` or `is_global` field to the lorebooks table
        // For now, we only support character-linked and session-linked lorebooks that belong to the user

        Ok(if combined_ids.is_empty() { None } else { Some(combined_ids) })
    }
}

#[derive(Insertable, Debug, Clone)]
#[diesel(table_name = chat_session_lorebooks)]
pub struct NewChatSessionLorebook {
    pub chat_session_id: Uuid,
    pub lorebook_id: Uuid,
    pub user_id: Uuid,
    // Timestamps are typically optional for New structs, allowing DB defaults
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

// --------------------------------
// --- CharacterLorebook Model ---
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
    Eq,
)]
#[diesel(table_name = character_lorebooks)]
#[diesel(primary_key(character_id, lorebook_id))]
#[diesel(belongs_to(Character, foreign_key = character_id))]
#[diesel(belongs_to(Lorebook, foreign_key = lorebook_id))]
#[diesel(belongs_to(User, foreign_key = user_id))]
pub struct CharacterLorebook {
    pub character_id: Uuid,
    pub lorebook_id: Uuid,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Insertable, Debug, Clone)]
#[diesel(table_name = character_lorebooks)]
pub struct NewCharacterLorebook {
    pub character_id: Uuid,
    pub lorebook_id: Uuid,
    pub user_id: Uuid,
    // Timestamps are typically optional for New structs, allowing DB defaults
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}
