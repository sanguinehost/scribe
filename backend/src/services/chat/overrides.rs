use diesel::{prelude::*, result::Error as DieselError};
use tracing::{error, instrument};
use uuid::Uuid;

use crate::{
    crypto::encrypt_gcm, // Corrected encryption service import
    errors::AppError,
    models::chat_override::{
        CharacterOverrideDto, ChatCharacterOverride, NewChatCharacterOverride,
    },
    schema::{chat_character_overrides, chat_sessions},
    state::DbPool, // Corrected DbPool import
};
use secrecy::{ExposeSecret, SecretBox}; // Added SecretBox import

// This function will be in a sibling module
/// Sets or updates a character override for a specific chat session.
#[instrument(skip(pool, payload, user_dek_secret_box), err)]
pub async fn set_character_override(
    pool: &DbPool,
    user_id: Uuid,
    session_id: Uuid,
    payload: CharacterOverrideDto,
    user_dek_secret_box: Option<&SecretBox<Vec<u8>>>, // Changed to Option<&SecretBox>
) -> Result<ChatCharacterOverride, AppError> {
    let conn = pool.get().await?;

    // Clone payload parts needed for the interact closure
    let field_name_clone = payload.field_name.clone();
    let value_clone = payload.value.clone();

    // Manually clone the inner secret data to create an owned SecretBox for the closure
    let owned_user_dek_opt: Option<SecretBox<Vec<u8>>> =
        user_dek_secret_box.map(|sb_ref| SecretBox::new(Box::new(sb_ref.expose_secret().clone())));

    conn.interact(move |conn| {
        conn.transaction(|transaction_conn| {
            // 1. Verify chat session ownership and get original character_id
            let (chat_owner_id, original_character_id_from_session) = chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .select((chat_sessions::user_id, chat_sessions::character_id))
                .first::<(Uuid, Uuid)>(transaction_conn)
                .map_err(|e| match e {
                    DieselError::NotFound => {
                        AppError::NotFound(format!("Chat session {session_id} not found."))
                    }
                    _ => AppError::DatabaseQueryError(e.to_string()),
                })?;

            if chat_owner_id != user_id {
                error!(
                    "User {} attempted to set override for session {} owned by {}",
                    user_id, session_id, chat_owner_id
                );
                return Err(AppError::Forbidden);
            }

            // 2. Encrypt the value
            let (encrypted_value, nonce) = if let Some(dek) = &owned_user_dek_opt {
                // dek is &SecretBox<Vec<u8>>
                encrypt_gcm(value_clone.as_bytes(), dek).map_err(|e| {
                    // Use direct call
                    error!("Failed to encrypt override value: {}", e);
                    AppError::EncryptionError("Failed to encrypt override value".to_string())
                })?
            } else {
                // This case should ideally be prevented if overrides require encryption.
                // For now, let's assume if no DEK, we store plaintext (though this is not ideal for sensitive data)
                // Or, more correctly, return an error if DEK is expected but not provided.
                // For this implementation, we'll require DEK for overrides.
                error!("User DEK not provided, cannot encrypt override value.");
                return Err(AppError::BadRequest(
                    "User DEK is required to set character overrides.".to_string(),
                ));
            };

            // 3. Perform an upsert (insert or update on conflict)
            let new_override = NewChatCharacterOverride {
                id: Uuid::new_v4(), // Generate a new ID for insert, conflict target will handle existing
                chat_session_id: session_id,
                original_character_id: original_character_id_from_session,
                field_name: field_name_clone,
                overridden_value: encrypted_value.clone(), // Clone for insert
                overridden_value_nonce: nonce.clone(),     // Clone for insert
            };

            // Upsert logic: Insert, and on conflict on (chat_session_id, field_name), update the value and nonce.
            // Note: Diesel's `on_conflict` requires the columns in the conflict target to be part of the insert.
            // The `id` will be different for new inserts vs updates if we rely on a simple update.
            // A common pattern is to try an update first, if 0 rows affected, then insert.
            // Or, use a raw query for complex upserts if Diesel's DSL is limiting.
            // For simplicity here, we'll use `insert_into` with `on_conflict` and `do_update`.
            // This assumes a unique constraint exists on (chat_session_id, field_name).
            // If not, this will always insert. A migration would be needed for the unique constraint.
            // Let's assume the constraint `chat_character_overrides_session_id_field_name_key` exists.

            let result = diesel::insert_into(chat_character_overrides::table)
                .values(&new_override)
                .on_conflict((
                    chat_character_overrides::chat_session_id,
                    chat_character_overrides::field_name,
                ))
                .do_update()
                .set((
                    chat_character_overrides::overridden_value.eq(encrypted_value),
                    chat_character_overrides::overridden_value_nonce.eq(nonce),
                    chat_character_overrides::updated_at.eq(chrono::Utc::now()), // Explicitly set updated_at
                ))
                .returning(ChatCharacterOverride::as_select())
                .get_result::<ChatCharacterOverride>(transaction_conn)
                .map_err(|e| {
                    error!("Failed to upsert chat character override: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;

            Ok(result)
        })
    })
    .await?
}
