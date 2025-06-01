use std::sync::Arc;

use chrono::Utc;
use diesel::{ExpressionMethods, RunQueryDsl, SelectableHelper};
use uuid::Uuid;

use crate::PgPool;
use crate::auth::session_dek::SessionDek;
use crate::errors::AppError;
use crate::models::chat_override::{ChatCharacterOverride, NewChatCharacterOverride};
use crate::schema::chat_character_overrides;
use crate::services::encryption_service::EncryptionService;

#[derive(Clone)]
pub struct ChatOverrideService {
    db_pool: PgPool,
    encryption_service: Arc<EncryptionService>, // Keep Arc in case future versions of EncryptionService have state or are expensive to create
}

impl ChatOverrideService {
    #[must_use]
    pub const fn new(db_pool: PgPool, encryption_service: Arc<EncryptionService>) -> Self {
        Self {
            db_pool,
            encryption_service,
        }
    }

    #[tracing::instrument(skip_all, fields(chat_session_id, user_id, field_name))]
    pub async fn create_or_update_chat_override(
        &self,
        chat_session_id: Uuid,
        original_character_id: Uuid, // Added original_character_id, must be fetched by handler
        _user_id: Uuid, // For logging and potential future checks, though immediate ownership check is in handler
        field_name: String,
        value: String, // Plaintext value from DTO
        session_dek: &SessionDek,
    ) -> Result<ChatCharacterOverride, AppError> {
        // 1. Encrypt the 'value' using encryption_service and session_dek
        let (encrypted_value, nonce) = self
            .encryption_service
            .encrypt(&value, session_dek.expose_bytes())
            .map_err(|e| {
                tracing::error!("Failed to encrypt override value: {}", e);
                AppError::EncryptionError(format!("Failed to encrypt override value: {e}"))
            })?;

        // 2. Prepare NewChatCharacterOverride
        let override_id_for_insert = Uuid::new_v4(); // Generate new ID for insert

        let new_override_for_db = NewChatCharacterOverride {
            id: override_id_for_insert,
            chat_session_id,
            original_character_id,
            field_name: field_name.clone(),
            overridden_value: encrypted_value.clone(),
            overridden_value_nonce: nonce.clone(),
        };

        // Clone values for the update part of the upsert to ensure they are moved into the closure
        let update_encrypted_value = encrypted_value;
        let update_nonce = nonce;

        // 3. Perform DB upsert using db_pool.interact
        let pool = self.db_pool.clone();
        let upserted_override = pool
            .get()
            .await
            .map_err(|e| {
                AppError::DbPoolError(format!("Failed to get DB connection from pool: {e}"))
            })?
            .interact(move |conn| {
                // Define what happens on conflict (update existing row)
                let changes_to_apply = (
                    chat_character_overrides::overridden_value.eq(&update_encrypted_value),
                    chat_character_overrides::overridden_value_nonce.eq(&update_nonce),
                    chat_character_overrides::updated_at.eq(Utc::now()), // Explicitly set updated_at
                );

                diesel::insert_into(chat_character_overrides::table)
                    .values(&new_override_for_db)
                    .on_conflict((
                        chat_character_overrides::chat_session_id,
                        chat_character_overrides::original_character_id,
                        chat_character_overrides::field_name,
                    ))
                    .do_update()
                    .set(changes_to_apply)
                    .returning(ChatCharacterOverride::as_returning())
                    .get_result::<ChatCharacterOverride>(conn)
                    .map_err(AppError::from)
            })
            .await
            .map_err(|e| {
                AppError::DbInteractError(format!(
                    "Database interaction error during override upsert: {e}"
                ))
            })??; // Handle pool.interact error and then the Result from the closure

        tracing::info!(override_id = %upserted_override.id, "Chat character override created/updated successfully via service");
        Ok(upserted_override)
    }
}

// Unit tests will go here later
#[cfg(test)]
mod tests {
    // use super::*;
    // use crate::test_helpers::db::create_test_db_pool;
    // use crate::services::encryption_service::EncryptionService;
    // use std::sync::Arc;

    // TODO: Add unit tests for ChatOverrideService
}
