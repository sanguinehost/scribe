use bigdecimal::BigDecimal;
// use chrono::Utc; // Likely unused after removing updated_at from changeset directly
use diesel::{
    AsChangeset, Connection, ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl,
};
use secrecy::{ExposeSecret, SecretBox};
use tracing::{error, info, instrument, warn};
use uuid::Uuid;

use crate::{
    crypto::{decrypt_gcm, encrypt_gcm},
    errors::AppError,
    models::chats::{ChatSettingsResponse, SettingsTuple, UpdateChatSettingsRequest},
    schema::chat_sessions,
    state::DbPool, // Corrected DbPool import
};

/// Helper enum for database updates to improve type safety
#[derive(Debug)]
enum DatabaseUpdate<T> {
    NoChange,
    SetValue(T),
    SetNull,
}

impl<T> Default for DatabaseUpdate<T> {
    fn default() -> Self {
        Self::NoChange
    }
}

// Convert to Option<Option<T>> for Diesel compatibility
impl<T> From<DatabaseUpdate<T>> for Option<Option<T>> {
    fn from(update: DatabaseUpdate<T>) -> Self {
        match update {
            DatabaseUpdate::NoChange => None,
            DatabaseUpdate::SetValue(val) => Some(Some(val)),
            DatabaseUpdate::SetNull => Some(None),
        }
    }
}

/// Custom wrapper for nullable encrypted fields that handles the Option<Option<T>> pattern
#[derive(Debug)]
pub struct NullableEncryptedField<T> {
    value: DatabaseUpdate<T>,
}

impl<T> Default for NullableEncryptedField<T> {
    fn default() -> Self {
        Self {
            value: DatabaseUpdate::NoChange,
        }
    }
}

impl<T> From<DatabaseUpdate<T>> for NullableEncryptedField<T> {
    fn from(update: DatabaseUpdate<T>) -> Self {
        Self { value: update }
    }
}

impl<T> From<NullableEncryptedField<T>> for Option<Option<T>> {
    fn from(field: NullableEncryptedField<T>) -> Self {
        field.value.into()
    }
}

#[derive(Debug, Default)]
struct ChatSessionUpdateBuilder {
    system_prompt_ciphertext: NullableEncryptedField<Vec<u8>>,
    system_prompt_nonce: NullableEncryptedField<Vec<u8>>,
    temperature: DatabaseUpdate<BigDecimal>,
    max_output_tokens: DatabaseUpdate<i32>,
    frequency_penalty: DatabaseUpdate<BigDecimal>,
    presence_penalty: DatabaseUpdate<BigDecimal>,
    top_k: DatabaseUpdate<i32>,
    top_p: DatabaseUpdate<BigDecimal>,
    seed: DatabaseUpdate<i32>,
    stop_sequences: DatabaseUpdate<Vec<String>>,
    history_management_strategy: DatabaseUpdate<String>,
    history_management_limit: DatabaseUpdate<i32>,
    model_name: DatabaseUpdate<String>,
    gemini_thinking_budget: DatabaseUpdate<i32>,
    gemini_enable_code_execution: DatabaseUpdate<bool>,
    updated_at: DatabaseUpdate<chrono::DateTime<chrono::Utc>>,
}

impl ChatSessionUpdateBuilder {
    fn build(self) -> ChatSessionUpdateChangeset {
        ChatSessionUpdateChangeset {
            system_prompt_ciphertext: self.system_prompt_ciphertext.into(),
            system_prompt_nonce: self.system_prompt_nonce.into(),
            temperature: match self.temperature {
                DatabaseUpdate::SetValue(v) => Some(v),
                _ => None,
            },
            max_output_tokens: match self.max_output_tokens {
                DatabaseUpdate::SetValue(v) => Some(v),
                _ => None,
            },
            frequency_penalty: match self.frequency_penalty {
                DatabaseUpdate::SetValue(v) => Some(v),
                _ => None,
            },
            presence_penalty: match self.presence_penalty {
                DatabaseUpdate::SetValue(v) => Some(v),
                _ => None,
            },
            top_k: match self.top_k {
                DatabaseUpdate::SetValue(v) => Some(v),
                _ => None,
            },
            top_p: match self.top_p {
                DatabaseUpdate::SetValue(v) => Some(v),
                _ => None,
            },
            seed: match self.seed {
                DatabaseUpdate::SetValue(v) => Some(v),
                _ => None,
            },
            stop_sequences: match self.stop_sequences {
                DatabaseUpdate::SetValue(v) => Some(v),
                _ => None,
            },
            history_management_strategy: match self.history_management_strategy {
                DatabaseUpdate::SetValue(v) => Some(v),
                _ => None,
            },
            history_management_limit: match self.history_management_limit {
                DatabaseUpdate::SetValue(v) => Some(v),
                _ => None,
            },
            model_name: match self.model_name {
                DatabaseUpdate::SetValue(v) => Some(v),
                _ => None,
            },
            gemini_thinking_budget: match self.gemini_thinking_budget {
                DatabaseUpdate::SetValue(v) => Some(v),
                _ => None,
            },
            gemini_enable_code_execution: match self.gemini_enable_code_execution {
                DatabaseUpdate::SetValue(v) => Some(v),
                _ => None,
            },
            updated_at: match self.updated_at {
                DatabaseUpdate::SetValue(v) => Some(v),
                _ => None,
            },
        }
    }

    const fn has_changes(&self) -> bool {
        !matches!(
            self.system_prompt_ciphertext.value,
            DatabaseUpdate::NoChange
        ) || !matches!(self.system_prompt_nonce.value, DatabaseUpdate::NoChange)
            || !matches!(self.temperature, DatabaseUpdate::NoChange)
            || !matches!(self.max_output_tokens, DatabaseUpdate::NoChange)
            || !matches!(self.frequency_penalty, DatabaseUpdate::NoChange)
            || !matches!(self.presence_penalty, DatabaseUpdate::NoChange)
            || !matches!(self.top_k, DatabaseUpdate::NoChange)
            || !matches!(self.top_p, DatabaseUpdate::NoChange)
            || !matches!(self.seed, DatabaseUpdate::NoChange)
            || !matches!(self.stop_sequences, DatabaseUpdate::NoChange)
            || !matches!(self.history_management_strategy, DatabaseUpdate::NoChange)
            || !matches!(self.history_management_limit, DatabaseUpdate::NoChange)
            || !matches!(self.model_name, DatabaseUpdate::NoChange)
            || !matches!(self.gemini_thinking_budget, DatabaseUpdate::NoChange)
            || !matches!(self.gemini_enable_code_execution, DatabaseUpdate::NoChange)
    }
}

#[allow(clippy::option_option)] // Diesel
#[derive(AsChangeset, Debug)]
#[diesel(table_name = chat_sessions)]
struct ChatSessionUpdateChangeset {
    /// Encrypted system prompt ciphertext - uses Option<Option<T>> pattern for nullable fields
    /// - None: Don't update the field
    /// - Some(None): Set field to NULL
    /// - Some(Some(value)): Set field to specific value
    system_prompt_ciphertext: Option<Option<Vec<u8>>>,
    /// Encrypted system prompt nonce - uses Option<Option<T>> pattern for nullable fields
    system_prompt_nonce: Option<Option<Vec<u8>>>,
    temperature: Option<BigDecimal>,
    max_output_tokens: Option<i32>,
    frequency_penalty: Option<BigDecimal>,
    presence_penalty: Option<BigDecimal>,
    top_k: Option<i32>,
    top_p: Option<BigDecimal>,
    seed: Option<i32>,
    stop_sequences: Option<Vec<String>>,
    history_management_strategy: Option<String>,
    history_management_limit: Option<i32>,
    model_name: Option<String>,
    gemini_thinking_budget: Option<i32>,
    gemini_enable_code_execution: Option<bool>,
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}
/// Verifies session ownership and returns the owner ID
fn verify_session_ownership(
    conn: &mut diesel::PgConnection,
    session_id: Uuid,
    user_id: Uuid,
) -> Result<(), AppError> {
    let owner_id_result = chat_sessions::table
        .filter(chat_sessions::id.eq(session_id))
        .select(chat_sessions::user_id)
        .first::<Uuid>(conn)
        .optional()
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

    match owner_id_result {
        None => {
            warn!(target: "scribe_backend::services::chat::settings", %session_id, %user_id, "Session not found");
            Err(AppError::NotFound("Chat session not found".into()))
        }
        Some(owner_id) if owner_id != user_id => {
            warn!(target: "scribe_backend::services::chat::settings", %session_id, requesting_user_id = %user_id, actual_owner_id = %owner_id, "Forbidden access attempt");
            Err(AppError::Forbidden(
                "Access denied to chat session settings".to_string(),
            ))
        }
        Some(_) => Ok(()),
    }
}

/// Decrypts system prompt if available and valid
fn decrypt_system_prompt(
    ciphertext: Option<&Vec<u8>>,
    nonce: Option<&Vec<u8>>,
    user_dek: Option<&SecretBox<Vec<u8>>>,
    session_id: Uuid,
    user_id: Uuid,
) -> Result<Option<String>, AppError> {
    info!(%session_id, %user_id, 
          has_ciphertext = ciphertext.is_some(), 
          ciphertext_len = ciphertext.map(|c| c.len()).unwrap_or(0),
          has_nonce = nonce.is_some(), 
          nonce_len = nonce.map(|n| n.len()).unwrap_or(0),
          has_dek = user_dek.is_some(),
          "decrypt_system_prompt: Input parameters");

    match (ciphertext, nonce, user_dek) {
        (Some(ciphertext), Some(nonce), Some(dek))
            if !ciphertext.is_empty() && !nonce.is_empty() =>
        {
            info!(%session_id, %user_id, "decrypt_system_prompt: Attempting decryption");
            let plaintext_secret = decrypt_gcm(ciphertext, nonce, dek).map_err(|e| {
                error!(%session_id, %user_id, error = ?e, "Failed to decrypt system_prompt");
                AppError::DecryptionError("Failed to decrypt system_prompt".to_string())
            })?;

            let decrypted_text = String::from_utf8(plaintext_secret.expose_secret().clone())
                .map_err(|e| {
                    error!(%session_id, %user_id, error = ?e, "Failed to convert decrypted system_prompt to UTF-8");
                    AppError::DecryptionError("Failed to convert system_prompt to UTF-8".to_string())
                })?;

            info!(%session_id, %user_id, decrypted_len = decrypted_text.len(), "decrypt_system_prompt: Successfully decrypted");
            Ok(Some(decrypted_text))
        }
        (Some(_), Some(_), None) => {
            error!(%session_id, %user_id, "System prompt is encrypted but no DEK provided");
            Err(AppError::DecryptionError(
                "No DEK available for decryption".to_string(),
            ))
        }
        (Some(ciphertext), None, _) => {
            error!(%session_id, %user_id, ciphertext_len = ciphertext.len(), "System prompt ciphertext exists but nonce is None");
            Ok(None)
        }
        (None, Some(_), _) => {
            info!(%session_id, %user_id, "Nonce exists but no ciphertext");
            Ok(None)
        }
        _ => {
            info!(%session_id, %user_id, "No system prompt data");
            Ok(None)
        } // No system prompt or empty fields
    }
}

/// Gets chat settings for a specific session, verifying ownership.
#[instrument(skip(pool, user_dek), err)]
pub async fn get_session_settings(
    pool: &DbPool,
    user_id: Uuid,
    session_id: Uuid,
    user_dek: Option<&SecretBox<Vec<u8>>>,
) -> Result<ChatSettingsResponse, AppError> {
    let conn = pool.get().await?;
    let user_dek_cloned = user_dek.map(|dek| SecretBox::new(Box::new(dek.expose_secret().clone())));

    conn.interact(move |conn| {
        verify_session_ownership(conn, session_id, user_id)?;
        info!(%session_id, %user_id, "Fetching settings for owned session");
        let settings_tuple = chat_sessions::table
            .filter(chat_sessions::id.eq(session_id))
            .select((
                chat_sessions::system_prompt_ciphertext,
                chat_sessions::system_prompt_nonce,
                chat_sessions::temperature,
                chat_sessions::max_output_tokens,
                chat_sessions::frequency_penalty,
                chat_sessions::presence_penalty,
                chat_sessions::top_k,
                chat_sessions::top_p,
                chat_sessions::seed,
                chat_sessions::stop_sequences,
                chat_sessions::history_management_strategy,
                chat_sessions::history_management_limit,
                chat_sessions::model_name,
                chat_sessions::gemini_thinking_budget,
                chat_sessions::gemini_enable_code_execution,
            ))
            .first::<SettingsTuple>(conn)
            .map_err(|e| {
                error!(%session_id, %user_id, error = ?e, "Failed to fetch settings after ownership check");
                AppError::DatabaseQueryError(e.to_string())
            })?;

        let (
            system_prompt_ciphertext,
            system_prompt_nonce,
            temperature,
            max_output_tokens,
            frequency_penalty,
            presence_penalty,
            top_k,
            top_p,
            seed,
            stop_sequences,
            history_management_strategy,
            history_management_limit,
            model_name,
            gemini_thinking_budget,
            gemini_enable_code_execution,
        ) = settings_tuple;

        let decrypted_system_prompt = decrypt_system_prompt(
            system_prompt_ciphertext.as_ref(),
            system_prompt_nonce.as_ref(),
            user_dek_cloned.as_ref(),
            session_id,
            user_id,
        )?;

        info!(%session_id, %user_id, 
              decrypted_system_prompt_is_some = decrypted_system_prompt.is_some(),
              decrypted_system_prompt_len = decrypted_system_prompt.as_ref().map(|s| s.len()).unwrap_or(0),
              "get_session_settings: Creating ChatSettingsResponse");

        let response = ChatSettingsResponse {
            system_prompt: decrypted_system_prompt,
            temperature,
            max_output_tokens,
            frequency_penalty,
            presence_penalty,
            top_k,
            top_p,
            seed,
            stop_sequences,
            history_management_strategy,
            history_management_limit,
            model_name,
            gemini_thinking_budget,
            gemini_enable_code_execution,
        };

        info!(%session_id, %user_id, 
              response_system_prompt_is_some = response.system_prompt.is_some(),
              response_system_prompt_len = response.system_prompt.as_ref().map(|s| s.len()).unwrap_or(0),
              "get_session_settings: Response created successfully");

        Ok(response)
    })
    .await?
}
/// Handles system prompt encryption for update
fn handle_system_prompt_update(
    new_prompt_str: &str,
    user_dek: Option<&SecretBox<Vec<u8>>>,
    update_builder: &mut ChatSessionUpdateBuilder,
) -> Result<(), AppError> {
    let trimmed_prompt = new_prompt_str.trim();
    if trimmed_prompt.is_empty() {
        update_builder.system_prompt_ciphertext = DatabaseUpdate::SetNull.into();
        update_builder.system_prompt_nonce = DatabaseUpdate::SetNull.into();
    } else if let Some(dek) = user_dek {
        let (ciphertext, nonce) = encrypt_gcm(trimmed_prompt.as_bytes(), dek).map_err(|e| {
            error!("Failed to encrypt system prompt: {}", e);
            AppError::EncryptionError("Failed to encrypt system prompt".to_string())
        })?;
        update_builder.system_prompt_ciphertext = DatabaseUpdate::SetValue(ciphertext).into();
        update_builder.system_prompt_nonce = DatabaseUpdate::SetValue(nonce).into();
    } else {
        error!("User DEK not provided, cannot encrypt system prompt for update.");
        return Err(AppError::BadRequest(
            "User DEK is required to update system prompt.".to_string(),
        ));
    }
    Ok(())
}

/// Applies all payload fields to the update builder
fn apply_payload_to_builder(
    payload: UpdateChatSettingsRequest,
    user_dek: Option<&SecretBox<Vec<u8>>>,
) -> Result<ChatSessionUpdateBuilder, AppError> {
    let mut update_builder = ChatSessionUpdateBuilder::default();

    if let Some(new_prompt_str) = payload.system_prompt {
        handle_system_prompt_update(&new_prompt_str, user_dek, &mut update_builder)?;
    }

    if let Some(temp) = payload.temperature {
        update_builder.temperature = DatabaseUpdate::SetValue(temp);
    }
    if let Some(max_tokens) = payload.max_output_tokens {
        update_builder.max_output_tokens = DatabaseUpdate::SetValue(max_tokens);
    }
    if let Some(freq_pen) = payload.frequency_penalty {
        update_builder.frequency_penalty = DatabaseUpdate::SetValue(freq_pen);
    }
    if let Some(pres_pen) = payload.presence_penalty {
        update_builder.presence_penalty = DatabaseUpdate::SetValue(pres_pen);
    }
    if let Some(tk) = payload.top_k {
        update_builder.top_k = DatabaseUpdate::SetValue(tk);
    }
    if let Some(tp) = payload.top_p {
        update_builder.top_p = DatabaseUpdate::SetValue(tp);
    }
    if let Some(s) = payload.seed {
        update_builder.seed = DatabaseUpdate::SetValue(s);
    }
    if let Some(ss_option_vec) = payload.stop_sequences {
        update_builder.stop_sequences =
            DatabaseUpdate::SetValue(ss_option_vec.into_iter().flatten().collect());
    }
    if let Some(hist_strat) = payload.history_management_strategy {
        update_builder.history_management_strategy = DatabaseUpdate::SetValue(hist_strat);
    }
    if let Some(hist_limit) = payload.history_management_limit {
        update_builder.history_management_limit = DatabaseUpdate::SetValue(hist_limit);
    }
    if let Some(model) = payload.model_name {
        update_builder.model_name = DatabaseUpdate::SetValue(model);
    }
    if let Some(gem_budget) = payload.gemini_thinking_budget {
        update_builder.gemini_thinking_budget = DatabaseUpdate::SetValue(gem_budget);
    }
    if let Some(gem_exec) = payload.gemini_enable_code_execution {
        update_builder.gemini_enable_code_execution = DatabaseUpdate::SetValue(gem_exec);
    }

    Ok(update_builder)
}

/// Executes the database update if there are changes
fn execute_update(
    update_builder: ChatSessionUpdateBuilder,
    session_id: Uuid,
    transaction_conn: &mut diesel::PgConnection,
) -> Result<(), AppError> {
    if update_builder.has_changes() {
        let mut builder = update_builder;
        builder.updated_at = DatabaseUpdate::SetValue(chrono::Utc::now());
        let changeset = builder.build();
        diesel::update(chat_sessions::table.filter(chat_sessions::id.eq(session_id)))
            .set(&changeset)
            .execute(transaction_conn)
            .map_err(|e| {
                error!("Failed to update chat session settings: {}", e);
                AppError::DatabaseQueryError(e.to_string())
            })?;
        info!(%session_id, "Chat session settings updated successfully in DB.");
    } else {
        info!(%session_id, "No changes provided to update chat session settings.");
    }
    Ok(())
}

/// Updates chat settings for a specific session, verifying ownership.
#[instrument(skip(pool, payload), err)]
pub async fn update_session_settings(
    pool: &DbPool,
    user_id: Uuid,
    session_id: Uuid,
    payload: UpdateChatSettingsRequest,
    user_dek: Option<&SecretBox<Vec<u8>>>,
) -> Result<ChatSettingsResponse, AppError> {
    let conn = pool.get().await?;
    let user_dek_owned_opt: Option<SecretBox<Vec<u8>>> =
        user_dek.map(|dek_ref| SecretBox::new(Box::new(dek_ref.expose_secret().clone())));

    conn.interact(move |conn_interaction| {
        conn_interaction.transaction::<_, AppError, _>(|transaction_conn| {
            verify_session_ownership(transaction_conn, session_id, user_id)?;

            let update_builder = apply_payload_to_builder(payload, user_dek_owned_opt.as_ref())?;
            execute_update(update_builder, session_id, transaction_conn)?;

            Ok(())
        })
    })
    .await??;

    get_session_settings(pool, user_id, session_id, user_dek).await
}
