
use bigdecimal::BigDecimal;
// use chrono::Utc; // Likely unused after removing updated_at from changeset directly
use diesel::prelude::*;
use secrecy::{ExposeSecret, SecretBox};
use serde_json::Value;
use tracing::{error, info, instrument, warn};
use uuid::Uuid;

use crate::{
    crypto::{decrypt_gcm, encrypt_gcm},
    errors::AppError,
    models::chats::{
            ChatSettingsResponse, SettingsTuple, UpdateChatSettingsRequest,
        },
    schema::chat_sessions,
    state::DbPool, // Corrected DbPool import
};
/// Gets chat settings for a specific session, verifying ownership.
#[instrument(skip(pool, user_dek), err)] // Added user_dek to skip
pub async fn get_session_settings(
    pool: &DbPool,
    user_id: Uuid, // <-- Removed underscore
    session_id: Uuid,
    user_dek: Option<&SecretBox<Vec<u8>>>, // Added for decryption
) -> Result<ChatSettingsResponse, AppError> {
    let conn = pool.get().await?;
    // Clone the DEK to move into the closure
    let user_dek_cloned = user_dek.map(|dek| SecretBox::new(Box::new(dek.expose_secret().clone())));
    conn.interact(move |conn| {
        // 1. Check if the session exists and get its owner_id
        let owner_id_result = chat_sessions::table
            .filter(chat_sessions::id.eq(session_id))
            .select(chat_sessions::user_id)
            .first::<Uuid>(conn)
            .optional()?;

        match owner_id_result {
            None => {
                // Session does not exist
                warn!(%session_id, %user_id, "Attempted to get settings for non-existent session");
                Err(AppError::NotFound("Chat session not found".into()))
            }
            Some(owner_id) => {
                // 2. Check if the requesting user owns the session
                if owner_id != user_id {
                    warn!(%session_id, %user_id, owner_id=%owner_id, "Forbidden attempt to get settings for session owned by another user");
                    Err(AppError::Forbidden) // Correct error for unauthorized access
                } else {
                    // 3. Fetch the actual settings since ownership is confirmed
                    info!(%session_id, %user_id, "Fetching settings for owned session");
                    let settings_tuple = chat_sessions::table
                        .filter(chat_sessions::id.eq(session_id)) // Filter only by session_id now
                        .select((
                            chat_sessions::system_prompt_ciphertext,
                            chat_sessions::system_prompt_nonce,
                            chat_sessions::temperature,
                            chat_sessions::max_output_tokens,
                            chat_sessions::frequency_penalty,
                            chat_sessions::presence_penalty,
                            chat_sessions::top_k,
                            chat_sessions::top_p,
                            chat_sessions::repetition_penalty,
                            chat_sessions::min_p,
                            chat_sessions::top_a,
                            chat_sessions::seed,
                            chat_sessions::logit_bias,
                            chat_sessions::history_management_strategy,
                            chat_sessions::history_management_limit,
                            chat_sessions::model_name,
                            // -- Gemini Specific Options --
                            chat_sessions::gemini_thinking_budget,
                            chat_sessions::gemini_enable_code_execution,
                        ))
                        .first::<SettingsTuple>(conn) // Expect a result now
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
                        repetition_penalty,
                        min_p,
                        top_a,
                        seed,
                        logit_bias,
                        history_management_strategy,
                        history_management_limit,
                        model_name,
                        // -- Gemini Specific Options --
                        gemini_thinking_budget,
                        gemini_enable_code_execution,
                    ) = settings_tuple;

                    // Decrypt system_prompt if available
                    let decrypted_system_prompt = match (
                        system_prompt_ciphertext.as_ref(),
                        system_prompt_nonce.as_ref(),
                        user_dek_cloned.as_ref()
                    ) {
                        (Some(ciphertext), Some(nonce), Some(dek)) if !ciphertext.is_empty() && !nonce.is_empty() => {
                            match decrypt_gcm(ciphertext, nonce, dek) { // Use direct call
                                Ok(plaintext_secret) => {
                                    match String::from_utf8(plaintext_secret.expose_secret().to_vec()) {
                                        Ok(decrypted_text) => Some(decrypted_text),
                                        Err(e) => {
                                            error!(%session_id, %user_id, error = ?e, "Failed to convert decrypted system_prompt to UTF-8");
                                            return Err(AppError::DecryptionError("Failed to convert system_prompt to UTF-8".to_string()));
                                        }
                                    }
                                },
                                Err(e) => {
                                    error!(%session_id, %user_id, error = ?e, "Failed to decrypt system_prompt");
                                    return Err(AppError::DecryptionError("Failed to decrypt system_prompt".to_string()));
                                }
                            }
                        },
                        (Some(_), Some(_), None) => {
                            error!(%session_id, %user_id, "System prompt is encrypted but no DEK provided");
                            return Err(AppError::DecryptionError("No DEK available for decryption".to_string()));
                        },
                        _ => None, // No system prompt or empty fields
                    };

                    Ok(ChatSettingsResponse {
                        system_prompt: decrypted_system_prompt,
                        temperature,
                        max_output_tokens,
                        frequency_penalty,
                        presence_penalty,
                        top_k,
                        top_p,
                        repetition_penalty,
                        min_p,
                        top_a,
                        seed,
                        logit_bias,
                        history_management_strategy,
                        history_management_limit,
                        model_name,
                        // -- Gemini Specific Options --
                        gemini_thinking_budget,
                        gemini_enable_code_execution,
                    })
                }
            }
        }
    })
    .await?
}
/// Updates chat settings for a specific session, verifying ownership.
#[instrument(skip(pool, payload), err)]
pub async fn update_session_settings(
    pool: &DbPool,
    user_id: Uuid,
    session_id: Uuid,
    payload: UpdateChatSettingsRequest,
    user_dek: Option<&SecretBox<Vec<u8>>>, // Added user_dek
) -> Result<ChatSettingsResponse, AppError> {
    let conn = pool.get().await?;

    // Clone the DEK for use inside the 'move' closure if it's Some.
    // We need an owned SecretBox for the closure if we are to use it.
    let user_dek_owned_opt: Option<SecretBox<Vec<u8>>> =
        user_dek.map(|dek_ref| SecretBox::new(Box::new(dek_ref.expose_secret().clone())));

    conn.interact(move |conn_interaction| {
        conn_interaction.transaction(|transaction_conn| {
            // 1. Verify ownership
            let owner_id_result = chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .select(chat_sessions::user_id)
                .first::<Uuid>(transaction_conn)
                .optional()?;

            match owner_id_result {
                Some(owner_id) => {
                    if owner_id != user_id {
                        error!(
                            "User {} attempted to update settings for session {} owned by {}",
                            user_id, session_id, owner_id
                        );
                        return Err(AppError::Forbidden);
                    }

                    // 2. Perform the update using AsChangeset
                    #[derive(AsChangeset, Default, Debug)]
                    #[diesel(table_name = chat_sessions)]
                    struct ChatSessionUpdateChangeset {
                        system_prompt_ciphertext: Option<Option<Vec<u8>>>,
                        system_prompt_nonce: Option<Option<Vec<u8>>>,
                        temperature: Option<BigDecimal>,
                        max_output_tokens: Option<i32>,
                        frequency_penalty: Option<BigDecimal>,
                        presence_penalty: Option<BigDecimal>,
                        top_k: Option<i32>,
                        top_p: Option<BigDecimal>,
                        repetition_penalty: Option<BigDecimal>,
                        min_p: Option<BigDecimal>,
                        top_a: Option<BigDecimal>,
                        seed: Option<i32>,
                        logit_bias: Option<Value>,
                        history_management_strategy: Option<String>,
                        history_management_limit: Option<i32>,
                        model_name: Option<String>,
                        gemini_thinking_budget: Option<i32>,
                        gemini_enable_code_execution: Option<bool>,
                        updated_at: Option<chrono::DateTime<chrono::Utc>>,
                    }

                    let mut changeset = ChatSessionUpdateChangeset::default();
                    let mut changes_made = false;

                    // Handle system_prompt update
                    if let Some(new_prompt_str) = payload.system_prompt {
                        changes_made = true;
                        let trimmed_prompt = new_prompt_str.trim();
                        if trimmed_prompt.is_empty() {
                            changeset.system_prompt_ciphertext = Some(None);
                            changeset.system_prompt_nonce = Some(None);
                        } else {
                            match &user_dek_owned_opt {
                                Some(dek) => {
                                    let (ciphertext, nonce) =
                                        encrypt_gcm(trimmed_prompt.as_bytes(), dek) // Use direct call
                                            .map_err(|e| {
                                                error!("Failed to encrypt system prompt: {}", e);
                                                AppError::EncryptionError(
                                                    "Failed to encrypt system prompt".to_string(),
                                                )
                                            })?;
                                    changeset.system_prompt_ciphertext = Some(Some(ciphertext));
                                    changeset.system_prompt_nonce = Some(Some(nonce));
                                }
                                None => {
                                    error!("User DEK not provided, cannot encrypt system prompt for update.");
                                    return Err(AppError::BadRequest(
                                        "User DEK is required to update system prompt.".to_string(),
                                    ));
                                }
                            }
                        }
                    }

                    // Handle other optional fields
                    if let Some(temp) = payload.temperature {
                        changes_made = true;
                        changeset.temperature = Some(temp);
                    }
                    if let Some(max_tokens) = payload.max_output_tokens {
                        changes_made = true;
                        changeset.max_output_tokens = Some(max_tokens);
                    }
                    if let Some(freq_pen) = payload.frequency_penalty {
                        changes_made = true;
                        changeset.frequency_penalty = Some(freq_pen);
                    }
                    if let Some(pres_pen) = payload.presence_penalty {
                        changes_made = true;
                        changeset.presence_penalty = Some(pres_pen);
                    }
                    if let Some(tk) = payload.top_k {
                        changes_made = true;
                        changeset.top_k = Some(tk);
                    }
                    if let Some(tp) = payload.top_p {
                        changes_made = true;
                        changeset.top_p = Some(tp);
                    }
                    if let Some(rep_pen) = payload.repetition_penalty {
                        changes_made = true;
                        changeset.repetition_penalty = Some(rep_pen);
                    }
                    if let Some(m_p) = payload.min_p {
                        changes_made = true;
                        changeset.min_p = Some(m_p);
                    }
                    if let Some(t_a) = payload.top_a {
                        changes_made = true;
                        changeset.top_a = Some(t_a);
                    }
                    if let Some(s) = payload.seed {
                        changes_made = true;
                        changeset.seed = Some(s);
                    }
                    if let Some(lb) = payload.logit_bias {
                        changes_made = true;
                        changeset.logit_bias = Some(lb);
                    }
                    if let Some(hist_strat) = payload.history_management_strategy {
                        changes_made = true;
                        changeset.history_management_strategy = Some(hist_strat);
                    }
                    if let Some(hist_limit) = payload.history_management_limit {
                        changes_made = true;
                        changeset.history_management_limit = Some(hist_limit);
                    }
                    if let Some(model) = payload.model_name {
                        changes_made = true;
                        changeset.model_name = Some(model);
                    }
                    if let Some(gem_budget) = payload.gemini_thinking_budget {
                        changes_made = true;
                        changeset.gemini_thinking_budget = Some(gem_budget);
                    }
                    if let Some(gem_exec) = payload.gemini_enable_code_execution {
                        changes_made = true;
                        changeset.gemini_enable_code_execution = Some(gem_exec);
                    }

                    if changes_made {
                        changeset.updated_at = Some(chrono::Utc::now());
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
                    
                    // Return Ok(()) from the transaction closure. The actual response will be fetched outside.
                    Ok(())
                }
                None => {
                    error!("Chat session {} not found for update", session_id);
                    Err(AppError::NotFound("Chat session not found".into()))
                }
            }
        })
    })
    .await??; // First '?' for InteractError, second for AppError from transaction

    // 3. Fetch and return the updated settings using get_session_settings
    // This ensures the response reflects the changes and system_prompt is correctly decrypted.
    // Note: get_session_settings expects Option<&SecretBox>, so we use the original user_dek.
    get_session_settings(pool, user_id, session_id, user_dek).await
}
