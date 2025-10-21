// backend/src/services/chat/message_variants.rs

use crate::errors::AppError;
use crate::models::chats::{MessageVariant, MessageVariantDto, NewMessageVariant};
use crate::schema::message_variants;
use crate::state::AppState;
use diesel::prelude::*;
use secrecy::{ExposeSecret, SecretBox};
use std::sync::Arc;
use uuid::Uuid;

/// Get all variants for a specific message
pub async fn get_message_variants(
    state: Arc<AppState>,
    message_id: crate::DbUuid,
    user_id: crate::DbUuid,
    dek: &SecretBox<Vec<u8>>,
) -> Result<Vec<MessageVariantDto>, AppError> {
    let variants = crate::db::with_conn(&state.pool, move |conn| {
        message_variants::table
            .filter(message_variants::parent_message_id.eq(message_id))
            .filter(message_variants::user_id.eq(user_id))
            .order(message_variants::variant_index.asc())
            .select(MessageVariant::as_select())
            .load::<MessageVariant>(conn)
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Failed to load message variants: {e}"))
            })
    })
    .await?;

    // Decrypt all variants
    let mut decrypted_variants = Vec::new();
    for variant in variants? {
        let dto = MessageVariantDto::from_model(variant, dek)?;
        decrypted_variants.push(dto);
    }

    Ok(decrypted_variants)
}

/// Create a new variant for a message and return the updated parent message
pub async fn create_message_variant(
    state: Arc<AppState>,
    message_id: crate::DbUuid,
    content: &str,
    user_id: crate::DbUuid,
    dek: &SecretBox<Vec<u8>>,
) -> Result<crate::models::chats::MessageResponse, AppError> {
    tracing::info!(
        "🆕 Creating new variant for message {} with content length {}",
        message_id,
        content.len()
    );

    // Get the next variant index first
    let next_index = crate::db::with_conn(&state.pool, move |conn| {
        get_next_variant_index(conn, message_id).map_err(AppError::from)
    })
    .await?;

    tracing::info!(
        "🔢 Next variant index for message {}: {}",
        message_id,
        next_index
    );

    // Create new variant with encryption outside the closure
    let new_variant = NewMessageVariant::new(message_id, next_index, content, user_id, dek)?;

    // Clone the DEK for use in the closure (create a new SecretBox from the exposed secret)
    let dek_for_closure = SecretBox::new(Box::new(dek.expose_secret().clone()));

    // Insert variant and update parent message in transaction
    let updated_message = crate::db::with_conn(&state.pool, move |conn| {
            use crate::models::chats::{MessageStatus, Message};
            use crate::schema::chat_messages;

            // Start a transaction to ensure atomicity
            conn.transaction::<Message, AppError, _>(|trans_conn| {
                // First, get the current parent message
                let parent_message = chat_messages::table
                    .filter(chat_messages::id.eq(message_id))
                    .select(Message::as_select())
                    .first::<Message>(trans_conn)
                    .map_err(|e| {
                        AppError::DatabaseQueryError(format!(
                            "Failed to get parent message: {e}"
                        ))
                    })?;

                // If this is the first variant (index 1), store the original content as variant 0
                let final_variant_count = if next_index == 1 {
                    tracing::info!(
                        "🆕 Creating first variant for message {}, storing original as variant 0",
                        message_id
                    );

                    // Decrypt the original message content to store as variant 0
                    let original_content = if let Some(nonce) = &parent_message.content_nonce {
                        // Message is encrypted, decrypt it
                        match crate::crypto::decrypt_gcm(&parent_message.content, nonce, &dek_for_closure) {
                            Ok(decrypted_secret_box) => {
                                let decrypted_bytes = decrypted_secret_box.expose_secret();
                                String::from_utf8(decrypted_bytes.clone())
                                    .map_err(|e| AppError::DecryptionError(format!("Invalid UTF-8: {e}")))?
                            },
                            Err(e) => return Err(AppError::DecryptionError(format!(
                                "Failed to decrypt original message content: {e}"
                            ))),
                        }
                    } else {
                        // Message is not encrypted (legacy or test data)
                        String::from_utf8(parent_message.content.clone())
                            .map_err(|e| AppError::DecryptionError(format!("Invalid UTF-8 in unencrypted message: {e}")))?
                    };

                    // Create variant 0 with original content
                    let original_variant = NewMessageVariant::new(
                        message_id,
                        0, // Original message is variant 0
                        &original_content,
                        user_id,
                        &dek_for_closure,
                    ).map_err(|e| AppError::DatabaseQueryError(format!(
                        "Failed to create original variant: {e}"
                    )))?;

                    // Insert original variant
                    diesel::insert_into(message_variants::table)
                        .values(&original_variant)
                        .execute(trans_conn)
                        .map_err(|e| {
                            AppError::DatabaseQueryError(format!(
                                "Failed to insert original variant: {e}"
                            ))
                        })?;

                    tracing::info!(
                        "✅ Stored original content as variant 0 for message {}",
                        message_id
                    );

                    // Total count includes original (0) + first variant (1) = 2
                    2
                } else {
                    // Not the first variant, just increment the count
                    parent_message.variant_count + 1
                };

                // Insert the new variant
                #[cfg(feature = "postgres-backend")]
                {
                    diesel::insert_into(message_variants::table)
                        .values(&new_variant)
                        .returning(MessageVariant::as_returning())
                        .get_result::<MessageVariant>(trans_conn)
                        .map_err(|e| {
                            AppError::DatabaseQueryError(format!(
                                "Failed to create message variant: {e}"
                            ))
                        })?;
                }

                #[cfg(feature = "sqlite-backend")]
                {
                    use diesel::prelude::*;
                    // SQLite doesn't support RETURNING, insert and query back
                    let parent_id_clone = new_variant.parent_message_id;
                    let variant_idx_clone = new_variant.variant_index;

                    diesel::insert_into(message_variants::table)
                        .values(&new_variant)
                        .execute(trans_conn)
                        .map_err(|e| {
                            AppError::DatabaseQueryError(format!(
                                "Failed to create message variant: {e}"
                            ))
                        })?;

                    // Query back using unique constraint (parent_message_id, variant_index)
                    message_variants::table
                        .filter(message_variants::parent_message_id.eq(parent_id_clone))
                        .filter(message_variants::variant_index.eq(variant_idx_clone))
                        .select(MessageVariant::as_select())
                        .first::<MessageVariant>(trans_conn)
                        .map_err(|e| {
                            AppError::DatabaseQueryError(format!(
                                "Failed to query message variant after insert: {e}"
                            ))
                        })?;
                }

                // Update parent message with new variant count and set current variant to the new one
                let new_variant_count = final_variant_count;
                tracing::info!(
                    "📊 Updating parent message {}: variant_count {} → {}, current_variant_index → {}",
                    message_id,
                    parent_message.variant_count,
                    new_variant_count,
                    next_index
                );

                #[cfg(feature = "postgres-backend")]
                let updated_parent = {
                    diesel::update(chat_messages::table)
                        .filter(chat_messages::id.eq(message_id))
                        .set((
                            chat_messages::variant_count.eq(new_variant_count),
                            chat_messages::current_variant_index.eq(next_index),
                            chat_messages::status.eq(MessageStatus::Completed.to_string()),
                            chat_messages::error_message.eq(None::<String>),
                        ))
                        .returning(Message::as_returning())
                        .get_result::<Message>(trans_conn)
                        .map_err(|e| {
                            AppError::DatabaseQueryError(format!(
                                "Failed to update parent message: {e}"
                            ))
                        })?
                };

                #[cfg(feature = "sqlite-backend")]
                let updated_parent = {
                    use diesel::prelude::*;
                    // SQLite doesn't support RETURNING, update and query back
                    diesel::update(chat_messages::table)
                        .filter(chat_messages::id.eq(message_id))
                        .set((
                            chat_messages::variant_count.eq(new_variant_count),
                            chat_messages::current_variant_index.eq(next_index),
                            chat_messages::status.eq(MessageStatus::Completed.to_string()),
                            chat_messages::error_message.eq(None::<String>),
                        ))
                        .execute(trans_conn)
                        .map_err(|e| {
                            AppError::DatabaseQueryError(format!(
                                "Failed to update parent message: {e}"
                            ))
                        })?;

                    chat_messages::table
                        .find(message_id)
                        .select(Message::as_select())
                        .first::<Message>(trans_conn)
                        .map_err(|e| {
                            AppError::DatabaseQueryError(format!(
                                "Failed to query parent message after update: {e}"
                            ))
                        })?
                };

                tracing::info!(
                    "✅ Successfully created variant {} for message {} (total variants: {})",
                    next_index,
                    message_id,
                    new_variant_count
                );
                Ok(updated_parent)
            })
        })
        .await?;

    // Get the content for the current variant (the newly created one)
    let current_content = if next_index == 0 {
        // Should not happen since variants start from index 1, but handle it
        let client_message = updated_message
            .clone()
            .into_decrypted_for_client(Some(dek))?;
        client_message.content
    } else {
        // Use the content we just created
        content.to_string()
    };

    // Build and return MessageResponse
    let response = crate::models::chats::MessageResponse {
        id: updated_message.id,
        session_id: updated_message.session_id,
        message_type: updated_message.message_type,
        role: updated_message
            .role
            .unwrap_or_else(|| updated_message.message_type.to_string()),
        content: current_content,
        parts: updated_message
            .parts
            .unwrap_or_else(|| serde_json::json!([])),
        attachments: updated_message
            .attachments
            .unwrap_or_else(|| serde_json::json!([])),
        created_at: updated_message.created_at,
        raw_prompt: None, // Don't expose raw prompts in variant creation
        prompt_tokens: updated_message.prompt_tokens,
        completion_tokens: updated_message.completion_tokens,
        model_name: Some(updated_message.model_name),
        status: updated_message.status,
        error_message: updated_message.error_message,
        variant_count: updated_message.variant_count,
        current_variant_index: updated_message.current_variant_index,
        is_variant: false,
        parent_message_id: None,
        variants: None, // Don't include full variant data in creation response
    };

    Ok(response)
}

/// Get a specific variant by message ID and variant index
pub async fn get_message_variant_by_index(
    state: Arc<AppState>,
    message_id: crate::DbUuid,
    variant_index: i32,
    user_id: crate::DbUuid,
    dek: &SecretBox<Vec<u8>>,
) -> Result<Option<MessageVariantDto>, AppError> {
    let variant = crate::db::with_conn(&state.pool, move |conn| {
        message_variants::table
            .filter(message_variants::parent_message_id.eq(message_id))
            .filter(message_variants::variant_index.eq(variant_index))
            .filter(message_variants::user_id.eq(user_id))
            .select(MessageVariant::as_select())
            .first::<MessageVariant>(conn)
            .optional()
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Failed to load message variant: {e}"))
            })
    })
    .await?;

    match variant? {
        Some(v) => Ok(Some(MessageVariantDto::from_model(v, dek)?)),
        None => Ok(None),
    }
}

/// Delete a message variant
pub async fn delete_message_variant(
    state: Arc<AppState>,
    message_id: crate::DbUuid,
    variant_index: i32,
    user_id: crate::DbUuid,
) -> Result<bool, AppError> {
    let deleted_count = crate::db::with_conn(&state.pool, move |conn| {
        diesel::delete(
            message_variants::table
                .filter(message_variants::parent_message_id.eq(message_id))
                .filter(message_variants::variant_index.eq(variant_index))
                .filter(message_variants::user_id.eq(user_id)),
        )
        .execute(conn)
        .map_err(|e| {
            AppError::DatabaseQueryError(format!("Failed to delete message variant: {e}"))
        })
    })
    .await?;

    Ok(deleted_count? > 0)
}

/// Get the count of variants for a message
pub async fn get_variant_count(
    state: Arc<AppState>,
    message_id: crate::DbUuid,
    user_id: crate::DbUuid,
) -> Result<i64, AppError> {
    let count = crate::db::with_conn(&state.pool, move |conn| {
        message_variants::table
            .filter(message_variants::parent_message_id.eq(message_id))
            .filter(message_variants::user_id.eq(user_id))
            .count()
            .get_result::<i64>(conn)
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Failed to count message variants: {e}"))
            })
    })
    .await?;

    Ok(count?)
}

/// Helper function to get the next variant index for a message
fn get_next_variant_index(conn: &mut crate::db::DbConn, message_id: crate::DbUuid) -> Result<i32, AppError> {
    let max_index: Option<i32> = message_variants::table
        .filter(message_variants::parent_message_id.eq(message_id))
        .select(diesel::dsl::max(message_variants::variant_index))
        .first::<Option<i32>>(conn)
        .map_err(|e| {
            AppError::DatabaseQueryError(format!("Failed to get max variant index: {e}"))
        })?;

    Ok(max_index.map_or(1, |max| max + 1))
}

/// Get the active variant content for a message (non-failed/partial)
/// Returns the latest variant content that's not in a failed state
pub async fn get_active_variant_content(
    state: Arc<AppState>,
    message_id: crate::DbUuid,
    user_id: crate::DbUuid,
    dek: &SecretBox<Vec<u8>>,
) -> Result<Option<String>, AppError> {
    use crate::models::chats::MessageStatus;
    use crate::schema::chat_messages;

    // First check the parent message status
    let parent_status = crate::db::with_conn(&state.pool, move |conn| {
        chat_messages::table
            .filter(chat_messages::id.eq(message_id))
            .select(chat_messages::status)
            .first::<String>(conn)
            .optional()
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Failed to get message status: {e}"))
            })
    })
    .await?;

    // If parent message doesn't exist or is failed/partial, look for variants
    match parent_status {
        Some(status)
            if status == MessageStatus::Failed.to_string()
                || status == MessageStatus::Partial.to_string() =>
        {
            // Parent is failed/partial, get the latest variant
            let variants = get_message_variants(state, message_id, user_id, dek).await?;
            Ok(variants.last().map(|v| v.content.clone()))
        }
        Some(_) => {
            // Parent is in good status, check if we have variants and return the latest
            let variants = get_message_variants(state, message_id, user_id, dek).await?;
            if variants.is_empty() {
                // No variants, return None (caller should use original message)
                Ok(None)
            } else {
                // Return the latest variant
                Ok(variants.last().map(|v| v.content.clone()))
            }
        }
        None => Ok(None),
    }
}

/// Store the original message content as variant index 0 if no variants exist yet
pub async fn ensure_original_variant_exists(
    state: Arc<AppState>,
    message_id: crate::DbUuid,
    original_content: &str,
    user_id: crate::DbUuid,
    dek: &SecretBox<Vec<u8>>,
) -> Result<(), AppError> {
    let variant_count = get_variant_count(state.clone(), message_id, user_id).await?;

    if variant_count == 0 {
        // Create original variant with encryption outside the closure
        let original_variant = NewMessageVariant::new(
            message_id,
            0, // Original message is always index 0
            original_content,
            user_id,
            dek,
        )?;

        crate::db::with_conn(&state.pool, move |conn| {
            diesel::insert_into(message_variants::table)
                .values(&original_variant)
                .execute(conn)
                .map_err(|e| {
                    AppError::DatabaseQueryError(format!("Failed to create original variant: {e}"))
                })
        })
        .await?;
    }

    Ok(())
}

/// Select a specific variant for a message by updating the current_variant_index
pub async fn select_message_variant(
    state: Arc<AppState>,
    message_id: crate::DbUuid,
    variant_index: i32,
    user_id: crate::DbUuid,
    dek: &SecretBox<Vec<u8>>,
) -> Result<crate::models::chats::MessageResponse, AppError> {
    use crate::models::chats::Message;
    use crate::schema::chat_messages;

    // First get the parent message to validate user ownership and variant bounds
    let parent_message = crate::db::with_conn(&state.pool, move |conn| {
        chat_messages::table
            .filter(chat_messages::id.eq(message_id))
            .filter(chat_messages::user_id.eq(user_id))
            .select(Message::as_select())
            .first::<Message>(conn)
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Failed to get parent message: {e}"))
            })
    })
    .await?;

    // Validate variant_index bounds
    if variant_index < 0 || variant_index >= parent_message.variant_count {
        return Err(AppError::BadRequest(format!(
            "Variant index {} is out of bounds. Message has {} variants (0-{})",
            variant_index,
            parent_message.variant_count,     // Total number of variants
            parent_message.variant_count - 1  // Highest valid index
        )));
    }

    // Get variant content - if index 0, use original message content; otherwise get from variants table
    let variant_content = if variant_index == 0 {
        // Index 0 is the original message content - decrypt from parent message
        use crate::crypto;

        // Get the nonce for the parent message content
        let nonce_bytes = parent_message.content_nonce.as_ref().ok_or_else(|| {
            AppError::DecryptionError("Missing content nonce for parent message".to_string())
        })?;

        let decrypted_content = crypto::decrypt_gcm(&parent_message.content, nonce_bytes, dek)
            .map_err(|e| {
                AppError::DecryptionError(format!(
                    "Failed to decrypt original message content: {e}"
                ))
            })?;
        String::from_utf8(decrypted_content.expose_secret().clone()).map_err(|e| {
            AppError::DecryptionError(format!("Failed to decode original message content: {e}"))
        })?
    } else {
        // Get content from variants table
        let variant_dto =
            get_message_variant_by_index(state.clone(), message_id, variant_index, user_id, dek)
                .await?;

        match variant_dto {
            Some(dto) => dto.content,
            None => {
                return Err(AppError::BadRequest(format!(
                    "Variant with index {} not found",
                    variant_index
                )));
            }
        }
    };

    // Update the parent message's current_variant_index
    let updated_message = crate::db::with_conn(&state.pool, move |conn| {
        #[cfg(feature = "postgres-backend")]
        {
            diesel::update(chat_messages::table)
                .filter(chat_messages::id.eq(message_id))
                .filter(chat_messages::user_id.eq(user_id))
                .set(chat_messages::current_variant_index.eq(variant_index))
                .returning(Message::as_returning())
                .get_result::<Message>(conn)
                .map_err(|e| {
                    AppError::DatabaseQueryError(format!(
                        "Failed to update current variant index: {e}"
                    ))
                })
        }

        #[cfg(feature = "sqlite-backend")]
        {
            use diesel::prelude::*;
            // SQLite doesn't support RETURNING, update and query back
            diesel::update(chat_messages::table)
                .filter(chat_messages::id.eq(message_id))
                .filter(chat_messages::user_id.eq(user_id))
                .set(chat_messages::current_variant_index.eq(variant_index))
                .execute(conn)
                .map_err(|e| {
                    AppError::DatabaseQueryError(format!(
                        "Failed to update current variant index: {e}"
                    ))
                })?;

            chat_messages::table
                .find(message_id)
                .select(Message::as_select())
                .first::<Message>(conn)
                .map_err(|e| {
                    AppError::DatabaseQueryError(format!(
                        "Failed to query message after update: {e}"
                    ))
                })
        }
    })
    .await?;

    // Build and return MessageResponse with the selected variant content
    let response = crate::models::chats::MessageResponse {
        id: updated_message.id,
        session_id: updated_message.session_id,
        message_type: updated_message.message_type,
        role: updated_message
            .role
            .unwrap_or_else(|| updated_message.message_type.to_string()),
        content: variant_content, // Use the selected variant's content
        parts: updated_message
            .parts
            .unwrap_or_else(|| serde_json::json!([])),
        attachments: updated_message
            .attachments
            .unwrap_or_else(|| serde_json::json!([])),
        created_at: updated_message.created_at,
        raw_prompt: None, // Don't expose raw prompts in variant selection
        prompt_tokens: updated_message.prompt_tokens,
        completion_tokens: updated_message.completion_tokens,
        model_name: Some(updated_message.model_name),
        status: updated_message.status,
        error_message: updated_message.error_message,
        variant_count: updated_message.variant_count,
        current_variant_index: updated_message.current_variant_index,
        is_variant: false,
        parent_message_id: None,
        variants: None, // Don't include full variant data in selection response
    };

    Ok(response)
}
