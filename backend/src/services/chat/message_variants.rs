// backend/src/services/chat/message_variants.rs

use crate::errors::AppError;
use crate::models::chats::{MessageVariant, MessageVariantDto, NewMessageVariant};
use crate::schema::message_variants;
use crate::state::AppState;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use secrecy::SecretBox;
use std::sync::Arc;
use uuid::Uuid;

/// Get all variants for a specific message
pub async fn get_message_variants(
    state: Arc<AppState>,
    message_id: Uuid,
    user_id: Uuid,
    dek: &SecretBox<Vec<u8>>,
) -> Result<Vec<MessageVariantDto>, AppError> {
    let conn = state.pool.get().await?;

    let variants = conn
        .interact(move |conn| {
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

/// Create a new variant for a message
pub async fn create_message_variant(
    state: Arc<AppState>,
    message_id: Uuid,
    content: &str,
    user_id: Uuid,
    dek: &SecretBox<Vec<u8>>,
) -> Result<MessageVariantDto, AppError> {
    let conn = state.pool.get().await?;

    // Get the next variant index first
    let next_index = conn
        .interact(move |conn| get_next_variant_index(&mut *conn, message_id))
        .await??;

    // Create new variant with encryption outside the closure
    let new_variant = NewMessageVariant::new(message_id, next_index, content, user_id, dek)?;

    // Insert into database and update parent message status if needed
    let created_variant = conn
        .interact(move |conn| {
            use crate::schema::chat_messages;
            use crate::models::chats::MessageStatus;
            
            // Start a transaction to ensure atomicity
            conn.transaction(|trans_conn| {
                // First, check the parent message status
                let parent_status: String = chat_messages::table
                    .filter(chat_messages::id.eq(message_id))
                    .select(chat_messages::status)
                    .first::<String>(trans_conn)
                    .map_err(|e| {
                        AppError::DatabaseQueryError(format!("Failed to get parent message status: {e}"))
                    })?;
                
                // If parent message has failed or partial status, update it to completed
                // since we're creating a successful variant
                if parent_status == MessageStatus::Failed.to_string() 
                    || parent_status == MessageStatus::Partial.to_string() {
                    diesel::update(chat_messages::table)
                        .filter(chat_messages::id.eq(message_id))
                        .set((
                            chat_messages::status.eq(MessageStatus::Completed.to_string()),
                            chat_messages::error_message.eq(None::<String>),
                        ))
                        .execute(trans_conn)
                        .map_err(|e| {
                            AppError::DatabaseQueryError(format!("Failed to update parent message status: {e}"))
                        })?;
                }
                
                // Now insert the variant
                diesel::insert_into(message_variants::table)
                    .values(&new_variant)
                    .returning(MessageVariant::as_returning())
                    .get_result::<MessageVariant>(trans_conn)
                    .map_err(|e| {
                        AppError::DatabaseQueryError(format!("Failed to create message variant: {e}"))
                    })
            })
        })
        .await??;

    // Return decrypted DTO
    MessageVariantDto::from_model(created_variant, dek)
}

/// Get a specific variant by message ID and variant index
pub async fn get_message_variant_by_index(
    state: Arc<AppState>,
    message_id: Uuid,
    variant_index: i32,
    user_id: Uuid,
    dek: &SecretBox<Vec<u8>>,
) -> Result<Option<MessageVariantDto>, AppError> {
    let conn = state.pool.get().await?;

    let variant = conn
        .interact(move |conn| {
            message_variants::table
                .filter(message_variants::parent_message_id.eq(message_id))
                .filter(message_variants::variant_index.eq(variant_index))
                .filter(message_variants::user_id.eq(user_id))
                .select(MessageVariant::as_select())
                .first::<MessageVariant>(&mut *conn)
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
    message_id: Uuid,
    variant_index: i32,
    user_id: Uuid,
) -> Result<bool, AppError> {
    let conn = state.pool.get().await?;

    let deleted_count = conn
        .interact(move |conn| {
            diesel::delete(
                message_variants::table
                    .filter(message_variants::parent_message_id.eq(message_id))
                    .filter(message_variants::variant_index.eq(variant_index))
                    .filter(message_variants::user_id.eq(user_id)),
            )
            .execute(&mut *conn)
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
    message_id: Uuid,
    user_id: Uuid,
) -> Result<i64, AppError> {
    let conn = state.pool.get().await?;

    let count = conn
        .interact(move |conn| {
            message_variants::table
                .filter(message_variants::parent_message_id.eq(message_id))
                .filter(message_variants::user_id.eq(user_id))
                .count()
                .get_result::<i64>(&mut *conn)
                .map_err(|e| {
                    AppError::DatabaseQueryError(format!("Failed to count message variants: {e}"))
                })
        })
        .await?;

    Ok(count?)
}

/// Helper function to get the next variant index for a message
fn get_next_variant_index(conn: &mut PgConnection, message_id: Uuid) -> Result<i32, AppError> {
    let max_index: Option<i32> = message_variants::table
        .filter(message_variants::parent_message_id.eq(message_id))
        .select(diesel::dsl::max(message_variants::variant_index))
        .first::<Option<i32>>(conn)
        .map_err(|e| {
            AppError::DatabaseQueryError(format!("Failed to get max variant index: {e}"))
        })?;

    Ok(max_index.map_or(0, |max| max + 1))
}

/// Get the active variant content for a message (non-failed/partial)
/// Returns the latest variant content that's not in a failed state
pub async fn get_active_variant_content(
    state: Arc<AppState>,
    message_id: Uuid,
    user_id: Uuid,
    dek: &SecretBox<Vec<u8>>,
) -> Result<Option<String>, AppError> {
    use crate::schema::chat_messages;
    use crate::models::chats::MessageStatus;
    
    let conn = state.pool.get().await?;
    
    // First check the parent message status
    let parent_status = conn
        .interact(move |conn| {
            chat_messages::table
                .filter(chat_messages::id.eq(message_id))
                .select(chat_messages::status)
                .first::<String>(&mut *conn)
                .optional()
                .map_err(|e| {
                    AppError::DatabaseQueryError(format!("Failed to get message status: {e}"))
                })
        })
        .await??;
    
    // If parent message doesn't exist or is failed/partial, look for variants
    match parent_status {
        Some(status) if status == MessageStatus::Failed.to_string() 
            || status == MessageStatus::Partial.to_string() => {
            // Parent is failed/partial, get the latest variant
            let variants = get_message_variants(state, message_id, user_id, dek).await?;
            Ok(variants.last().map(|v| v.content.clone()))
        },
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
        },
        None => Ok(None),
    }
}

/// Store the original message content as variant index 0 if no variants exist yet
pub async fn ensure_original_variant_exists(
    state: Arc<AppState>,
    message_id: Uuid,
    original_content: &str,
    user_id: Uuid,
    dek: &SecretBox<Vec<u8>>,
) -> Result<(), AppError> {
    let variant_count = get_variant_count(state.clone(), message_id, user_id).await?;

    if variant_count == 0 {
        // Create variant index 0 with the original content
        let conn = state.pool.get().await?;

        // Create original variant with encryption outside the closure
        let original_variant = NewMessageVariant::new(
            message_id,
            0, // Original message is always index 0
            original_content,
            user_id,
            dek,
        )?;

        conn.interact(move |conn| {
            diesel::insert_into(message_variants::table)
                .values(&original_variant)
                .execute(&mut *conn)
                .map_err(|e| {
                    AppError::DatabaseQueryError(format!("Failed to create original variant: {e}"))
                })
        })
        .await??;
    }

    Ok(())
}
