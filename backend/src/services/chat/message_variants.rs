// backend/src/services/chat/message_variants.rs

use crate::models::chats::{MessageVariant, NewMessageVariant, MessageVariantDto};
use crate::schema::message_variants;
use crate::errors::AppError;
use crate::state::AppState;
use diesel::prelude::*;
use diesel::pg::PgConnection;
use std::sync::Arc;
use uuid::Uuid;
use secrecy::SecretBox;

/// Get all variants for a specific message
pub async fn get_message_variants(
    state: Arc<AppState>,
    message_id: Uuid,
    user_id: Uuid,
    dek: &SecretBox<Vec<u8>>,
) -> Result<Vec<MessageVariantDto>, AppError> {
    let conn = state.pool.get().await?;

    let variants = conn.interact(move |conn| {
        message_variants::table
            .filter(message_variants::parent_message_id.eq(message_id))
            .filter(message_variants::user_id.eq(user_id))
            .order(message_variants::variant_index.asc())
            .select(MessageVariant::as_select())
            .load::<MessageVariant>(conn)
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Failed to load message variants: {e}"))
            })
    }).await?;

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
    let next_index = conn.interact(move |conn| {
        get_next_variant_index(&mut *conn, message_id)
    }).await??;

    // Create new variant with encryption outside the closure
    let new_variant = NewMessageVariant::new(
        message_id,
        next_index,
        content,
        user_id,
        dek,
    )?;

    // Insert into database
    let created_variant = conn.interact(move |conn| {
        diesel::insert_into(message_variants::table)
            .values(&new_variant)
            .returning(MessageVariant::as_returning())
            .get_result::<MessageVariant>(&mut *conn)
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Failed to create message variant: {e}"))
            })
    }).await??;

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

    let variant = conn.interact(move |conn| {
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
    }).await?;

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

    let deleted_count = conn.interact(move |conn| {
        diesel::delete(
            message_variants::table
                .filter(message_variants::parent_message_id.eq(message_id))
                .filter(message_variants::variant_index.eq(variant_index))
                .filter(message_variants::user_id.eq(user_id))
        )
        .execute(&mut *conn)
        .map_err(|e| {
            AppError::DatabaseQueryError(format!("Failed to delete message variant: {e}"))
        })
    }).await?;

    Ok(deleted_count? > 0)
}

/// Get the count of variants for a message
pub async fn get_variant_count(
    state: Arc<AppState>,
    message_id: Uuid,
    user_id: Uuid,
) -> Result<i64, AppError> {
    let conn = state.pool.get().await?;

    let count = conn.interact(move |conn| {
        message_variants::table
            .filter(message_variants::parent_message_id.eq(message_id))
            .filter(message_variants::user_id.eq(user_id))
            .count()
            .get_result::<i64>(&mut *conn)
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Failed to count message variants: {e}"))
            })
    }).await?;

    Ok(count?)
}

/// Helper function to get the next variant index for a message
fn get_next_variant_index(
    conn: &mut PgConnection,
    message_id: Uuid,
) -> Result<i32, AppError> {
    let max_index: Option<i32> = message_variants::table
        .filter(message_variants::parent_message_id.eq(message_id))
        .select(diesel::dsl::max(message_variants::variant_index))
        .first::<Option<i32>>(conn)
        .map_err(|e| {
            AppError::DatabaseQueryError(format!("Failed to get max variant index: {e}"))
        })?;

    Ok(max_index.map_or(0, |max| max + 1))
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
        }).await??;
    }
    
    Ok(())
}