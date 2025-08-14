// Migration script to encrypt existing plaintext data in Qdrant
// This script will:
// 1. Fetch all existing points from Qdrant
// 2. For each point with plaintext data, encrypt it using the user's DEK
// 3. Update the point with encrypted fields while preserving plaintext for backward compatibility

use anyhow::{Context, Result};
use scribe_backend::{
    crypto::{encrypt_gcm},
    services::{
        embeddings::metadata::{LorebookChunkMetadata, ChatMessageChunkMetadata},
    },
};
use qdrant_client::{
    Qdrant,
    qdrant::{
        PointId, 
        ScrollPointsBuilder, Value as QdrantValue,
    },
};
use secrecy::SecretBox;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("Starting Qdrant encryption migration...");

    // Load configuration from environment
    let qdrant_url = std::env::var("QDRANT_URL")
        .unwrap_or_else(|_| "http://localhost:6334".to_string());
    
    // Initialize Qdrant client
    let qdrant_client = Qdrant::from_url(&qdrant_url).build()?;
    
    // TODO: You'll need to initialize database connection to fetch user DEKs
    // For now, this is a placeholder showing the structure
    
    info!("Connected to Qdrant at {}", qdrant_url);
    
    // Process lorebook chunks
    migrate_lorebook_chunks(&qdrant_client).await?;
    
    // Process chat message chunks  
    migrate_chat_message_chunks(&qdrant_client).await?;
    
    info!("Migration completed successfully!");
    Ok(())
}

async fn migrate_lorebook_chunks(
    client: &Qdrant,
) -> Result<()> {
    info!("Migrating lorebook chunks...");
    
    let collection_name = "lorebook_chunks";
    let mut offset: Option<PointId> = None;
    let limit = 100;
    let mut total_migrated = 0;
    let mut total_skipped = 0;
    
    loop {
        // Scroll through points in batches
        let mut builder = ScrollPointsBuilder::new(collection_name)
            .limit(limit)
            .with_payload(true)
            .with_vectors(false);
        
        if let Some(ref offset_id) = offset {
            builder = builder.offset(offset_id.clone());
        }
        
        let scroll_result = client.scroll(builder).await?;
        
        if scroll_result.result.is_empty() {
            break;
        }
        
        for point in &scroll_result.result {
            let point_id = point.id.clone().unwrap();
            let payload = point.payload.clone();
            
            // Check if this point already has encrypted fields
            if payload.contains_key("encrypted_chunk_text") {
                total_skipped += 1;
                continue;
            }
            
            // Extract user_id to get the user's DEK
            let user_id = extract_uuid_from_payload(&payload, "user_id")?;
            
            // TODO: Fetch the user's DEK from the database
            // For now, this is a placeholder - in production, you'd fetch from DB
            warn!("DEK fetching not implemented - skipping point {:?} for user {}", point_id, user_id);
            total_skipped += 1;
            continue;
            
            // Once DEK is available, the encryption would look like this:
            /*
            let user_dek = get_user_dek(user_id, dek_cache).await?;
            
            // Extract plaintext content
            let chunk_text = extract_string_from_payload(&payload, "chunk_text")?;
            let entry_title = extract_optional_string_from_payload(&payload, "entry_title");
            
            // Encrypt the content
            let (encrypted_chunk_text, chunk_text_nonce) = 
                encrypt_gcm(chunk_text.as_bytes(), &user_dek)?;
            
            let (encrypted_title, title_nonce) = if let Some(title) = entry_title {
                let (enc, nonce) = encrypt_gcm(title.as_bytes(), &user_dek)?;
                (Some(enc), Some(nonce))
            } else {
                (None, None)
            };
            
            // Update the point with encrypted fields
            let mut new_payload = HashMap::new();
            
            // Add encrypted fields
            new_payload.insert("encrypted_chunk_text".to_string(), 
                QdrantValue::from(encrypted_chunk_text));
            new_payload.insert("chunk_text_nonce".to_string(), 
                QdrantValue::from(chunk_text_nonce));
            
            if let Some(enc_title) = encrypted_title {
                new_payload.insert("encrypted_title".to_string(), 
                    QdrantValue::from(enc_title));
            }
            if let Some(nonce) = title_nonce {
                new_payload.insert("title_nonce".to_string(), 
                    QdrantValue::from(nonce));
            }
            
            // Update the point
            client
                .set_payload(
                    collection_name,
                    None,
                    &SetPayloadPointsBuilder::new(collection_name, new_payload)
                        .points_selector(vec![point_id.clone()])
                        .build(),
                    None,
                )
                .await?;
            
            total_migrated += 1;
            */
        }
        
        // Update offset for next batch
        offset = scroll_result.result.last().and_then(|p| p.id.clone());
        
        info!("Processed batch: {} migrated, {} skipped", total_migrated, total_skipped);
    }
    
    info!("Lorebook migration complete: {} migrated, {} skipped", 
          total_migrated, total_skipped);
    Ok(())
}

async fn migrate_chat_message_chunks(
    client: &Qdrant,
) -> Result<()> {
    info!("Migrating chat message chunks...");
    
    let collection_name = "chat_message_chunks";
    let mut offset: Option<PointId> = None;
    let limit = 100;
    let mut total_migrated = 0;
    let mut total_skipped = 0;
    
    loop {
        // Scroll through points in batches
        let mut builder = ScrollPointsBuilder::new(collection_name)
            .limit(limit)
            .with_payload(true)
            .with_vectors(false);
        
        if let Some(ref offset_id) = offset {
            builder = builder.offset(offset_id.clone());
        }
        
        let scroll_result = client.scroll(builder).await?;
        
        if scroll_result.result.is_empty() {
            break;
        }
        
        for point in &scroll_result.result {
            let point_id = point.id.clone().unwrap();
            let payload = point.payload.clone();
            
            // Check if this point already has encrypted fields
            if payload.contains_key("encrypted_text") {
                total_skipped += 1;
                continue;
            }
            
            // Extract user_id to get the user's DEK
            let user_id = extract_uuid_from_payload(&payload, "user_id")?;
            
            // TODO: Fetch the user's DEK from the database
            // For now, this is a placeholder
            warn!("DEK fetching not implemented - skipping point {:?} for user {}", point_id, user_id);
            total_skipped += 1;
            continue;
            
            // Once DEK is available, the encryption would look like this:
            /*
            let user_dek = get_user_dek(user_id, dek_cache).await?;
            
            // Extract plaintext content
            let text = extract_string_from_payload(&payload, "text")?;
            
            // Encrypt the content
            let (encrypted_text, text_nonce) = encrypt_gcm(text.as_bytes(), &user_dek)?;
            
            // Update the point with encrypted fields
            let mut new_payload = HashMap::new();
            new_payload.insert("encrypted_text".to_string(), 
                QdrantValue::from(encrypted_text));
            new_payload.insert("text_nonce".to_string(), 
                QdrantValue::from(text_nonce));
            
            // Update the point
            client
                .set_payload(
                    collection_name,
                    None,
                    &SetPayloadPointsBuilder::new(collection_name, new_payload)
                        .points_selector(vec![point_id.clone()])
                        .build(),
                    None,
                )
                .await?;
            
            total_migrated += 1;
            */
        }
        
        // Update offset for next batch
        offset = scroll_result.result.last().and_then(|p| p.id.clone());
        
        info!("Processed batch: {} migrated, {} skipped", total_migrated, total_skipped);
    }
    
    info!("Chat message migration complete: {} migrated, {} skipped", 
          total_migrated, total_skipped);
    Ok(())
}

// Helper functions to extract values from payload
fn extract_string_from_payload(
    payload: &HashMap<String, QdrantValue>,
    key: &str,
) -> Result<String> {
    payload
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .context(format!("Missing or invalid '{}' in payload", key))
}

fn extract_optional_string_from_payload(
    payload: &HashMap<String, QdrantValue>,
    key: &str,
) -> Option<String> {
    payload
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn extract_uuid_from_payload(
    payload: &HashMap<String, QdrantValue>,
    key: &str,
) -> Result<Uuid> {
    let str_value = extract_string_from_payload(payload, key)?;
    Uuid::parse_str(&str_value)
        .context(format!("Invalid UUID format for '{}'", key))
}

// Placeholder for fetching user DEK - would need DB connection
#[allow(dead_code)]
async fn get_user_dek(
    _user_id: Uuid,
) -> Result<SecretBox<Vec<u8>>> {
    // TODO: Implement actual DEK fetching from database
    // This would involve:
    // 1. Check cache first
    // 2. If not in cache, fetch from database
    // 3. Decrypt DEK using KEK
    // 4. Store in cache
    // 5. Return DEK
    
    anyhow::bail!("DEK fetching not yet implemented")
}