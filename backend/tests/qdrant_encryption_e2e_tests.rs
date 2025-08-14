#![cfg(test)]

use anyhow::Result;
use scribe_backend::{
    auth::session_dek::SessionDek,
    crypto::{decrypt_gcm, encrypt_gcm, generate_dek},
    services::{
        agentic::narrative_tools::SearchKnowledgeBaseTool,
        agentic::tools::ScribeTool,
        embeddings::{EmbeddingPipelineService, EmbeddingPipelineServiceTrait, LorebookEntryParams},
    },
    test_helpers::{self, TestDataGuard},
    text_processing::chunking::ChunkConfig,
};
use chrono::Utc;
use diesel::prelude::*;
use qdrant_client::qdrant::{Condition, FieldCondition, Filter, Match, condition::ConditionOneOf, r#match::MatchValue};
use secrecy::{ExposeSecret, SecretBox};
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;

/// Helper to create a test DEK key  
fn create_test_dek_key() -> Vec<u8> {
    let dek = generate_dek().expect("Failed to generate DEK");
    dek.expose_secret().clone()
}

/// Helper to create a SessionDek for search tests
fn create_test_session_dek() -> SessionDek {
    let key = create_test_dek_key();
    SessionDek(SecretBox::new(Box::new(key)))
}

#[tokio::test]
#[serial]
async fn test_lorebook_entry_encryption_in_qdrant() -> Result<()> {
    let test_app = test_helpers::spawn_app(false, false, true).await; // Use real Qdrant
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user with DEK
    let user = test_helpers::db::create_test_user(&test_app.db_pool, "test_user".to_string(), "password".to_string()).await?;
    let dek_key = create_test_dek_key();
    let dek_secret = SecretBox::new(Box::new(dek_key));
    
    // Create a lorebook
    let lorebook_id = Uuid::new_v4();
    let lorebook = scribe_backend::models::NewLorebook {
        id: lorebook_id,
        user_id: user.id,
        name: "Test Lorebook".to_string(),
        description: Some("Test description".to_string()),
        source_format: "scribe_minimal".to_string(),
        is_public: false,
        created_at: Some(Utc::now()),
        updated_at: Some(Utc::now()),
    };
    
    // Insert lorebook into database
    let conn = test_app.db_pool.get().await?;
    conn.interact(move |conn_sync| {
        diesel::insert_into(scribe_backend::schema::lorebooks::table)
            .values(&lorebook)
            .execute(conn_sync)
    }).await
    .map_err(|e| anyhow::anyhow!("Failed to execute database operation: {}", e))?
    .map_err(|e| anyhow::anyhow!("Failed to insert: {}", e))?;
    
    // Create lorebook entry parameters
    let entry_content = "This is secret content about dragons that should be encrypted";
    let entry_title = "Dragon Secrets";
    
    let params = LorebookEntryParams {
        original_lorebook_entry_id: Uuid::new_v4(),
        lorebook_id,
        user_id: user.id,
        decrypted_content: entry_content.to_string(),
        decrypted_title: Some(entry_title.to_string()),
        decrypted_keywords: Some(vec!["dragon".to_string(), "secret".to_string()]),
        is_enabled: true,
        is_constant: false,
        session_dek: Some(dek_secret),
    };
    
    // Process and embed the lorebook entry with encryption
    // Create a REAL embedding pipeline service since we need actual Qdrant storage
    let chunk_config = ChunkConfig {
        metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
        max_size: 512,
        overlap: 50,
    };
    let real_embedding_service = EmbeddingPipelineService::new(chunk_config);
    let app_state = test_app.create_app_state().await;
    
    real_embedding_service
        .process_and_embed_lorebook_entry(app_state, params)
        .await?;
    
    // Give Qdrant time to index
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    
    // Query Qdrant directly to verify encryption
    let filter = Filter {
        must: vec![
            Condition {
                condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                    key: "user_id".to_string(),
                    r#match: Some(Match {
                        match_value: Some(MatchValue::Keyword(user.id.to_string())),
                    }),
                    ..Default::default()
                })),
            },
            Condition {
                condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                    key: "source_type".to_string(),
                    r#match: Some(Match {
                        match_value: Some(MatchValue::Keyword("lorebook_entry".to_string())),
                    }),
                    ..Default::default()
                })),
            },
        ],
        ..Default::default()
    };
    
    let scroll_result = test_app.qdrant_service
        .retrieve_points(Some(filter), 10)
        .await?;
    
    // Verify we got results
    assert!(!scroll_result.is_empty(), "Expected to find lorebook entries in Qdrant");
    
    // Verify encryption in the payload
    for point in &scroll_result {
        let payload_json: serde_json::Map<String, serde_json::Value> = 
            serde_json::from_value(json!(point.payload))?;
        
        // Check for encrypted fields
        assert!(payload_json.contains_key("encrypted_chunk_text"), "Should have encrypted_chunk_text field");
        assert!(payload_json.contains_key("chunk_text_nonce"), "Should have chunk_text_nonce field");
        
        // Check that plaintext field is placeholder
        if let Some(chunk_text) = payload_json.get("chunk_text") {
            if let Some(text_str) = chunk_text.as_str() {
                assert_eq!(text_str, "[encrypted]", "Plaintext field should contain [encrypted] placeholder");
                assert!(!text_str.contains("dragon"), "Should not contain actual content in plaintext field");
            }
        }
    }
    
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_search_without_dek_returns_placeholders() -> Result<()> {
    let test_app = test_helpers::spawn_app(false, false, true).await; // Use real Qdrant
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user 
    let user = test_helpers::db::create_test_user(&test_app.db_pool, "test_user_nodek".to_string(), "password".to_string()).await?;
    let dek_key_2 = create_test_dek_key();
    let dek_secret_2 = SecretBox::new(Box::new(dek_key_2));
    
    // Create and embed encrypted content (same setup as above)
    let lorebook_id = Uuid::new_v4();
    let lorebook = scribe_backend::models::NewLorebook {
        id: lorebook_id,
        user_id: user.id,
        name: "Secret Lorebook".to_string(),
        description: Some("Contains secrets".to_string()),
        source_format: "scribe_minimal".to_string(),
        is_public: false,
        created_at: Some(Utc::now()),
        updated_at: Some(Utc::now()),
    };
    
    let conn = test_app.db_pool.get().await?;
    conn.interact(move |conn_sync| {
        diesel::insert_into(scribe_backend::schema::lorebooks::table)
            .values(&lorebook)
            .execute(conn_sync)
    }).await
    .map_err(|e| anyhow::anyhow!("Failed to execute database operation: {}", e))?
    .map_err(|e| anyhow::anyhow!("Failed to insert: {}", e))?;
    
    let params = LorebookEntryParams {
        original_lorebook_entry_id: Uuid::new_v4(),
        lorebook_id,
        user_id: user.id,
        decrypted_content: "Top secret information that should never leak".to_string(),
        decrypted_title: Some("Secret Information".to_string()),
        decrypted_keywords: Some(vec!["secret".to_string(), "classified".to_string()]),
        is_enabled: true,
        is_constant: false,
        session_dek: Some(dek_secret_2),
    };
    
    let app_state = test_app.create_app_state().await;
    test_app.mock_embedding_pipeline_service
        .process_and_embed_lorebook_entry(app_state, params)
        .await?;
    
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    
    // Search WITHOUT providing SessionDek
    let search_tool = SearchKnowledgeBaseTool::new(
        test_app.qdrant_service.clone(),
        test_app.mock_embedding_client.clone(),
        test_app.create_app_state().await,
    );
    
    let search_params = json!({
        "query": "secret information",
        "search_type": "lorebooks",
        "user_id": user.id.to_string(),
        // NOTE: No session_dek provided!
        "limit": 10
    });
    
    let search_result = search_tool.execute(&search_params).await?;
    
    let results = search_result["results"].as_array()
        .expect("Expected results array");
    
    if !results.is_empty() {
        let first_result = &results[0];
        let content = first_result["content"].as_str().unwrap();
        
        // Verify content is encrypted placeholder, not actual content
        assert!(
            content.contains("[encrypted") || content == "[encrypted]",
            "Without DEK, should return encrypted placeholder, got: {}",
            content
        );
        assert!(
            !content.contains("secret information") || content.contains("[encrypted"),
            "Should not leak actual content without DEK, got: {}",
            content
        );
    }
    
    Ok(())
}

// Removed test_plaintext_backward_compatibility - not needed per ENCRYPTION_ARCHITECTURE.md
// The system is designed to encrypt all data from the start using per-user DEKs

#[tokio::test]
#[serial]
async fn test_chronicle_event_encryption_in_qdrant() -> Result<()> {
    let test_app = test_helpers::spawn_app(false, false, true).await; // Use real Qdrant
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user with DEK
    let user = test_helpers::db::create_test_user(&test_app.db_pool, "chronicle_test_user".to_string(), "password".to_string()).await?;
    let dek_key = create_test_dek_key();
    let dek_secret = SecretBox::new(Box::new(dek_key));
    
    // Create a chronicle first  
    let chronicle_id = Uuid::new_v4();
    let new_chronicle = scribe_backend::models::chronicle::NewPlayerChronicle {
        user_id: user.id,
        name: "Test Chronicle".to_string(),
        description: Some("Test chronicle for encryption".to_string()),
    };
    
    // Insert chronicle into database
    let conn = test_app.db_pool.get().await?;
    let inserted_chronicle: scribe_backend::models::chronicle::PlayerChronicle = conn.interact(move |conn_sync| {
        diesel::insert_into(scribe_backend::schema::player_chronicles::table)
            .values(&new_chronicle)
            .get_result(conn_sync)
    }).await
    .map_err(|e| anyhow::anyhow!("Failed to execute database operation: {}", e))?
    .map_err(|e| anyhow::anyhow!("Failed to insert chronicle: {}", e))?;
    
    let chronicle_id = inserted_chronicle.id;
    
    // Create a chronicle event
    let event_summary = "The dragon awakened from its centuries-long slumber, sensing the disturbance in the ancient magic";
    let event_keywords = vec!["dragon".to_string(), "awakening".to_string(), "magic".to_string()];
    
    let new_event = scribe_backend::models::chronicle_event::NewChronicleEvent::new(
        chronicle_id,
        user.id,
        "AWAKENING_EVENT".to_string(),
        event_summary.to_string(),
        scribe_backend::models::chronicle_event::EventSource::AiExtracted,
        Some(event_keywords),
        None, // No chat session
    );
    
    // Insert event into database
    let conn = test_app.db_pool.get().await?;
    let event_id = new_event.chronicle_id; // We'll need this for querying Qdrant
    conn.interact(move |conn_sync| {
        diesel::insert_into(scribe_backend::schema::chronicle_events::table)
            .values(&new_event)
            .get_result::<scribe_backend::models::chronicle_event::ChronicleEvent>(conn_sync)
    }).await
    .map_err(|e| anyhow::anyhow!("Failed to execute database operation: {}", e))?
    .map_err(|e| anyhow::anyhow!("Failed to insert chronicle event: {}", e))?;
    
    // Query the inserted event back from database to get the full event
    let conn = test_app.db_pool.get().await?;
    let inserted_event: scribe_backend::models::chronicle_event::ChronicleEvent = conn.interact(move |conn_sync| {
        use scribe_backend::schema::chronicle_events::dsl::*;
        chronicle_events
            .filter(chronicle_id.eq(event_id))
            .first(conn_sync)
    }).await
    .map_err(|e| anyhow::anyhow!("Failed to execute database operation: {}", e))?
    .map_err(|e| anyhow::anyhow!("Failed to query chronicle event: {}", e))?;
    
    // Process and embed the chronicle event with encryption
    // Create a REAL embedding pipeline service since we need actual Qdrant storage
    let chunk_config = ChunkConfig {
        metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
        max_size: 512,
        overlap: 50,
    };
    let real_embedding_service = EmbeddingPipelineService::new(chunk_config);
    let app_state = test_app.create_app_state().await;
    let session_dek = SessionDek(dek_secret);
    
    real_embedding_service
        .process_and_embed_chronicle_event(app_state, inserted_event, Some(&session_dek))
        .await?;
    
    // Give Qdrant time to index
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    
    // Query Qdrant directly to verify encryption
    let filter = Filter {
        must: vec![
            Condition {
                condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                    key: "user_id".to_string(),
                    r#match: Some(Match {
                        match_value: Some(MatchValue::Keyword(user.id.to_string())),
                    }),
                    ..Default::default()
                })),
            },
            Condition {
                condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                    key: "source_type".to_string(),
                    r#match: Some(Match {
                        match_value: Some(MatchValue::Keyword("chronicle_event".to_string())),
                    }),
                    ..Default::default()
                })),
            },
        ],
        ..Default::default()
    };
    
    let scroll_result = test_app.qdrant_service
        .retrieve_points(Some(filter), 10)
        .await?;
    
    // Verify we got results
    assert!(!scroll_result.is_empty(), "Expected to find chronicle event in Qdrant");
    
    // Verify encryption in the payload
    for point in &scroll_result {
        let payload_json: serde_json::Map<String, serde_json::Value> = 
            serde_json::from_value(json!(point.payload))?;
        
        // Check for encrypted fields
        assert!(payload_json.contains_key("encrypted_chunk_text"), "Should have encrypted_chunk_text field");
        assert!(payload_json.contains_key("chunk_text_nonce"), "Should have chunk_text_nonce field");
        
        // Check that plaintext field is placeholder
        if let Some(chunk_text) = payload_json.get("chunk_text") {
            if let Some(text_str) = chunk_text.as_str() {
                assert_eq!(text_str, "[encrypted]", "Plaintext field should contain [encrypted] placeholder");
                assert!(!text_str.contains("dragon"), "Should not contain actual content in plaintext field");
            }
        }
    }
    
    Ok(())
}

#[tokio::test] 
#[serial]
async fn test_encryption_isolation_between_users() -> Result<()> {
    let test_app = test_helpers::spawn_app(false, false, false).await; // This test doesn't need Qdrant
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create two users with different DEKs
    let user_a = test_helpers::db::create_test_user(&test_app.db_pool, "user_a".to_string(), "password".to_string()).await?;
    let user_b = test_helpers::db::create_test_user(&test_app.db_pool, "user_b".to_string(), "password".to_string()).await?;
    
    // Different keys for each user
    let key_a = create_test_dek_key();
    let key_b = create_test_dek_key();
    let dek_a = SecretBox::new(Box::new(key_a));
    let dek_b = SecretBox::new(Box::new(key_b));
    
    // Create encrypted content for User A
    let content_a = "User A's private secret information";
    let (encrypted_a, nonce_a) = encrypt_gcm(content_a.as_bytes(), &dek_a)?;
    
    // Try to decrypt User A's content with User B's key - should fail
    let decrypt_result = decrypt_gcm(&encrypted_a, &nonce_a, &dek_b);
    assert!(decrypt_result.is_err(), "Should not be able to decrypt User A's data with User B's key");
    
    // But User A should be able to decrypt their own content
    let decrypt_result_a = decrypt_gcm(&encrypted_a, &nonce_a, &dek_a)?;
    let decrypted_content = String::from_utf8(decrypt_result_a.expose_secret().clone())?;
    assert_eq!(decrypted_content, content_a, "User A should be able to decrypt their own content");
    
    Ok(())
}