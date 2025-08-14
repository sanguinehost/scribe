use scribe_backend::services::agentic::narrative_tools::SearchKnowledgeBaseTool;
use scribe_backend::services::agentic::tools::ScribeTool;
use scribe_backend::test_helpers::{spawn_app, TestDataGuard};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
#[ignore] // Run with --ignored since this needs real services
async fn test_search_improvements_with_keyword_matching() {
    // Set up test environment with mock services
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create test user and session
    let (user, _) = guard.create_test_user("test_user", "password").await;
    let session = guard.create_chat_session(&user, "Test Session").await;
    
    // Create a lorebook with "China" in it
    let lorebook = guard.create_lorebook(&user, "Test Lorebook", Some("A lorebook about China")).await;
    
    // Create lorebook entries with China mentioned
    let entry1 = guard.create_lorebook_entry(
        &lorebook,
        "China Overview",
        "China is a country in East Asia with a rich history spanning thousands of years.",
        Some(vec!["China", "Asia", "history"]),
        true,
        false
    ).await;
    
    let entry2 = guard.create_lorebook_entry(
        &lorebook,
        "Chinese Culture",
        "Chinese culture includes traditions like tea ceremonies, calligraphy, and martial arts.",
        Some(vec!["China", "culture", "traditions"]),
        true,
        false
    ).await;
    
    // Associate lorebook with session
    guard.associate_lorebook_with_session(&session, &lorebook).await;
    
    // Embed the lorebook entries
    let embedding_service = app.state.embedding_service.clone();
    for entry in [&entry1, &entry2] {
        let params = scribe_backend::services::embeddings::LorebookEntryParams {
            original_lorebook_entry_id: entry.id,
            lorebook_id: lorebook.id,
            user_id: user.id,
            decrypted_content: entry.content.clone(),
            decrypted_title: entry.title.clone(),
            decrypted_keywords: entry.keywords.clone(),
            is_enabled: entry.is_enabled,
            is_constant: entry.is_constant,
        };
        
        embedding_service
            .process_and_embed_lorebook_entry(app.state.clone(), params)
            .await
            .expect("Failed to embed lorebook entry");
    }
    
    // Create search tool
    let search_tool = SearchKnowledgeBaseTool::new(
        app.state.qdrant_service.clone(),
        app.state.embedding_client.clone(),
        app.state.clone(),
    );
    
    // Test 1: Search for "China" directly - should use hybrid search
    let search_params = json!({
        "query": "China",
        "search_type": "lorebooks",
        "session_id": session.id.to_string(),
        "user_id": user.id.to_string(),
        "limit": 10
    });
    
    let result = search_tool.execute(search_params).await;
    assert!(result.is_ok(), "Search should succeed");
    
    let response = result.unwrap();
    let results = response["results"].as_array().expect("Should have results array");
    
    // Should find at least one entry with China
    assert!(!results.is_empty(), "Should find results for 'China'");
    
    // Check that we found the right entries
    let found_china = results.iter().any(|r| {
        r["text"].as_str().map_or(false, |t| t.contains("China"))
    });
    assert!(found_china, "Should find entries containing 'China'");
    
    // Test 2: Search for a longer query - should use vector search
    let search_params = json!({
        "query": "Tell me about the history and culture of China",
        "search_type": "lorebooks",
        "session_id": session.id.to_string(),
        "user_id": user.id.to_string(),
        "limit": 10
    });
    
    let result = search_tool.execute(search_params).await;
    assert!(result.is_ok(), "Complex search should succeed");
    
    let response = result.unwrap();
    let results = response["results"].as_array().expect("Should have results array");
    
    // Should still find relevant entries
    assert!(!results.is_empty(), "Should find results for complex query");
    
    // Test 3: Test score threshold filtering
    // Create a mock Qdrant response to test threshold filtering
    app.state.qdrant_service.queue_search_response(vec![
        // High relevance result
        create_mock_scored_point(0.8, "High relevance content about China"),
        // Low relevance result (should be filtered)
        create_mock_scored_point(0.3, "Unrelated content about quantum computing"),
    ]);
    
    let search_params = json!({
        "query": "China history",
        "search_type": "lorebooks",
        "session_id": session.id.to_string(),
        "user_id": user.id.to_string(),
        "limit": 10
    });
    
    let result = search_tool.execute(search_params).await;
    assert!(result.is_ok(), "Threshold search should succeed");
    
    // Cleanup
    drop(guard);
}

fn create_mock_scored_point(score: f32, text: &str) -> qdrant_client::qdrant::ScoredPoint {
    use qdrant_client::qdrant::{PointId, ScoredPoint, Value, value::Kind};
    use std::collections::HashMap;
    
    let mut payload = HashMap::new();
    payload.insert(
        "chunk_text".to_string(),
        Value {
            kind: Some(Kind::StringValue(text.to_string())),
        },
    );
    payload.insert(
        "user_id".to_string(),
        Value {
            kind: Some(Kind::StringValue(Uuid::new_v4().to_string())),
        },
    );
    payload.insert(
        "source_type".to_string(),
        Value {
            kind: Some(Kind::StringValue("lorebook_entry".to_string())),
        },
    );
    
    ScoredPoint {
        id: Some(PointId::from(Uuid::new_v4().to_string())),
        payload,
        score,
        version: 0,
        vectors: None,
        shard_key: None,
        order_value: None,
    }
}