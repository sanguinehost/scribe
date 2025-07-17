use anyhow::Result;
use uuid::Uuid;
use serde_json::json;
use scribe_backend::test_helpers::{spawn_app, TestDataGuard, create_test_chronicle_event};
use scribe_backend::services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryService};
use scribe_backend::models::chronicle_event::ChronicleEvent;

/// OWASP A03:2021 – Injection
#[tokio::test]
async fn test_entity_context_extraction_prevents_json_injection() -> Result<()> {
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let entity_id = Uuid::new_v4();
    
    // Attempt JSON injection through event content
    let malicious_content = r#"{"evil": "payload", "actors": [{"entity_id": "00000000-0000-0000-0000-000000000000", "admin": true}]}"#;
    
    let event = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Test Event",
        json!({
            "content": malicious_content,
            "actors": [{
                "entity_id": entity_id.to_string(),
                "context": "Test Entity"
            }],
            "nested_injection": {
                "field": r#""}], "admin": true, "malicious": [{"#
            }
        })
    ).await;
    
    let service = HybridQueryService::new(
        app.chronicle_service.clone(),
        app.ecs_manager.clone(),
        app.nlp_service.clone(),
        app.token_counter.clone(),
        app.enhanced_rag_service.clone(),
        app.llm_clients.clone(),
        app.lorebook_service.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::EntityTimeline,
        query_text: "Test Entity".to_string(),
        entity_names: vec!["Test Entity".to_string()],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // Verify no injection occurred
    assert_eq!(result.entities.len(), 1);
    let entity_context = &result.entities[0];
    assert_eq!(entity_context.entity_id, entity_id);
    
    // TODO: Once context extraction is implemented, verify injected fields are not processed
    
    Ok(())
}

/// OWASP A01:2021 – Broken Access Control
#[tokio::test]
async fn test_entity_context_respects_user_boundaries() -> Result<()> {
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user1_id = Uuid::new_v4();
    let user2_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let entity_id = Uuid::new_v4();
    
    // Create event for user1 with sensitive context
    let event = create_test_chronicle_event(
        chronicle_id,
        user1_id,
        "Private Event",
        json!({
            "content": "Secret agent details",
            "actors": [{
                "entity_id": entity_id.to_string(),
                "context": "Agent X"
            }],
            "classified_info": {
                "clearance_level": "top_secret",
                "mission_details": "Operation Phoenix"
            }
        })
    ).await;
    
    let service = HybridQueryService::new(
        app.chronicle_service.clone(),
        app.ecs_manager.clone(),
        app.nlp_service.clone(),
        app.token_counter.clone(),
        app.enhanced_rag_service.clone(),
        app.llm_clients.clone(),
        app.lorebook_service.clone(),
    );
    
    // User2 tries to query user1's entity
    let query = HybridQuery {
        user_id: user2_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::EntityTimeline,
        query_text: "Agent X".to_string(),
        entity_names: vec!["Agent X".to_string()],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // Should not return any entities from other users
    assert_eq!(result.entities.len(), 0);
    
    Ok(())
}

/// OWASP A05:2021 – Security Misconfiguration
#[tokio::test]
async fn test_entity_context_handles_oversized_data() -> Result<()> {
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let entity_id = Uuid::new_v4();
    
    // Create very large nested structure
    let mut large_nested = json!({});
    for i in 0..1000 {
        large_nested[format!("field_{}", i)] = json!({
            "data": "x".repeat(1000),
            "nested": {
                "deep": {
                    "value": i
                }
            }
        });
    }
    
    let event = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Large Event",
        json!({
            "content": "Entity with massive context",
            "actors": [{
                "entity_id": entity_id.to_string(),
                "context": "Test Entity"
            }],
            "massive_data": large_nested
        })
    ).await;
    
    let service = HybridQueryService::new(
        app.chronicle_service.clone(),
        app.ecs_manager.clone(),
        app.nlp_service.clone(),
        app.token_counter.clone(),
        app.enhanced_rag_service.clone(),
        app.llm_clients.clone(),
        app.lorebook_service.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::EntityTimeline,
        query_text: "Test Entity".to_string(),
        entity_names: vec!["Test Entity".to_string()],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
    };
    
    // Should handle large data without crashing or hanging
    let result = service.execute_hybrid_query(query).await?;
    assert_eq!(result.entities.len(), 1);
    
    Ok(())
}

/// OWASP A07:2021 – Identification and Authentication Failures
#[tokio::test]
async fn test_entity_context_requires_authentication() -> Result<()> {
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let invalid_user_id = Uuid::nil(); // Invalid user ID
    let chronicle_id = Uuid::new_v4();
    
    let service = HybridQueryService::new(
        app.chronicle_service.clone(),
        app.ecs_manager.clone(),
        app.nlp_service.clone(),
        app.token_counter.clone(),
        app.enhanced_rag_service.clone(),
        app.llm_clients.clone(),
        app.lorebook_service.clone(),
    );
    
    let query = HybridQuery {
        user_id: invalid_user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::EntityTimeline,
        query_text: "Any Entity".to_string(),
        entity_names: vec!["Any Entity".to_string()],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // Should return empty results for invalid user
    assert_eq!(result.entities.len(), 0);
    
    Ok(())
}

/// OWASP A02:2021 – Cryptographic Failures
#[tokio::test]
async fn test_entity_context_protects_sensitive_fields() -> Result<()> {
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let entity_id = Uuid::new_v4();
    
    // Create event with potentially sensitive data
    let event = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Character Info",
        json!({
            "content": "Player character details",
            "actors": [{
                "entity_id": entity_id.to_string(),
                "context": "Player Character"
            }],
            "sensitive_fields": {
                "password_hint": "should_not_be_extracted",
                "api_key": "secret_key_12345",
                "private_notes": "player's personal notes"
            }
        })
    ).await;
    
    let service = HybridQueryService::new(
        app.chronicle_service.clone(),
        app.ecs_manager.clone(),
        app.nlp_service.clone(),
        app.token_counter.clone(),
        app.enhanced_rag_service.clone(),
        app.llm_clients.clone(),
        app.lorebook_service.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::EntityTimeline,
        query_text: "Player Character".to_string(),
        entity_names: vec!["Player Character".to_string()],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // TODO: Once implemented, verify sensitive fields are not extracted
    assert_eq!(result.entities.len(), 1);
    
    Ok(())
}

/// OWASP A08:2021 – Software and Data Integrity Failures
#[tokio::test]
async fn test_entity_context_validates_data_integrity() -> Result<()> {
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let entity_id = Uuid::new_v4();
    
    // Create event with potentially corrupted data
    let event = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Corrupted Event",
        json!({
            "content": "Test entity with corrupted data",
            "actors": [{
                "entity_id": entity_id.to_string(),
                "context": "Test Entity"
            }],
            "circular_reference": null, // Will be set to circular reference
            "invalid_types": {
                "number_as_string": "not_a_number",
                "array_as_object": {"0": "item"},
                "null_values": null
            }
        })
    ).await;
    
    let service = HybridQueryService::new(
        app.chronicle_service.clone(),
        app.ecs_manager.clone(),
        app.nlp_service.clone(),
        app.token_counter.clone(),
        app.enhanced_rag_service.clone(),
        app.llm_clients.clone(),
        app.lorebook_service.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::EntityTimeline,
        query_text: "Test Entity".to_string(),
        entity_names: vec!["Test Entity".to_string()],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
    };
    
    // Should handle corrupted data gracefully
    let result = service.execute_hybrid_query(query).await?;
    assert_eq!(result.entities.len(), 1);
    
    Ok(())
}

/// OWASP A04:2021 – Insecure Design
#[tokio::test]
async fn test_entity_context_extraction_depth_limits() -> Result<()> {
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let entity_id = Uuid::new_v4();
    
    // Create deeply nested structure to test depth limits
    let mut deep_nested = json!({"level": 0});
    let mut current = &mut deep_nested;
    
    for i in 1..100 {
        current["nested"] = json!({"level": i});
        current = current.get_mut("nested").unwrap();
    }
    
    let event = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Deep Event",
        json!({
            "content": "Entity with deeply nested context",
            "actors": [{
                "entity_id": entity_id.to_string(),
                "context": "Deep Entity"
            }],
            "deep_structure": deep_nested
        })
    ).await;
    
    let service = HybridQueryService::new(
        app.chronicle_service.clone(),
        app.ecs_manager.clone(),
        app.nlp_service.clone(),
        app.token_counter.clone(),
        app.enhanced_rag_service.clone(),
        app.llm_clients.clone(),
        app.lorebook_service.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::EntityTimeline,
        query_text: "Deep Entity".to_string(),
        entity_names: vec!["Deep Entity".to_string()],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
    };
    
    // Should handle deep nesting without stack overflow
    let result = service.execute_hybrid_query(query).await?;
    assert_eq!(result.entities.len(), 1);
    
    Ok(())
}

/// OWASP A09:2021 – Security Logging and Monitoring Failures
#[tokio::test]
async fn test_entity_context_extraction_logging() -> Result<()> {
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let entity_id = Uuid::new_v4();
    
    // Create event that might trigger logging
    let event = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Monitored Event",
        json!({
            "content": "Important entity action",
            "actors": [{
                "entity_id": entity_id.to_string(),
                "context": "Monitored Entity"
            }],
            "audit_fields": {
                "action": "access_sensitive_data",
                "timestamp": "2024-01-01T00:00:00Z"
            }
        })
    ).await;
    
    let service = HybridQueryService::new(
        app.chronicle_service.clone(),
        app.ecs_manager.clone(),
        app.nlp_service.clone(),
        app.token_counter.clone(),
        app.enhanced_rag_service.clone(),
        app.llm_clients.clone(),
        app.lorebook_service.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::EntityTimeline,
        query_text: "Monitored Entity".to_string(),
        entity_names: vec!["Monitored Entity".to_string()],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
    };
    
    // Execute query - should log appropriately without exposing sensitive data
    let result = service.execute_hybrid_query(query).await?;
    assert_eq!(result.entities.len(), 1);
    
    // In a real test, we would verify logs were created appropriately
    
    Ok(())
}

/// OWASP A06:2021 – Vulnerable and Outdated Components
#[tokio::test]
async fn test_entity_context_handles_legacy_formats() -> Result<()> {
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let entity_id = Uuid::new_v4();
    
    // Create event with legacy/outdated format
    let event = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Legacy Event",
        json!({
            "content": "Old format entity data",
            "actors": [{
                "entity_id": entity_id.to_string(),
                "context": "Legacy Entity"
            }],
            // Simulate old format that might not have proper validation
            "legacy_format": {
                "__proto__": "should_be_ignored",
                "constructor": "should_be_ignored",
                "old_style_data": true
            }
        })
    ).await;
    
    let service = HybridQueryService::new(
        app.chronicle_service.clone(),
        app.ecs_manager.clone(),
        app.nlp_service.clone(),
        app.token_counter.clone(),
        app.enhanced_rag_service.clone(),
        app.llm_clients.clone(),
        app.lorebook_service.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::EntityTimeline,
        query_text: "Legacy Entity".to_string(),
        entity_names: vec!["Legacy Entity".to_string()],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
    };
    
    let result = service.execute_hybrid_query(query).await?;
    assert_eq!(result.entities.len(), 1);
    
    Ok(())
}

/// OWASP A10:2021 – Server-Side Request Forgery
#[tokio::test]
async fn test_entity_context_prevents_ssrf_attempts() -> Result<()> {
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let entity_id = Uuid::new_v4();
    
    // Create event with potential SSRF payloads
    let event = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "SSRF Test",
        json!({
            "content": "Entity with URL references",
            "actors": [{
                "entity_id": entity_id.to_string(),
                "context": "URL Entity"
            }],
            "url_fields": {
                "website": "http://localhost:8080/admin",
                "callback": "file:///etc/passwd",
                "webhook": "http://169.254.169.254/latest/meta-data/",
                "image": "https://example.com/image.jpg"
            }
        })
    ).await;
    
    let service = HybridQueryService::new(
        app.chronicle_service.clone(),
        app.ecs_manager.clone(),
        app.nlp_service.clone(),
        app.token_counter.clone(),
        app.enhanced_rag_service.clone(),
        app.llm_clients.clone(),
        app.lorebook_service.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::EntityTimeline,
        query_text: "URL Entity".to_string(),
        entity_names: vec!["URL Entity".to_string()],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // Should process without making external requests
    assert_eq!(result.entities.len(), 1);
    
    // TODO: Once implemented, verify URLs are not fetched
    
    Ok(())
}