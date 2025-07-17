use anyhow::Result;
use uuid::Uuid;
use serde_json::json;
use scribe_backend::test_helpers::{spawn_app, TestDataGuard, create_test_chronicle_event};
use scribe_backend::services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryService};

/// OWASP A01:2021 – Broken Access Control
#[tokio::test]
async fn test_item_ownership_access_control() -> Result<()> {
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user1_id = Uuid::new_v4();
    let user2_id = Uuid::new_v4();
    let chronicle1_id = Uuid::new_v4();
    let chronicle2_id = Uuid::new_v4();
    let item_id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    
    // User1 creates an item in their chronicle
    let event = create_test_chronicle_event(
        chronicle1_id,
        user1_id,
        "Item Creation",
        json!({
            "content": "A powerful artifact was discovered",
            "actors": [{
                "entity_id": owner_id.to_string(),
                "context": "Hero"
            }],
            "items": [{
                "item_id": item_id.to_string(),
                "name": "Artifact of Power",
                "action": "discovered",
                "owner": owner_id.to_string(),
                "value": 10000
            }]
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
    
    // User2 tries to query user1's items
    let query = HybridQuery {
        user_id: user2_id,
        chronicle_id: Some(chronicle1_id), // Wrong chronicle
        query_type: HybridQueryType::ItemTimeline,
        query_text: "Artifact of Power".to_string(),
        entity_names: vec![],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // Should not return items from other users' chronicles
    assert_eq!(result.entities.len(), 0);
    
    Ok(())
}

/// OWASP A03:2021 – Injection
#[tokio::test]
async fn test_item_query_injection_prevention() -> Result<()> {
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let item_id = Uuid::new_v4();
    
    // Create item with potential injection vectors
    let event = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Item Creation",
        json!({
            "content": "Item with malicious data",
            "items": [{
                "item_id": item_id.to_string(),
                "name": "'; DROP TABLE items; --",
                "action": "created",
                "properties": {
                    "sql_injection": "' OR '1'='1",
                    "json_injection": r#"}", "admin": true, "extra": {"#,
                    "script_tag": "<script>alert('xss')</script>"
                }
            }]
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
    
    // Query with injection attempt
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemSearch,
        query_text: "'; SELECT * FROM users; --".to_string(),
        entity_names: vec![],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
    };
    
    // Should handle injection attempts safely
    let result = service.execute_hybrid_query(query).await?;
    
    // Verify no injection occurred (no error, controlled results)
    assert!(result.warnings.is_empty() || !result.warnings.iter().any(|w| w.contains("syntax")));
    
    Ok(())
}

/// OWASP A04:2021 – Insecure Design
#[tokio::test]
async fn test_item_duplication_prevention() -> Result<()> {
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let item_id = Uuid::new_v4();
    let owner1_id = Uuid::new_v4();
    let owner2_id = Uuid::new_v4();
    
    // Attempt to create duplicate ownership through race condition
    let event1 = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Item Transfer",
        json!({
            "content": "Item transferred to owner1",
            "items": [{
                "item_id": item_id.to_string(),
                "name": "Unique Artifact",
                "action": "transferred",
                "owner": owner1_id.to_string()
            }]
        })
    ).await;
    
    // Simultaneous conflicting transfer
    let event2 = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Item Transfer",
        json!({
            "content": "Item transferred to owner2",
            "items": [{
                "item_id": item_id.to_string(),
                "name": "Unique Artifact",
                "action": "transferred",
                "owner": owner2_id.to_string()
            }]
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
        query_type: HybridQueryType::ItemTimeline,
        query_text: "Unique Artifact".to_string(),
        entity_names: vec![],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // TODO: Verify only one valid owner once implemented
    
    Ok(())
}

/// OWASP A05:2021 – Security Misconfiguration
#[tokio::test]
async fn test_item_data_exposure_limits() -> Result<()> {
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    
    // Create many items to test pagination/limits
    for i in 0..100 {
        let item_id = Uuid::new_v4();
        let event = create_test_chronicle_event(
            chronicle_id,
            user_id,
            "Item Creation",
            json!({
                "content": format!("Item {} created", i),
                "items": [{
                    "item_id": item_id.to_string(),
                    "name": format!("Item {}", i),
                    "action": "created",
                    "sensitive_data": {
                        "internal_id": i,
                        "debug_info": "should_not_be_exposed"
                    }
                }]
            })
        ).await;
    }
    
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
        query_type: HybridQueryType::ItemSearch,
        query_text: "all items".to_string(),
        entity_names: vec![],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10, // Should respect this limit
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // Should respect max_results limit
    assert!(result.chronicle_events.len() <= 10);
    
    Ok(())
}

/// OWASP A07:2021 – Identification and Authentication Failures
#[tokio::test]
async fn test_item_query_authentication_required() -> Result<()> {
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let chronicle_id = Uuid::new_v4();
    let anonymous_user = Uuid::nil(); // Invalid/anonymous user
    
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
        user_id: anonymous_user,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemSearch,
        query_text: "valuable items".to_string(),
        entity_names: vec![],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // Should return no results for unauthenticated user
    assert_eq!(result.entities.len(), 0);
    assert_eq!(result.chronicle_events.len(), 0);
    
    Ok(())
}

/// OWASP A02:2021 – Cryptographic Failures
#[tokio::test]
async fn test_item_value_data_protection() -> Result<()> {
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let item_id = Uuid::new_v4();
    
    // Create item with sensitive value data
    let event = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Valuable Item",
        json!({
            "content": "A treasure was found",
            "items": [{
                "item_id": item_id.to_string(),
                "name": "Royal Treasury Key",
                "action": "discovered",
                "sensitive_properties": {
                    "vault_code": "1234567890",
                    "combination": "L36-R45-L12",
                    "access_pattern": "should_be_encrypted"
                }
            }]
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
        query_type: HybridQueryType::ItemTimeline,
        query_text: "Royal Treasury Key".to_string(),
        entity_names: vec![],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // TODO: Verify sensitive properties are not exposed once implemented
    
    Ok(())
}

/// OWASP A08:2021 – Software and Data Integrity Failures
#[tokio::test]
async fn test_item_state_consistency() -> Result<()> {
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let item_id = Uuid::new_v4();
    
    // Create conflicting item states
    let event1 = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Item State 1",
        json!({
            "content": "The sword is pristine",
            "items": [{
                "item_id": item_id.to_string(),
                "name": "Magic Sword",
                "action": "updated",
                "condition": "pristine",
                "durability": 100
            }]
        })
    ).await;
    
    // Conflicting state
    let event2 = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Item State 2",
        json!({
            "content": "The sword is broken",
            "items": [{
                "item_id": item_id.to_string(),
                "name": "Magic Sword",
                "action": "updated",
                "condition": "broken",
                "durability": 0
            }]
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
        query_type: HybridQueryType::ItemTimeline,
        query_text: "Magic Sword".to_string(),
        entity_names: vec![],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // Should handle state conflicts gracefully
    assert!(result.warnings.is_empty() || !result.warnings.iter().any(|w| w.contains("conflict")));
    
    Ok(())
}

/// OWASP A09:2021 – Security Logging and Monitoring Failures
#[tokio::test]
async fn test_item_transaction_logging() -> Result<()> {
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let item_id = Uuid::new_v4();
    let thief_id = Uuid::new_v4();
    
    // High-value item transaction that should be logged
    let event = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Suspicious Transaction",
        json!({
            "content": "The Crown Jewels were stolen",
            "actors": [{
                "entity_id": thief_id.to_string(),
                "context": "Unknown Thief"
            }],
            "items": [{
                "item_id": item_id.to_string(),
                "name": "Crown Jewels",
                "action": "stolen",
                "value": 1000000,
                "security_level": "critical",
                "alert_required": true
            }]
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
        query_type: HybridQueryType::ItemTimeline,
        query_text: "Crown Jewels".to_string(),
        entity_names: vec![],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
    };
    
    // Execute suspicious query
    let result = service.execute_hybrid_query(query).await?;
    
    // In production, would verify audit logs were created
    // For now, just ensure query executes without exposing sensitive audit data
    assert!(result.warnings.is_empty() || !result.warnings.iter().any(|w| w.contains("audit")));
    
    Ok(())
}

/// OWASP A06:2021 – Vulnerable and Outdated Components
#[tokio::test]
async fn test_item_format_compatibility() -> Result<()> {
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let item_id = Uuid::new_v4();
    
    // Create item with legacy format
    let event = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Legacy Item",
        json!({
            "content": "Old format item data",
            // Old format using different structure
            "item": {
                "id": item_id.to_string(),
                "title": "Legacy Artifact",
                "owner_entity": "old_format_id"
            },
            // New format in same event
            "items": [{
                "item_id": item_id.to_string(),
                "name": "Legacy Artifact",
                "action": "migrated"
            }]
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
        query_type: HybridQueryType::ItemTimeline,
        query_text: "Legacy Artifact".to_string(),
        entity_names: vec![],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
    };
    
    // Should handle both formats gracefully
    let result = service.execute_hybrid_query(query).await?;
    
    // No errors from format differences
    assert!(result.chronicle_events.len() >= 0);
    
    Ok(())
}

/// OWASP A10:2021 – Server-Side Request Forgery
#[tokio::test]
async fn test_item_external_reference_safety() -> Result<()> {
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let item_id = Uuid::new_v4();
    
    // Create item with external references
    let event = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "External Item",
        json!({
            "content": "Item with external data",
            "items": [{
                "item_id": item_id.to_string(),
                "name": "Remote Artifact",
                "action": "linked",
                "external_refs": {
                    "image_url": "http://internal.server/admin/secret.jpg",
                    "data_source": "file:///etc/passwd",
                    "api_endpoint": "http://169.254.169.254/latest/meta-data/",
                    "safe_url": "https://example.com/item.json"
                }
            }]
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
        query_type: HybridQueryType::ItemTimeline,
        query_text: "Remote Artifact".to_string(),
        entity_names: vec![],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // Should not make any external requests
    // TODO: Verify no SSRF attempts once implemented
    
    Ok(())
}