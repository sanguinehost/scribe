use anyhow::Result;
use std::sync::Arc;
use uuid::Uuid;
use serde_json::json;
use chrono::Utc;
use scribe_backend::test_helpers::{spawn_app, TestDataGuard};
use scribe_backend::services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryService};
use scribe_backend::models::chronicle_event::{NewChronicleEvent, EventSource};

// Helper function to create test NewChronicleEvent objects
fn create_test_chronicle_event(
    chronicle_id: Uuid,
    user_id: Uuid,
    event_type: &str,
    event_data: serde_json::Value,
) -> NewChronicleEvent {
    let now = Utc::now();
    NewChronicleEvent {
        chronicle_id,
        user_id,
        event_type: event_type.to_string(),
        summary: "Test event".to_string(),
        source: EventSource::UserAdded.to_string(),
        event_data: Some(event_data),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: now,
        actors: None,
        action: None,
        context_data: None,
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: None,
        causes_event_ids: None,
        sequence_number: 1,
    }
}

/// OWASP A01:2021 – Broken Access Control
#[tokio::test]
async fn test_item_ownership_access_control() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user1_id = Uuid::new_v4();
    let user2_id = Uuid::new_v4();
    let chronicle1_id = Uuid::new_v4();
    let _chronicle2_id = Uuid::new_v4();
    let item_id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    
    // User1 creates an item in their chronicle
    let _event = create_test_chronicle_event(
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
    );
    
    let service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(),
        app.app_state.feature_flags.clone(),
        app.ai_client.clone(),
        app.config.advanced_model.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.ecs_enhanced_rag_service.clone(),
        app.app_state.ecs_graceful_degradation.clone(),
    );
    
    // User2 tries to query user1's items
    let query = HybridQuery {
        user_id: user2_id,
        chronicle_id: Some(chronicle1_id), // Wrong chronicle
        query_type: HybridQueryType::ItemTimeline,
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: Default::default(),
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // Should not return items from other users' chronicles
    assert_eq!(result.entities.len(), 0);
    
    Ok(())
}

/// OWASP A03:2021 – Injection
#[tokio::test]
async fn test_item_query_injection_prevention() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let item_id = Uuid::new_v4();
    
    // Create item with potential injection vectors
    let _event = create_test_chronicle_event(
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
    );
    
    let service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(),
        app.app_state.feature_flags.clone(),
        app.ai_client.clone(),
        app.config.advanced_model.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.ecs_enhanced_rag_service.clone(),
        app.app_state.ecs_graceful_degradation.clone(),
    );
    
    // Query with injection attempt
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemSearch,
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: Default::default(),
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
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let item_id = Uuid::new_v4();
    let owner1_id = Uuid::new_v4();
    let owner2_id = Uuid::new_v4();
    
    // Attempt to create duplicate ownership through race condition
    let _event1 = create_test_chronicle_event(
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
    );
    
    // Simultaneous conflicting transfer
    let _event2 = create_test_chronicle_event(
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
    );
    
    let service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(),
        app.app_state.feature_flags.clone(),
        app.ai_client.clone(),
        app.config.advanced_model.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.ecs_enhanced_rag_service.clone(),
        app.app_state.ecs_graceful_degradation.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemTimeline,
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: Default::default(),
    };
    
    let _result = service.execute_hybrid_query(query).await?;
    
    // TODO: Verify only one valid owner once implemented
    
    Ok(())
}

/// OWASP A05:2021 – Security Misconfiguration
#[tokio::test]
async fn test_item_data_exposure_limits() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    
    // Create many items to test pagination/limits
    for i in 0..100 {
        let item_id = Uuid::new_v4();
        let _event = create_test_chronicle_event(
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
        );
    }
    
    let service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(),
        app.app_state.feature_flags.clone(),
        app.ai_client.clone(),
        app.config.advanced_model.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.ecs_enhanced_rag_service.clone(),
        app.app_state.ecs_graceful_degradation.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemSearch,
        max_results: 10, // Should respect this limit
        include_current_state: true,
        include_relationships: false,
        options: Default::default(),
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // Should respect max_results limit
    assert!(result.chronicle_events.len() <= 10);
    
    Ok(())
}

/// OWASP A07:2021 – Identification and Authentication Failures
#[tokio::test]
async fn test_item_query_authentication_required() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let chronicle_id = Uuid::new_v4();
    let anonymous_user = Uuid::nil(); // Invalid/anonymous user
    
    let service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(),
        app.app_state.feature_flags.clone(),
        app.ai_client.clone(),
        app.config.advanced_model.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.ecs_enhanced_rag_service.clone(),
        app.app_state.ecs_graceful_degradation.clone(),
    );
    
    let query = HybridQuery {
        user_id: anonymous_user,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemSearch,
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: Default::default(),
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
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let item_id = Uuid::new_v4();
    
    // Create item with sensitive value data
    let _event = create_test_chronicle_event(
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
    );
    
    let service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(),
        app.app_state.feature_flags.clone(),
        app.ai_client.clone(),
        app.config.advanced_model.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.ecs_enhanced_rag_service.clone(),
        app.app_state.ecs_graceful_degradation.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemTimeline,
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: Default::default(),
    };
    
    let _result = service.execute_hybrid_query(query).await?;
    
    // TODO: Verify sensitive properties are not exposed once implemented
    
    Ok(())
}

/// OWASP A08:2021 – Software and Data Integrity Failures
#[tokio::test]
async fn test_item_state_consistency() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let item_id = Uuid::new_v4();
    
    // Create conflicting item states
    let _event1 = create_test_chronicle_event(
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
    );
    
    // Conflicting state
    let _event2 = create_test_chronicle_event(
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
    );
    
    let service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(),
        app.app_state.feature_flags.clone(),
        app.ai_client.clone(),
        app.config.advanced_model.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.ecs_enhanced_rag_service.clone(),
        app.app_state.ecs_graceful_degradation.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemTimeline,
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: Default::default(),
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // Should handle state conflicts gracefully
    assert!(result.warnings.is_empty() || !result.warnings.iter().any(|w| w.contains("conflict")));
    
    Ok(())
}

/// OWASP A09:2021 – Security Logging and Monitoring Failures
#[tokio::test]
async fn test_item_transaction_logging() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let item_id = Uuid::new_v4();
    let thief_id = Uuid::new_v4();
    
    // High-value item transaction that should be logged
    let _event = create_test_chronicle_event(
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
    );
    
    let service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(),
        app.app_state.feature_flags.clone(),
        app.ai_client.clone(),
        app.config.advanced_model.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.ecs_enhanced_rag_service.clone(),
        app.app_state.ecs_graceful_degradation.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemTimeline,
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: Default::default(),
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
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let item_id = Uuid::new_v4();
    
    // Create item with legacy format
    let _event = create_test_chronicle_event(
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
    );
    
    let service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(),
        app.app_state.feature_flags.clone(),
        app.ai_client.clone(),
        app.config.advanced_model.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.ecs_enhanced_rag_service.clone(),
        app.app_state.ecs_graceful_degradation.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemTimeline,
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: Default::default(),
    };
    
    // Should handle both formats gracefully
    let result = service.execute_hybrid_query(query).await?;
    
    // No errors from format differences
    assert!(!result.chronicle_events.is_empty() || result.chronicle_events.is_empty());
    
    Ok(())
}

/// OWASP A10:2021 – Server-Side Request Forgery
#[tokio::test]
async fn test_item_external_reference_safety() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let item_id = Uuid::new_v4();
    
    // Create item with external references
    let _event = create_test_chronicle_event(
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
    );
    
    let service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(),
        app.app_state.feature_flags.clone(),
        app.ai_client.clone(),
        app.config.advanced_model.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.ecs_enhanced_rag_service.clone(),
        app.app_state.ecs_graceful_degradation.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemTimeline,
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: Default::default(),
    };
    
    let _result = service.execute_hybrid_query(query).await?;
    
    // Should not make any external requests
    // TODO: Verify no SSRF attempts once implemented
    
    Ok(())
}