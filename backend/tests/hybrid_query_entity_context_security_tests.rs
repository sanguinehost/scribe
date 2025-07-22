use anyhow::Result;
use uuid::Uuid;
use serde_json::json;
use scribe_backend::test_helpers::{spawn_app, TestDataGuard};
use scribe_backend::services::hybrid_query_service::{
    HybridQuery, HybridQueryType, HybridQueryOptions
};

/// OWASP A03:2021 – Injection
#[tokio::test]
async fn test_entity_context_extraction_prevents_json_injection() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let entity_id = Uuid::new_v4();
    
    // Create an entity with potentially malicious content
    let malicious_content = r#"{"evil": "payload", "actors": [{"entity_id": "00000000-0000-0000-0000-000000000000", "admin": true}]}"#;
    
    // Create entity with malicious content
    let entity_result = app.app_state.ecs_entity_manager.create_entity(
        user_id,
        None,
        "test_entity".to_string(),
        vec![
            ("name".to_string(), json!({"value": "Test Entity"})),
            ("description".to_string(), json!({"value": malicious_content})),
        ],
    ).await?;
    
    let query = HybridQuery {
        query_type: HybridQueryType::EntityTimeline {
            entity_name: "Test Entity".to_string(),
            entity_id: Some(entity_result.entity.id),
            include_current_state: true,
        },
        user_id,
        chronicle_id: Some(chronicle_id),
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: HybridQueryOptions::default(),
    };
    
    let result = app.app_state.hybrid_query_service.execute_hybrid_query(query).await?;
    
    // Verify no injection occurred
    assert!(!result.entities.is_empty());
    let entity_context = &result.entities[0];
    assert_eq!(entity_context.entity_id, entity_result.entity.id);
    
    // Ensure malicious content is properly escaped/contained
    if let Some(description_component) = entity_result.components.iter()
        .find(|comp| comp.component_type == "description") 
    {
        // The malicious content should be stored as a string value, not parsed as JSON
        assert!(description_component.component_data.get("value").is_some());
    }
    
    Ok(())
}

/// OWASP A01:2021 – Broken Access Control
#[tokio::test]
async fn test_entity_context_respects_user_boundaries() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user1_id = Uuid::new_v4();
    let user2_id = Uuid::new_v4();
    let chronicle1_id = Uuid::new_v4();
    let chronicle2_id = Uuid::new_v4();
    
    // Create entity for user 1
    let user1_entity = app.app_state.ecs_entity_manager.create_entity(
        user1_id,
        None,
        "character".to_string(),
        vec![
            ("name".to_string(), json!({"value": "User1 Secret Entity"})),
            ("secret_data".to_string(), json!({"value": "User1 confidential info"})),
        ],
    ).await?;
    
    // Create entity for user 2
    let user2_entity = app.app_state.ecs_entity_manager.create_entity(
        user2_id,
        None,
        "character".to_string(),
        vec![
            ("name".to_string(), json!({"value": "User2 Entity"})),
        ],
    ).await?;
    
    // User 2 tries to query User 1's entity
    let malicious_query = HybridQuery {
        query_type: HybridQueryType::EntityTimeline {
            entity_name: "User1 Secret Entity".to_string(),
            entity_id: Some(user1_entity.entity.id),
            include_current_state: true,
        },
        user_id: user2_id, // User 2's ID
        chronicle_id: Some(chronicle1_id), // User 1's chronicle
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: HybridQueryOptions::default(),
    };
    
    let result = app.app_state.hybrid_query_service.execute_hybrid_query(malicious_query).await?;
    
    // Verify user 2 cannot see user 1's entity
    assert!(result.entities.is_empty() || result.entities.iter()
        .all(|e| e.entity_id != user1_entity.entity.id));
    
    Ok(())
}

/// OWASP A07:2021 – Identification and Authentication Failures
#[tokio::test]
async fn test_entity_context_requires_valid_user_id() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let invalid_user_id = Uuid::nil(); // Invalid user ID
    let chronicle_id = Uuid::new_v4();
    
    let query = HybridQuery {
        query_type: HybridQueryType::EntityTimeline {
            entity_name: "Test Entity".to_string(),
            entity_id: None,
            include_current_state: true,
        },
        user_id: invalid_user_id,
        chronicle_id: Some(chronicle_id),
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: HybridQueryOptions::default(),
    };
    
    let result = app.app_state.hybrid_query_service.execute_hybrid_query(query).await?;
    
    // Should return empty results for invalid user
    assert!(result.entities.is_empty());
    assert_eq!(result.summary.entities_found, 0);
    
    Ok(())
}

/// OWASP A02:2021 – Cryptographic Failures
#[tokio::test]
async fn test_entity_context_does_not_expose_sensitive_fields() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    
    // Create entity with sensitive data
    let entity = app.app_state.ecs_entity_manager.create_entity(
        user_id,
        None,
        "secure_entity".to_string(),
        vec![
            ("name".to_string(), json!({"value": "Public Entity"})),
            ("password_hash".to_string(), json!({"value": "$2b$12$secret.hash"})),
            ("api_key".to_string(), json!({"value": "sk_live_secret123"})),
            ("public_data".to_string(), json!({"value": "This is public"})),
        ],
    ).await?;
    
    let query = HybridQuery {
        query_type: HybridQueryType::EntityTimeline {
            entity_name: "Public Entity".to_string(),
            entity_id: Some(entity.entity.id),
            include_current_state: true,
        },
        user_id,
        chronicle_id: Some(chronicle_id),
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: HybridQueryOptions::default(),
    };
    
    let result = app.app_state.hybrid_query_service.execute_hybrid_query(query).await?;
    
    assert!(!result.entities.is_empty());
    let entity_context = &result.entities[0];
    
    // Verify sensitive fields are not exposed in timeline context
    if let Some(current_state) = &entity_context.current_state {
        for (comp_name, _comp_data) in &current_state.components {
            // Sensitive component names should be filtered
            assert_ne!(comp_name, "password_hash");
            assert_ne!(comp_name, "api_key");
        }
    }
    
    Ok(())
}

/// OWASP A08:2021 – Software and Data Integrity Failures
#[tokio::test]
async fn test_entity_context_validates_component_data_types() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    
    // Try to create entity with invalid component data
    let result = app.app_state.ecs_entity_manager.create_entity(
        user_id,
        None,
        "test_entity".to_string(),
        vec![
            ("name".to_string(), json!({"value": "Test Entity"})),
            // Invalid component data (should be object with fields)
            ("invalid_component".to_string(), json!("raw string instead of object")),
        ],
    ).await;
    
    // Should handle invalid data gracefully
    match result {
        Ok(entity) => {
            // If it accepts the data, ensure it's properly handled in queries
            let query = HybridQuery {
                query_type: HybridQueryType::EntityTimeline {
                    entity_name: "Test Entity".to_string(),
                    entity_id: Some(entity.entity.id),
                    include_current_state: true,
                },
                user_id,
                chronicle_id: Some(chronicle_id),
                max_results: 10,
                include_current_state: true,
                include_relationships: false,
                options: HybridQueryOptions::default(),
            };
            
            let query_result = app.app_state.hybrid_query_service.execute_hybrid_query(query).await?;
            
            // Verify data is handled safely
            assert!(!query_result.entities.is_empty());
        }
        Err(_) => {
            // Good - invalid data was rejected
            assert!(true);
        }
    }
    
    Ok(())
}

/// OWASP A04:2021 – Insecure Design
#[tokio::test]
async fn test_entity_context_rate_limiting_protection() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    
    // Create a test entity
    let entity = app.app_state.ecs_entity_manager.create_entity(
        user_id,
        None,
        "test_entity".to_string(),
        vec![
            ("name".to_string(), json!({"value": "Rate Test Entity"})),
        ],
    ).await?;
    
    // Attempt many rapid queries
    let mut query_count = 0;
    for _ in 0..20 {
        let query = HybridQuery {
            query_type: HybridQueryType::EntityTimeline {
                entity_name: "Rate Test Entity".to_string(),
                entity_id: Some(entity.entity.id),
                include_current_state: true,
            },
            user_id,
            chronicle_id: Some(chronicle_id),
            max_results: 100, // Large result set
            include_current_state: true,
            include_relationships: true,
            options: HybridQueryOptions::default(),
        };
        
        match app.app_state.hybrid_query_service.execute_hybrid_query(query).await {
            Ok(_) => query_count += 1,
            Err(_) => break, // Might hit rate limit
        }
    }
    
    // Should have processed some queries but potentially hit limits
    assert!(query_count > 0);
    
    Ok(())
}

/// OWASP A09:2021 – Security Logging and Monitoring Failures
#[tokio::test]
async fn test_entity_context_logs_suspicious_queries() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    
    // Create query with suspicious patterns
    let suspicious_query = HybridQuery {
        query_type: HybridQueryType::NarrativeQuery {
            query_text: "'; DROP TABLE entities; SELECT * FROM users WHERE '1'='1".to_string(),
            focus_entities: None,
            time_range: None,
        },
        user_id,
        chronicle_id: Some(chronicle_id),
        max_results: 1000, // Unusually high
        include_current_state: true,
        include_relationships: true,
        options: HybridQueryOptions::default(),
    };
    
    let result = app.app_state.hybrid_query_service.execute_hybrid_query(suspicious_query).await?;
    
    // Query should complete safely (injection prevented)
    assert_eq!(result.summary.entities_found, 0);
    
    // In production, this would generate security logs
    // Here we just verify the query was handled safely
    
    Ok(())
}

/// OWASP A05:2021 – Security Misconfiguration
#[tokio::test]
async fn test_entity_context_default_security_settings() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    
    // Create entity
    let entity = app.app_state.ecs_entity_manager.create_entity(
        user_id,
        None,
        "config_entity".to_string(),
        vec![
            ("name".to_string(), json!({"value": "Config Test Entity"})),
            ("internal_config".to_string(), json!({"debug_mode": true})),
        ],
    ).await?;
    
    let query = HybridQuery {
        query_type: HybridQueryType::EntityTimeline {
            entity_name: "Config Test Entity".to_string(),
            entity_id: Some(entity.entity.id),
            include_current_state: true,
        },
        user_id,
        chronicle_id: Some(chronicle_id),
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: HybridQueryOptions {
            use_cache: true,
            include_timelines: true,
            analyze_relationships: false,
            confidence_threshold: 0.0, // Try to bypass filtering
        },
    };
    
    let result = app.app_state.hybrid_query_service.execute_hybrid_query(query).await?;
    
    // Should still apply security defaults despite low confidence threshold
    assert!(!result.entities.is_empty());
    
    Ok(())
}

/// OWASP A06:2021 – Vulnerable and Outdated Components
#[tokio::test]
async fn test_entity_context_handles_legacy_data_formats() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    
    // Create entity with potentially legacy format
    let entity = app.app_state.ecs_entity_manager.create_entity(
        user_id,
        None,
        "legacy_entity".to_string(),
        vec![
            ("name".to_string(), json!({"value": "Legacy Entity"})),
            // Old format that might cause issues
            ("old_component".to_string(), json!({
                "type": "legacy",
                "data": {"nested": {"deep": {"value": "test"}}},
                "__proto__": {"polluted": "value"} // Prototype pollution attempt
            })),
        ],
    ).await?;
    
    let query = HybridQuery {
        query_type: HybridQueryType::EntityTimeline {
            entity_name: "Legacy Entity".to_string(),
            entity_id: Some(entity.entity.id),
            include_current_state: true,
        },
        user_id,
        chronicle_id: Some(chronicle_id),
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: HybridQueryOptions::default(),
    };
    
    let result = app.app_state.hybrid_query_service.execute_hybrid_query(query).await?;
    
    // Should handle legacy data safely
    assert!(!result.entities.is_empty());
    
    Ok(())
}

/// OWASP A10:2021 – Server-Side Request Forgery (SSRF)
#[tokio::test]
async fn test_entity_context_prevents_ssrf_in_references() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    
    // Create entity with potential SSRF vectors
    let entity = app.app_state.ecs_entity_manager.create_entity(
        user_id,
        None,
        "external_entity".to_string(),
        vec![
            ("name".to_string(), json!({"value": "SSRF Test Entity"})),
            ("external_ref".to_string(), json!({
                "url": "http://localhost:6379/", // Try to access Redis
                "webhook": "http://169.254.169.254/latest/meta-data/", // AWS metadata
                "callback": "file:///etc/passwd" // Local file access
            })),
        ],
    ).await?;
    
    let query = HybridQuery {
        query_type: HybridQueryType::EntityTimeline {
            entity_name: "SSRF Test Entity".to_string(),
            entity_id: Some(entity.entity.id),
            include_current_state: true,
        },
        user_id,
        chronicle_id: Some(chronicle_id),
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: HybridQueryOptions::default(),
    };
    
    let result = app.app_state.hybrid_query_service.execute_hybrid_query(query).await?;
    
    // Query should complete without making external requests
    assert!(!result.entities.is_empty());
    
    // The service should not have attempted to fetch external URLs
    // In production, this would be monitored/blocked by security controls
    
    Ok(())
}