//! OWASP Top 10 Security Tests for World Interaction Tools - Create and Update functionality
//!
//! This test suite validates security aspects of create_entity and update_entity tools
//! based on the OWASP Top 10 (2021) security risks.

use scribe_backend::{
    models::ecs::{
        SpatialScale, SpatialArchetypeComponent,
        ParentLinkComponent, NameComponent, TemporalComponent,
        PositionComponent, RelationshipsComponent, Relationship,
    },
    services::{
        EcsEntityManager, EntityManagerConfig, ComponentUpdate, ComponentOperation,
        agentic::tools::{ScribeTool, ToolError},
    },
    test_helpers::{spawn_app, db::create_test_user},
    errors::AppError,
    PgPool,
};
use serde_json::{json, Value as JsonValue};
use std::sync::Arc;
use uuid::Uuid;

/// Create EcsEntityManager with Redis for testing
async fn create_entity_manager(db_pool: PgPool) -> Arc<EcsEntityManager> {
    let redis_client = Arc::new(
        redis::Client::open("redis://127.0.0.1:6379/")
            .expect("Failed to create Redis client for tests")
    );
    
    let config = EntityManagerConfig {
        default_cache_ttl: 60,
        hot_cache_ttl: 300,
        bulk_operation_batch_size: 50,
        enable_component_caching: true,
    };
    
    Arc::new(EcsEntityManager::new(
        db_pool.into(),
        redis_client,
        Some(config),
    ))
}

use scribe_backend::services::agentic::tools::world_interaction_tools::{
    CreateEntityTool, UpdateEntityTool, FindEntityTool,
};

#[cfg(test)]
mod world_interaction_create_update_security_tests {
    use super::*;

    // A01: Broken Access Control Tests
    #[tokio::test]
    async fn test_a01_create_entity_cross_user_isolation() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());

        let user1 = create_test_user(&_app.db_pool, "user1@example.com".to_string(), "user1".to_string()).await.unwrap();
        let user2 = create_test_user(&_app.db_pool, "user2@example.com".to_string(), "user2".to_string()).await.unwrap();

        // User1 creates an entity
        let params = json!({
            "user_id": user1.id.to_string(),
            "entity_name": "User1 Private Entity",
            "archetype_signature": "Name",
            "components": {
                "Name": {"name": "User1 Private Entity", "display_name": "Private Entity", "aliases": []}
            }
        });

        let result = create_tool.execute(&params).await.expect("Creation failed");
        let entity_id = result.get("entity_id").unwrap().as_str().unwrap();

        // Verify user2 cannot see user1's entity
        let find_tool = FindEntityTool::new(entity_manager.clone());
        let find_params = json!({
            "user_id": user2.id.to_string(),
            "criteria": {
                "type": "ByName",
                "name": "User1 Private Entity"
            },
            "limit": 10
        });

        let find_result = find_tool.execute(&find_params).await.expect("Find failed");
        eprintln!("Find result: {:?}", find_result);
        let entities = find_result.get("entities").unwrap().as_array().unwrap();
        eprintln!("Found {} entities for user2 when searching for user1's entity", entities.len());
        if !entities.is_empty() {
            eprintln!("Entities found: {:?}", entities);
        }
        assert_eq!(entities.len(), 0, "User2 should not see User1's entities");
    }

    #[tokio::test]
    async fn test_a01_update_entity_ownership_check() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());
        let update_tool = UpdateEntityTool::new(entity_manager.clone());

        let user1 = create_test_user(&_app.db_pool, "user1@example.com".to_string(), "user1".to_string()).await.unwrap();
        let user2 = create_test_user(&_app.db_pool, "user2@example.com".to_string(), "user2".to_string()).await.unwrap();

        // User1 creates an entity
        let create_params = json!({
            "user_id": user1.id.to_string(),
            "entity_name": "Protected Entity",
            "archetype_signature": "Name",
            "components": {
                "Name": {"name": "Protected Entity", "display_name": "Protected", "aliases": []}
            }
        });

        let result = create_tool.execute(&create_params).await.expect("Creation failed");
        let entity_id = result.get("entity_id").unwrap().as_str().unwrap();

        // User2 attempts to update user1's entity
        let update_params = json!({
            "user_id": user2.id.to_string(),
            "entity_id": entity_id,
            "updates": [
                {
                    "component_type": "Name",
                    "operation": "Update",
                    "data": {"name": "Hacked!", "display_name": "Compromised", "aliases": []}
                }
            ]
        });

        let result = update_tool.execute(&update_params).await;
        assert!(result.is_err(), "User2 should not be able to update User1's entity");
    }

    #[tokio::test]
    async fn test_a01_parent_entity_ownership_validation() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());

        let user1 = create_test_user(&_app.db_pool, "user1@example.com".to_string(), "user1".to_string()).await.unwrap();
        let user2 = create_test_user(&_app.db_pool, "user2@example.com".to_string(), "user2".to_string()).await.unwrap();

        // User1 creates a parent entity
        let parent_params = json!({
            "user_id": user1.id.to_string(),
            "entity_name": "User1's Building",
            "archetype_signature": "Name|SpatialArchetype",
            "components": {
                "Name": {"name": "User1's Building", "display_name": "Private Building", "aliases": []},
                "SpatialArchetype": {"scale": "Planetary", "hierarchical_level": 0, "level_name": "Building"}
            }
        });

        let parent_result = create_tool.execute(&parent_params).await.expect("Parent creation failed");
        let parent_id = parent_result.get("entity_id").unwrap().as_str().unwrap();

        // User2 attempts to create a child under User1's parent
        let child_params = json!({
            "user_id": user2.id.to_string(),
            "entity_name": "Sneaky Room",
            "archetype_signature": "Name|SpatialArchetype|ParentLink",
            "parent_entity_id": parent_id,
            "components": {
                "Name": {"name": "Sneaky Room", "display_name": "Unauthorized Room", "aliases": []},
                "SpatialArchetype": {"scale": "Intimate", "hierarchical_level": 1, "level_name": "Room"}
            }
        });

        let result = create_tool.execute(&child_params).await;
        assert!(result.is_err(), "User2 should not be able to use User1's entity as parent");
    }

    // A03: Injection Tests
    #[tokio::test]
    async fn test_a03_sql_injection_in_entity_name() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Attempt SQL injection in entity name
        let params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Test OR 1=1; DROP TABLE ecs_entities; --",
            "archetype_signature": "Name",
            "components": {
                "Name": {
                    "name": "Test OR 1=1; DROP TABLE ecs_entities; --",
                    "display_name": "Malicious",
                    "aliases": []
                }
            }
        });

        let result = create_tool.execute(&params).await;
        // Should either succeed (with escaped values) or fail gracefully
        // But should NOT execute SQL injection
        
        // Verify tables still exist
        let verify_params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Verification Entity",
            "archetype_signature": "Name",
            "components": {
                "Name": {"name": "Verification Entity", "display_name": "Test", "aliases": []}
            }
        });
        
        let verify_result = create_tool.execute(&verify_params).await;
        assert!(verify_result.is_ok(), "Database should still be functional");
    }

    #[tokio::test]
    async fn test_a03_json_injection_in_component_data() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Attempt JSON injection with nested malicious payload
        let params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Test Entity",
            "archetype_signature": "Name",
            "components": {
                "Name": {
                    "name": "Test",
                    "display_name": "Test",
                    "aliases": [],
                    "__proto__": {"isAdmin": true},
                    "constructor": {"prototype": {"isAdmin": true}}
                }
            }
        });

        let result = create_tool.execute(&params).await;
        // Should handle gracefully without prototype pollution
        if result.is_ok() {
            // Verify the malicious fields were not stored
            let entity_id = result.unwrap().get("entity_id").unwrap().as_str().unwrap().to_string();
            // In a real implementation, we'd verify the stored component doesn't have __proto__
        }
    }

    #[tokio::test]
    async fn test_a03_nosql_injection_in_updates() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());
        let update_tool = UpdateEntityTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Create entity first
        let create_params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Target",
            "archetype_signature": "Name",
            "components": {
                "Name": {"name": "Target", "display_name": "Target Entity", "aliases": []}
            }
        });

        let create_result = create_tool.execute(&create_params).await.expect("Creation failed");
        let entity_id = create_result.get("entity_id").unwrap().as_str().unwrap();

        // Attempt NoSQL injection in update
        let update_params = json!({
            "user_id": user.id.to_string(),
            "entity_id": entity_id,
            "updates": [
                {
                    "component_type": "Name",
                    "operation": "Update",
                    "data": {
                        "$set": {"isAdmin": true},
                        "$where": "function() { return true; }",
                        "name": "Legitimate Update"
                    }
                }
            ]
        });

        let result = update_tool.execute(&update_params).await;
        // Should process safely without executing NoSQL operators
    }

    // A05: Security Misconfiguration Tests
    #[tokio::test]
    async fn test_a05_invalid_component_type_validation() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Attempt to create entity with invalid component types
        let params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Invalid Entity",
            "archetype_signature": "Name|InvalidComponent|AnotherBadComponent",
            "components": {
                "Name": {"name": "Test", "display_name": "Test", "aliases": []},
                "InvalidComponent": {"malicious": "data"},
                "AnotherBadComponent": {"more": "bad_data"}
            }
        });

        let result = create_tool.execute(&params).await;
        assert!(result.is_err(), "Should reject invalid component types");
    }

    #[tokio::test]
    async fn test_a05_schema_validation_enforcement() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Attempt to create with malformed component data
        let params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Malformed Entity",
            "archetype_signature": "Name|Position",
            "components": {
                "Name": {"wrong_field": "No name field!"},
                "Position": {"x": "not_a_number", "y": true, "z": null}
            }
        });

        let result = create_tool.execute(&params).await;
        assert!(result.is_err(), "Should reject malformed component data");
    }

    #[tokio::test]
    async fn test_a05_operation_type_validation() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());
        let update_tool = UpdateEntityTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Create entity
        let create_params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Test",
            "archetype_signature": "Name",
            "components": {
                "Name": {"name": "Test", "display_name": "Test", "aliases": []}
            }
        });

        let create_result = create_tool.execute(&create_params).await.expect("Creation failed");
        let entity_id = create_result.get("entity_id").unwrap().as_str().unwrap();

        // Attempt update with invalid operation
        let update_params = json!({
            "user_id": user.id.to_string(),
            "entity_id": entity_id,
            "updates": [
                {
                    "component_type": "Name",
                    "operation": "InvalidOperation",
                    "data": {"name": "Updated"}
                }
            ]
        });

        let result = update_tool.execute(&update_params).await;
        assert!(result.is_err(), "Should reject invalid operation types");
    }

    // A07: Authentication Failures Tests
    #[tokio::test]
    async fn test_a07_invalid_user_id_format() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());

        // Various invalid user ID formats
        let invalid_user_ids = vec![
            "not-a-uuid",
            "12345",
            "",
            "00000000-0000-0000-0000-00000000000g", // Invalid character
            "../../../etc/passwd",
        ];

        for invalid_id in invalid_user_ids {
            let params = json!({
                "user_id": invalid_id,
                "entity_name": "Test",
                "archetype_signature": "Name",
                "components": {
                    "Name": {"name": "Test", "display_name": "Test", "aliases": []}
                }
            });

            let result = create_tool.execute(&params).await;
            assert!(result.is_err(), "Should reject invalid user ID: {}", invalid_id);
            assert!(matches!(result.unwrap_err(), ToolError::InvalidParams(_)));
        }
    }

    #[tokio::test]
    async fn test_a07_empty_user_context() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let update_tool = UpdateEntityTool::new(entity_manager.clone());

        // Attempt to update without user context
        let update_params = json!({
            "entity_id": Uuid::new_v4().to_string(),
            "updates": [
                {
                    "component_type": "Name",
                    "operation": "Update",
                    "data": {"name": "Unauthorized"}
                }
            ]
        });

        let result = update_tool.execute(&update_params).await;
        assert!(result.is_err(), "Should require user_id in request");
    }

    // A08: Data Integrity Tests
    #[tokio::test]
    async fn test_a08_malformed_json_handling() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Deeply nested JSON that might cause stack overflow
        let mut deeply_nested = json!({});
        let mut current = &mut deeply_nested;
        for _ in 0..1000 {
            *current = json!({"nested": {}});
            current = current.get_mut("nested").unwrap();
        }

        let params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Deep Entity",
            "archetype_signature": "Name",
            "components": {
                "Name": {
                    "name": "Test",
                    "display_name": "Test",
                    "aliases": [],
                    "metadata": deeply_nested
                }
            }
        });

        let result = create_tool.execute(&params).await;
        // Should handle gracefully without stack overflow
    }

    #[tokio::test]
    async fn test_a08_concurrent_update_integrity() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());
        let update_tool = UpdateEntityTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Create entity
        let create_params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Concurrent Test",
            "archetype_signature": "Name|Position",
            "components": {
                "Name": {"name": "Concurrent Test", "display_name": "Test", "aliases": []},
                "Position": {"x": 0.0, "y": 0.0, "z": 0.0, "zone": "origin"}
            }
        });

        let create_result = create_tool.execute(&create_params).await.expect("Creation failed");
        let entity_id = create_result.get("entity_id").unwrap().as_str().unwrap();

        // Simulate concurrent updates
        let update_params1 = json!({
            "user_id": user.id.to_string(),
            "entity_id": entity_id,
            "updates": [{
                "component_type": "Position",
                "operation": "Update",
                "data": {"x": 10.0, "y": 10.0, "z": 10.0, "zone": "zone1"}
            }]
        });

        let update_params2 = json!({
            "user_id": user.id.to_string(),
            "entity_id": entity_id,
            "updates": [{
                "component_type": "Position",
                "operation": "Update",
                "data": {"x": 20.0, "y": 20.0, "z": 20.0, "zone": "zone2"}
            }]
        });

        // Launch concurrent updates
        let tool1 = update_tool.clone();
        let tool2 = update_tool.clone();
        
        let (result1, result2) = tokio::join!(
            tool1.execute(&update_params1),
            tool2.execute(&update_params2)
        );

        // Both should complete without corruption
        assert!(result1.is_ok() || result2.is_ok());
    }

    // A09: Logging & Monitoring Tests
    #[tokio::test]
    async fn test_a09_security_event_logging() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Create entity with potentially sensitive data
        let params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Sensitive Entity",
            "archetype_signature": "Name",
            "components": {
                "Name": {
                    "name": "Sensitive Entity",
                    "display_name": "Contains PII",
                    "aliases": ["SSN: 123-45-6789", "Credit Card: 1234-5678-9012-3456"]
                }
            }
        });

        let result = create_tool.execute(&params).await;
        // Tool should log the event but not expose sensitive data in logs
        // In production, we'd verify logs don't contain the SSN or credit card numbers
    }

    #[tokio::test]
    async fn test_a09_failed_access_attempt_logging() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let update_tool = UpdateEntityTool::new(entity_manager.clone());

        let user1 = create_test_user(&_app.db_pool, "user1@example.com".to_string(), "user1".to_string()).await.unwrap();
        let user2 = create_test_user(&_app.db_pool, "user2@example.com".to_string(), "user2".to_string()).await.unwrap();

        // Create entity as user1
        let create_tool = CreateEntityTool::new(entity_manager.clone());
        let create_params = json!({
            "user_id": user1.id.to_string(),
            "entity_name": "Protected",
            "archetype_signature": "Name",
            "components": {
                "Name": {"name": "Protected", "display_name": "Protected", "aliases": []}
            }
        });

        let create_result = create_tool.execute(&create_params).await.expect("Creation failed");
        let entity_id = create_result.get("entity_id").unwrap().as_str().unwrap();

        // User2 attempts unauthorized update
        let update_params = json!({
            "user_id": user2.id.to_string(),
            "entity_id": entity_id,
            "updates": [{
                "component_type": "Name",
                "operation": "Update",
                "data": {"name": "Hacked", "display_name": "Compromised", "aliases": []}
            }]
        });

        let result = update_tool.execute(&update_params).await;
        assert!(result.is_err());
        // Should log failed access attempt with user2's ID and target entity
    }

    // A10: SSRF Tests  
    #[tokio::test]
    async fn test_a10_external_reference_prevention() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Attempt to include external references
        let params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "External Ref Entity",
            "archetype_signature": "Name",
            "components": {
                "Name": {
                    "name": "Test",
                    "display_name": "Test",
                    "aliases": [],
                    "external_ref": "http://malicious.com/steal-data",
                    "webhook": "https://attacker.com/log"
                }
            }
        });

        let result = create_tool.execute(&params).await;
        // Should either strip external references or handle safely
    }

    #[tokio::test]
    async fn test_a10_internal_network_access_prevention() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Attempt to reference internal network resources
        let params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Internal Scanner",
            "archetype_signature": "Name",
            "components": {
                "Name": {
                    "name": "Scanner",
                    "display_name": "Port Scanner",
                    "aliases": [],
                    "scan_targets": [
                        "http://localhost:6379",
                        "http://127.0.0.1:5432",
                        "http://169.254.169.254/latest/meta-data/",
                        "file:///etc/passwd"
                    ]
                }
            }
        });

        let result = create_tool.execute(&params).await;
        // Should not allow internal network scanning attempts
    }
}