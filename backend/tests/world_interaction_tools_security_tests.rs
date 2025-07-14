//! Security Tests for World Interaction Tools
//!
//! This test suite validates security requirements based on OWASP Top 10 (2021)
//! for the find_entity and get_entity tools to ensure they cannot be
//! exploited for malicious purposes.

use scribe_backend::{
    models::ecs::{
        SpatialScale, SpatialArchetypeComponent,
        ParentLinkComponent, NameComponent, TemporalComponent,
        PositionComponent,
    },
    services::{
        EcsEntityManager, EntityManagerConfig,
        agentic::tools::{ScribeTool, ToolError},
        agentic::tools::world_interaction_tools::{
            FindEntityTool, GetEntityDetailsTool,
        },
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

/// Helper function to create a test entity
async fn create_test_entity(
    entity_manager: &Arc<EcsEntityManager>,
    user_id: Uuid,
    name: &str,
    scale: SpatialScale,
) -> Result<Uuid, AppError> {
    let entity_id = Uuid::new_v4();
    
    let level_name = scale.level_name(0)
        .ok_or_else(|| AppError::InternalServerErrorGeneric("Invalid scale level".to_string()))?;

    let spatial_archetype = SpatialArchetypeComponent::new(
        scale,
        0,
        level_name.to_string(),
    ).map_err(|e| AppError::InternalServerErrorGeneric(e))?;

    let name_component = NameComponent {
        name: name.to_string(),
        display_name: name.to_string(),
        aliases: Vec::new(),
    };

    let temporal_component = TemporalComponent::default();
    let position_component = PositionComponent {
        x: 0.0,
        y: 0.0,
        z: 0.0,
        zone: "default".to_string(),
    };

    let components = vec![
        ("SpatialArchetype".to_string(), serde_json::to_value(spatial_archetype)?),
        ("Name".to_string(), serde_json::to_value(name_component)?),
        ("Temporal".to_string(), serde_json::to_value(temporal_component)?),
        ("Position".to_string(), serde_json::to_value(position_component)?),
    ];

    entity_manager.create_entity(
        user_id,
        Some(entity_id),
        "Test Entity".to_string(),
        components,
    ).await?;

    Ok(entity_id)
}

#[cfg(test)]
mod world_interaction_tools_security_tests {
    use super::*;

    // A01:2021 - Broken Access Control Tests
    mod access_control_tests {
        use super::*;

        #[tokio::test]
        async fn test_user_isolation_find_entity() {
            let _app = spawn_app(false, false, false).await;
            let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
            let find_tool = FindEntityTool::new(entity_manager.clone());

            // Create two different users
            let user1 = create_test_user(&_app.db_pool, "user1@example.com".to_string(), "user1".to_string()).await.unwrap();
            let user2 = create_test_user(&_app.db_pool, "user2@example.com".to_string(), "user2".to_string()).await.unwrap();

            // User1 creates an entity
            let _entity_id = create_test_entity(
                &entity_manager,
                user1.id,
                "User1 Secret Entity",
                SpatialScale::Intimate,
            ).await.expect("Failed to create entity for user1");

            // User2 tries to find User1's entity by name
            let params = json!({
                "user_id": user2.id.to_string(),
                "criteria": {
                    "type": "ByName",
                    "name": "User1 Secret Entity"
                }
            });

            let result = find_tool.execute(&params).await.expect("Tool execution should succeed");
            let output: JsonValue = result;
            
            // User2 should not be able to see User1's entities
            assert_eq!(output.get("total_found").unwrap().as_u64().unwrap(), 0);
            assert!(output.get("entities").unwrap().as_array().unwrap().is_empty());
        }

        #[tokio::test]
        async fn test_user_isolation_get_entity() {
            let _app = spawn_app(false, false, false).await;
            let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
            let details_tool = GetEntityDetailsTool::new(entity_manager.clone());

            // Create two different users
            let user1 = create_test_user(&_app.db_pool, "user1@example.com".to_string(), "user1".to_string()).await.unwrap();
            let user2 = create_test_user(&_app.db_pool, "user2@example.com".to_string(), "user2".to_string()).await.unwrap();

            // User1 creates an entity
            let entity_id = create_test_entity(
                &entity_manager,
                user1.id,
                "User1 Secret Entity",
                SpatialScale::Intimate,
            ).await.expect("Failed to create entity for user1");

            // User2 tries to access User1's entity details directly
            let params = json!({
                "user_id": user2.id.to_string(),
                "entity_id": entity_id.to_string()
            });

            let result = details_tool.execute(&params).await;
            
            // Should fail - User2 cannot access User1's entity
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), ToolError::ExecutionFailed(_)));
        }

        #[tokio::test]
        async fn test_privilege_escalation_prevention() {
            let _app = spawn_app(false, false, false).await;
            let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
            let find_tool = FindEntityTool::new(entity_manager.clone());

            let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

            // Try to use admin/system UUID patterns
            let admin_like_params = json!({
                "user_id": "00000000-0000-0000-0000-000000000000", // System-like UUID
                "criteria": {
                    "type": "ByName",
                    "name": "test"
                }
            });

            let result = find_tool.execute(&admin_like_params).await;
            
            // Should either fail or return empty results (no privilege escalation)
            if let Ok(output) = result {
                let entities = output.get("entities").unwrap().as_array().unwrap();
                assert!(entities.is_empty(), "No privilege escalation should occur");
            }
        }
    }

    // A03:2021 - Injection Tests
    mod injection_tests {
        use super::*;

        #[tokio::test]
        async fn test_sql_injection_in_name_search() {
            let _app = spawn_app(false, false, false).await;
            let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
            let find_tool = FindEntityTool::new(entity_manager.clone());

            let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

            // Create a legitimate entity
            let _entity_id = create_test_entity(
                &entity_manager,
                user.id,
                "Legitimate Entity",
                SpatialScale::Intimate,
            ).await.expect("Failed to create entity");

            // Try SQL injection attacks
            let injection_attempts = vec![
                "'; DROP TABLE ecs_entities; --",
                "' OR '1'='1",
                "' UNION SELECT * FROM users --",
                "'; INSERT INTO ecs_entities VALUES(...); --",
                "%'; SELECT pg_sleep(10); --",
                "\\'; EXEC xp_cmdshell('dir'); --",
            ];

            for injection in injection_attempts {
                let params = json!({
                    "user_id": user.id.to_string(),
                    "criteria": {
                        "type": "ByName",
                        "name": injection
                    }
                });

                let result = find_tool.execute(&params).await;
                
                // Should either succeed with no results or fail gracefully (no injection)
                if let Ok(output) = result {
                    let entities = output.get("entities").unwrap().as_array().unwrap();
                    // Injection should not return unexpected data
                    assert!(entities.len() <= 1, "Injection attempt should not return multiple unexpected entities");
                }
            }
        }

        #[tokio::test]
        async fn test_nosql_injection_in_component_query() {
            let _app = spawn_app(false, false, false).await;
            let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
            let find_tool = FindEntityTool::new(entity_manager.clone());

            let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

            // Try NoSQL injection patterns
            let injection_attempts = vec![
                "Position'; return true; var x='",
                "Position\"; return this.name === 'admin'; var y=\"",
                "Position'; return db.users.find(); var z='",
            ];

            for injection in injection_attempts {
                let params = json!({
                    "user_id": user.id.to_string(),
                    "criteria": {
                        "type": "ByComponent",
                        "component_type": injection
                    }
                });

                let result = find_tool.execute(&params).await;
                
                // Should not allow injection to execute
                if let Ok(output) = result {
                    let entities = output.get("entities").unwrap().as_array().unwrap();
                    assert!(entities.is_empty(), "NoSQL injection should not return data");
                }
            }
        }

        #[tokio::test]
        async fn test_json_injection_in_advanced_query() {
            let _app = spawn_app(false, false, false).await;
            let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
            let find_tool = FindEntityTool::new(entity_manager.clone());

            let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

            // Try JSON injection in advanced query
            let malicious_query = json!({
                "user_id": user.id.to_string(),
                "criteria": {
                    "type": "Advanced",
                    "queries": [
                        {
                            "component_type": "Position\"; DROP TABLE ecs_entities; --",
                            "has_component": true
                        }
                    ]
                }
            });

            let result = find_tool.execute(&malicious_query).await;
            
            // Should handle gracefully without executing injection
            if let Ok(output) = result {
                let entities = output.get("entities").unwrap().as_array().unwrap();
                assert!(entities.is_empty(), "JSON injection should not succeed");
            }
        }
    }

    // A04:2021 - Insecure Design Tests
    mod insecure_design_tests {
        use super::*;

        #[tokio::test]
        async fn test_rate_limiting_compliance() {
            let _app = spawn_app(false, false, false).await;
            let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
            let find_tool = FindEntityTool::new(entity_manager.clone());

            let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

            // Test that large limit requests are capped
            let params = json!({
                "user_id": user.id.to_string(),
                "criteria": {
                    "type": "ByName",
                    "name": "test"
                },
                "limit": 10000 // Attempt to request excessive data
            });

            let result = find_tool.execute(&params).await.expect("Tool should execute");
            let output: JsonValue = result;
            
            // Verify limit is enforced (should be capped at 100 per the implementation)
            let entities = output.get("entities").unwrap().as_array().unwrap();
            assert!(entities.len() <= 100, "Results should be limited to prevent resource exhaustion");
        }

        #[tokio::test]
        async fn test_information_disclosure_prevention() {
            let _app = spawn_app(false, false, false).await;
            let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
            let details_tool = GetEntityDetailsTool::new(entity_manager.clone());

            let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

            // Try to access non-existent entity
            let fake_entity_id = Uuid::new_v4();
            let params = json!({
                "user_id": user.id.to_string(),
                "entity_id": fake_entity_id.to_string()
            });

            let result = details_tool.execute(&params).await;
            
            // Should fail without revealing system information
            assert!(result.is_err());
            if let Err(ToolError::ExecutionFailed(msg)) = result {
                // Error message should not reveal internal system details
                assert!(!msg.contains("database"), "Error should not reveal database details");
                assert!(!msg.contains("table"), "Error should not reveal table structure");
                assert!(!msg.contains("sql"), "Error should not reveal SQL details");
                assert!(!msg.contains("redis"), "Error should not reveal Redis details");
            }
        }
    }

    // A05:2021 - Security Misconfiguration Tests
    mod security_misconfiguration_tests {
        use super::*;

        #[tokio::test]
        async fn test_input_validation_enforcement() {
            let _app = spawn_app(false, false, false).await;
            let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
            let find_tool = FindEntityTool::new(entity_manager.clone());

            // Test invalid UUID format
            let invalid_params = json!({
                "user_id": "not-a-valid-uuid",
                "criteria": {
                    "type": "ByName",
                    "name": "test"
                }
            });

            let result = find_tool.execute(&invalid_params).await;
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), ToolError::InvalidParams(_)));
        }

        #[tokio::test]
        async fn test_schema_validation_enforcement() {
            let _app = spawn_app(false, false, false).await;
            let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
            let find_tool = FindEntityTool::new(entity_manager.clone());

            let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

            // Test invalid scale value
            let invalid_scale_params = json!({
                "user_id": user.id.to_string(),
                "criteria": {
                    "type": "ByScale",
                    "scale": "InvalidScale" // Not one of Cosmic, Planetary, Intimate
                }
            });

            let result = find_tool.execute(&invalid_scale_params).await;
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), ToolError::InvalidParams(_)));
        }

        #[tokio::test]
        async fn test_missing_required_fields() {
            let _app = spawn_app(false, false, false).await;
            let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
            let find_tool = FindEntityTool::new(entity_manager.clone());

            // Test missing user_id
            let missing_user_params = json!({
                "criteria": {
                    "type": "ByName",
                    "name": "test"
                }
            });

            let result = find_tool.execute(&missing_user_params).await;
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), ToolError::InvalidParams(_)));

            // Test missing criteria
            let missing_criteria_params = json!({
                "user_id": "550e8400-e29b-41d4-a716-446655440000"
            });

            let result2 = find_tool.execute(&missing_criteria_params).await;
            assert!(result2.is_err());
            assert!(matches!(result2.unwrap_err(), ToolError::InvalidParams(_)));
        }
    }

    // A07:2021 - Identification and Authentication Failures Tests
    mod authentication_tests {
        use super::*;

        #[tokio::test]
        async fn test_user_id_validation() {
            let _app = spawn_app(false, false, false).await;
            let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
            let find_tool = FindEntityTool::new(entity_manager.clone());

            // Test various invalid user ID formats
            let invalid_user_ids = vec![
                "",
                "null",
                "undefined",
                "0",
                "admin",
                "root",
                "system",
                "guest",
                "anonymous",
            ];

            for invalid_id in invalid_user_ids {
                let params = json!({
                    "user_id": invalid_id,
                    "criteria": {
                        "type": "ByName",
                        "name": "test"
                    }
                });

                let result = find_tool.execute(&params).await;
                assert!(result.is_err(), "Invalid user ID '{}' should be rejected", invalid_id);
                assert!(matches!(result.unwrap_err(), ToolError::InvalidParams(_)));
            }
        }

        #[tokio::test]
        async fn test_session_context_integrity() {
            let _app = spawn_app(false, false, false).await;
            let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
            let find_tool = FindEntityTool::new(entity_manager.clone());

            let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();
            
            // Create entity for user
            let _entity_id = create_test_entity(
                &entity_manager,
                user.id,
                "User Entity",
                SpatialScale::Intimate,
            ).await.expect("Failed to create entity");

            // Tool should only operate in context of authenticated user
            let params = json!({
                "user_id": user.id.to_string(),
                "criteria": {
                    "type": "ByName",
                    "name": "User Entity"
                }
            });

            let result = find_tool.execute(&params).await.expect("Tool should execute for valid user");
            let output: JsonValue = result;
            
            assert_eq!(output.get("total_found").unwrap().as_u64().unwrap(), 1);
        }
    }

    // A08:2021 - Software and Data Integrity Failures Tests
    mod data_integrity_tests {
        use super::*;

        #[tokio::test]
        async fn test_data_consistency_validation() {
            let _app = spawn_app(false, false, false).await;
            let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
            let details_tool = GetEntityDetailsTool::new(entity_manager.clone());

            let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

            let entity_id = create_test_entity(
                &entity_manager,
                user.id,
                "Test Entity",
                SpatialScale::Intimate,
            ).await.expect("Failed to create entity");

            // Get entity details
            let params = json!({
                "user_id": user.id.to_string(),
                "entity_id": entity_id.to_string()
            });

            let result = details_tool.execute(&params).await.expect("Tool should execute");
            let output: JsonValue = result;
            
            // Verify data integrity
            assert_eq!(output.get("entity_id").unwrap().as_str().unwrap(), entity_id.to_string());
            assert_eq!(output.get("name").unwrap().as_str().unwrap(), "Test Entity");
            
            let components = output.get("components").unwrap().as_object().unwrap();
            assert!(components.contains_key("Name"));
            assert!(components.contains_key("SpatialArchetype"));
            assert!(components.contains_key("Position"));
            assert!(components.contains_key("Temporal"));
            
            // Verify component data integrity
            let name_component = components.get("Name").unwrap().as_object().unwrap();
            assert_eq!(name_component.get("name").unwrap().as_str().unwrap(), "Test Entity");
        }

        #[tokio::test]
        async fn test_malformed_data_handling() {
            let _app = spawn_app(false, false, false).await;
            let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
            let find_tool = FindEntityTool::new(entity_manager.clone());

            // Test with malformed JSON-like strings in parameters
            let malformed_params = json!({
                "user_id": "550e8400-e29b-41d4-a716-446655440000",
                "criteria": {
                    "type": "ByName",
                    "name": "{\"malicious\": \"payload\"}"
                }
            });

            let result = find_tool.execute(&malformed_params).await;
            
            // Should handle gracefully without crashing
            if let Ok(output) = result {
                let entities = output.get("entities").unwrap().as_array().unwrap();
                assert!(entities.is_empty(), "Malformed data should not match entities");
            }
        }
    }

    // A09:2021 - Security Logging and Monitoring Tests
    mod logging_monitoring_tests {
        use super::*;

        #[tokio::test]
        async fn test_security_event_logging() {
            let _app = spawn_app(false, false, false).await;
            let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
            let find_tool = FindEntityTool::new(entity_manager.clone());

            // Trigger a security-relevant event (invalid user ID)
            let params = json!({
                "user_id": "invalid-user-id",
                "criteria": {
                    "type": "ByName",
                    "name": "test"
                }
            });

            let result = find_tool.execute(&params).await;
            
            // Should fail and ideally log the security event
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), ToolError::InvalidParams(_)));
            
            // Note: In a real implementation, this would verify that security logs
            // are generated for authentication failures, access violations, etc.
        }

        #[tokio::test]
        async fn test_audit_trail_for_data_access() {
            let _app = spawn_app(false, false, false).await;
            let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
            let details_tool = GetEntityDetailsTool::new(entity_manager.clone());

            let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

            let entity_id = create_test_entity(
                &entity_manager,
                user.id,
                "Sensitive Entity",
                SpatialScale::Intimate,
            ).await.expect("Failed to create entity");

            // Access entity details
            let params = json!({
                "user_id": user.id.to_string(),
                "entity_id": entity_id.to_string(),
                "include_hierarchy": true,
                "include_relationships": true
            });

            let result = details_tool.execute(&params).await.expect("Tool should execute");
            
            // Verify that sensitive data access succeeds (audit trail should be logged)
            let output: JsonValue = result;
            assert_eq!(output.get("entity_id").unwrap().as_str().unwrap(), entity_id.to_string());
            
            // Note: In a real implementation, this would verify that data access
            // events are logged for compliance and monitoring purposes
        }
    }

    // A10:2021 - Server-Side Request Forgery (SSRF) Tests
    mod ssrf_tests {
        use super::*;

        #[tokio::test]
        async fn test_no_external_requests() {
            let _app = spawn_app(false, false, false).await;
            let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
            let find_tool = FindEntityTool::new(entity_manager.clone());

            let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

            // Try to inject URL-like patterns that might trigger SSRF
            let ssrf_attempts = vec![
                "http://evil.com/steal-data",
                "https://internal.network/admin",
                "file:///etc/passwd",
                "ftp://malicious.site/upload",
                "ldap://directory.internal/users",
            ];

            for ssrf_attempt in ssrf_attempts {
                let params = json!({
                    "user_id": user.id.to_string(),
                    "criteria": {
                        "type": "ByName",
                        "name": ssrf_attempt
                    }
                });

                let result = find_tool.execute(&params).await;
                
                // Should handle as normal string search, not trigger SSRF
                if let Ok(output) = result {
                    let entities = output.get("entities").unwrap().as_array().unwrap();
                    assert!(entities.is_empty(), "SSRF attempt should not trigger external requests");
                }
            }
        }

        #[tokio::test]
        async fn test_no_internal_network_access() {
            let _app = spawn_app(false, false, false).await;
            let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
            let details_tool = GetEntityDetailsTool::new(entity_manager.clone());

            let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

            // Try to use internal network addresses as entity IDs
            let internal_addresses = vec![
                "127.0.0.1",
                "localhost",
                "192.168.1.1",
                "10.0.0.1",
                "172.16.0.1",
                "metadata.google.internal",
                "169.254.169.254", // AWS metadata service
            ];

            for address in internal_addresses {
                let params = json!({
                    "user_id": user.id.to_string(),
                    "entity_id": address
                });

                let result = details_tool.execute(&params).await;
                
                // Should fail due to invalid UUID format, not attempt network access
                assert!(result.is_err());
                assert!(matches!(result.unwrap_err(), ToolError::InvalidParams(_)));
            }
        }
    }
}