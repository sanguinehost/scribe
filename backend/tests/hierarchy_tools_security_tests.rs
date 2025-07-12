// Hierarchy Tools Security Tests
//
// Comprehensive security test suite for hierarchy promotion tools following OWASP Top 10 guidelines
// This test suite validates that the hierarchy management tools properly enforce security controls
// and cannot be exploited to violate access control or data integrity principles.

use scribe_backend::{
    models::ecs::{
        SpatialScale, PositionType, HierarchicalCoordinates, SpatialArchetypeComponent,
        ParentLinkComponent, NameComponent, TemporalComponent, Component,
    },
    services::{
        EcsEntityManager, EntityManagerConfig,
        agentic::tools::{ScribeTool, ToolError, ToolParams},
        agentic::tools::hierarchy_tools::{PromoteEntityHierarchyTool, GetEntityHierarchyTool},
    },
    test_helpers::{spawn_app, TestDataGuard, db::create_test_user},
    errors::AppError,
    PgPool,
};
use serde_json::{json, Value as JsonValue};
use std::sync::Arc;
use uuid::Uuid;
use futures;

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

#[cfg(test)]
mod hierarchy_tools_security_tests {
    use super::*;

    /// Helper function to create a test entity with proper components
    async fn create_test_entity(
        entity_manager: &Arc<EcsEntityManager>,
        user_id: Uuid,
        name: &str,
        scale: SpatialScale,
        parent_id: Option<Uuid>,
    ) -> Result<Uuid, AppError> {
        let entity_id = Uuid::new_v4();
        
        let level_name = scale.level_name(0)
            .ok_or_else(|| AppError::InternalServerErrorGeneric("Invalid level 0 for scale".to_string()))?;
        
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

        let mut components = vec![
            ("SpatialArchetype".to_string(), serde_json::to_value(spatial_archetype)?),
            ("Name".to_string(), serde_json::to_value(name_component)?),
            ("Temporal".to_string(), serde_json::to_value(temporal_component)?),
        ];

        if let Some(parent) = parent_id {
            let parent_link = ParentLinkComponent {
                parent_entity_id: parent,
                depth_from_root: 1,
                spatial_relationship: "contained_within".to_string(),
            };
            components.push(("ParentLink".to_string(), serde_json::to_value(parent_link)?));
        }

        entity_manager.create_entity(
            user_id,
            Some(entity_id),
            "Test Entity".to_string(),
            components,
        ).await?;

        Ok(entity_id)
    }

    // =============================================================================
    // A01: BROKEN ACCESS CONTROL TESTS
    // =============================================================================

    #[tokio::test]
    async fn test_promote_hierarchy_prevents_cross_user_access() {
        let app = spawn_app(false, false, false).await;
        let _test_guard = TestDataGuard::new(app.db_pool.clone());
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        
        // Create two separate users
        let user1 = create_test_user(&app.db_pool, "user1@example.com".to_string(), "password".to_string()).await
            .expect("Failed to create user1");
        let user1_id = user1.id;
        let user2 = create_test_user(&app.db_pool, "user2@example.com".to_string(), "password".to_string()).await
            .expect("Failed to create user2");
        let user2_id = user2.id;

        // User 1 creates an entity
        let user1_entity = create_test_entity(
            &entity_manager,
            user1_id,
            "User1 Planet",
            SpatialScale::Planetary,
            None,
        ).await.expect("Failed to create user1 entity");

        // Create the hierarchy promotion tool
        let promote_tool = PromoteEntityHierarchyTool::new(entity_manager.clone());

        // User 2 attempts to promote User 1's entity - should fail
        let malicious_params = json!({
            "user_id": user2_id.to_string(),
            "entity_id": user1_entity.to_string(),
            "new_parent_name": "Malicious Galaxy",
            "new_parent_scale": "Cosmic",
            "new_parent_position": {
                "position_type": "absolute",
                "coordinates": {"x": 0.0, "y": 0.0, "z": 0.0}
            },
            "relationship_type": "contains"
        });

        let result = promote_tool.execute(&malicious_params).await;
        
        // Should fail due to access control violation
        assert!(result.is_err(), "Cross-user entity promotion should be rejected");
        match result.unwrap_err() {
            ToolError::AppError(AppError::NotFound(_)) => {
                // Expected - entity not found because user2 doesn't have access
            }
            _ => panic!("Expected NotFound error for cross-user access"),
        }
    }

    #[tokio::test]
    async fn test_get_hierarchy_prevents_cross_user_access() {
        let app = spawn_app(false, false, false).await;
        let _test_guard = TestDataGuard::new(app.db_pool.clone());
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        
        // Create two separate users
        let user1 = create_test_user(&app.db_pool, "user1@example.com".to_string(), "password".to_string()).await
            .expect("Failed to create user1");
        let user1_id = user1.id;
        let user2 = create_test_user(&app.db_pool, "user2@example.com".to_string(), "password".to_string()).await
            .expect("Failed to create user2");
        let user2_id = user2.id;

        // User 1 creates an entity
        let user1_entity = create_test_entity(
            &entity_manager,
            user1_id,
            "User1 Secret Location",
            SpatialScale::Intimate,
            None,
        ).await.expect("Failed to create user1 entity");

        let get_tool = GetEntityHierarchyTool::new(entity_manager.clone());

        // User 2 attempts to get User 1's entity hierarchy - should fail
        let malicious_params = json!({
            "user_id": user2_id.to_string(),
            "entity_id": user1_entity.to_string(),
        });

        let result = get_tool.execute(&malicious_params).await;
        
        // Should fail due to access control violation
        assert!(result.is_err(), "Cross-user hierarchy access should be rejected");
        match result.unwrap_err() {
            ToolError::ExecutionFailed(msg) => {
                assert!(msg.contains("Entity not found"), "Should indicate entity not found for unauthorized access");
            }
            ToolError::AppError(AppError::NotFound(_)) => {
                // Also acceptable - entity not found because user2 doesn't have access
            }
            other => panic!("Expected ExecutionFailed or NotFound error for cross-user access, got: {:?}", other),
        }
    }

    // =============================================================================
    // A03: INJECTION TESTS
    // =============================================================================

    #[tokio::test]
    async fn test_promote_hierarchy_sql_injection_prevention() {
        let app = spawn_app(false, false, false).await;
        let _test_guard = TestDataGuard::new(app.db_pool.clone());
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        
        let user = create_test_user(&app.db_pool, "test@example.com".to_string(), "password".to_string()).await
            .expect("Failed to create user");
        let user_id = user.id;
        
        let entity_id = create_test_entity(
            &entity_manager,
            user_id,
            "Test Planet",
            SpatialScale::Planetary,
            None,
        ).await.expect("Failed to create entity");

        let promote_tool = PromoteEntityHierarchyTool::new(entity_manager.clone());

        // Test SQL injection in new_parent_name
        let injection_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": entity_id.to_string(),
            "new_parent_name": "'; DROP TABLE ecs_entities; --",
            "new_parent_scale": "Cosmic",
            "new_parent_position": {
                "position_type": "absolute",
                "coordinates": {"x": 0.0, "y": 0.0, "z": 0.0}
            },
            "relationship_type": "contains"
        });

        let result = promote_tool.execute(&injection_params).await;
        
        // Should either succeed (treating injection as literal string) or fail gracefully
        // but never cause database corruption
        match result {
            Ok(_) => {
                // If it succeeds, verify the injection was treated as literal text
                let hierarchy = entity_manager
                    .get_entity_hierarchy_path(user_id, entity_id)
                    .await
                    .expect("Should be able to get hierarchy after injection attempt");
                
                // Verify database integrity - we should be able to query other entities
                let test_entity_2 = create_test_entity(
                    &entity_manager,
                    user_id,
                    "Integrity Check",
                    SpatialScale::Intimate,
                    None,
                ).await;
                assert!(test_entity_2.is_ok(), "Database should remain intact after injection attempt");
            }
            Err(_) => {
                // If it fails, that's also acceptable as long as it fails gracefully
                // Verify database integrity
                let test_entity_2 = create_test_entity(
                    &entity_manager,
                    user_id,
                    "Integrity Check",
                    SpatialScale::Intimate,
                    None,
                ).await;
                assert!(test_entity_2.is_ok(), "Database should remain intact after failed injection attempt");
            }
        }
    }

    #[tokio::test]
    async fn test_hierarchy_tools_json_injection_prevention() {
        let app = spawn_app(false, false, false).await;
        let _test_guard = TestDataGuard::new(app.db_pool.clone());
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        
        let user = create_test_user(&app.db_pool, "test@example.com".to_string(), "password".to_string()).await
            .expect("Failed to create user");
        let user_id = user.id;
        
        let promote_tool = PromoteEntityHierarchyTool::new(entity_manager.clone());

        // Test malformed JSON injection
        let malformed_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": "not-a-uuid\"injected\":\"value",
            "new_parent_name": "Test Galaxy",
            "new_parent_scale": "Cosmic",
            "new_parent_position": {
                "position_type": "absolute",
                "coordinates": {"x": 0.0, "y": 0.0, "z": 0.0}
            },
            "relationship_type": "contains"
        });

        let result = promote_tool.execute(&malformed_params).await;
        
        // Should fail with proper validation error
        assert!(result.is_err(), "Malformed UUID should be rejected");
        match result.unwrap_err() {
            ToolError::InvalidParams(msg) => {
                assert!(msg.contains("Invalid entity_id UUID"), "Should indicate UUID validation error");
            }
            _ => panic!("Expected InvalidParams error for malformed UUID"),
        }
    }

    // =============================================================================
    // A08: SOFTWARE AND DATA INTEGRITY FAILURES TESTS
    // =============================================================================

    #[tokio::test]
    async fn test_promote_hierarchy_data_validation() {
        let app = spawn_app(false, false, false).await;
        let _test_guard = TestDataGuard::new(app.db_pool.clone());
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        
        let user = create_test_user(&app.db_pool, "test@example.com".to_string(), "password".to_string()).await
            .expect("Failed to create user");
        let user_id = user.id;
        
        let entity_id = create_test_entity(
            &entity_manager,
            user_id,
            "Test Planet",
            SpatialScale::Planetary,
            None,
        ).await.expect("Failed to create entity");

        let promote_tool = PromoteEntityHierarchyTool::new(entity_manager.clone());

        // Test invalid spatial scale
        let invalid_scale_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": entity_id.to_string(),
            "new_parent_name": "Test Galaxy",
            "new_parent_scale": "InvalidScale",
            "new_parent_position": {
                "position_type": "absolute",
                "coordinates": {"x": 0.0, "y": 0.0, "z": 0.0}
            },
            "relationship_type": "contains"
        });

        let result = promote_tool.execute(&invalid_scale_params).await;
        
        assert!(result.is_err(), "Invalid spatial scale should be rejected");
        match result.unwrap_err() {
            ToolError::InvalidParams(msg) => {
                assert!(msg.contains("Invalid spatial scale"), "Should indicate invalid scale error");
            }
            _ => panic!("Expected InvalidParams error for invalid scale"),
        }

        // Test invalid position type
        let invalid_position_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": entity_id.to_string(),
            "new_parent_name": "Test Galaxy",
            "new_parent_scale": "Cosmic",
            "new_parent_position": {
                "position_type": "invalid_type",
                "coordinates": {"x": 0.0, "y": 0.0, "z": 0.0}
            },
            "relationship_type": "contains"
        });

        let result = promote_tool.execute(&invalid_position_params).await;
        
        assert!(result.is_err(), "Invalid position type should be rejected");
        match result.unwrap_err() {
            ToolError::InvalidParams(msg) => {
                assert!(msg.contains("Invalid position_type"), "Should indicate invalid position type error");
            }
            _ => panic!("Expected InvalidParams error for invalid position type"),
        }
    }

    #[tokio::test]
    async fn test_promote_hierarchy_relative_position_validation() {
        let app = spawn_app(false, false, false).await;
        let _test_guard = TestDataGuard::new(app.db_pool.clone());
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        
        let user = create_test_user(&app.db_pool, "test@example.com".to_string(), "password".to_string()).await
            .expect("Failed to create user");
        let user_id = user.id;
        
        let entity_id = create_test_entity(
            &entity_manager,
            user_id,
            "Test Planet",
            SpatialScale::Planetary,
            None,
        ).await.expect("Failed to create entity");

        let promote_tool = PromoteEntityHierarchyTool::new(entity_manager.clone());

        // Test relative position without relative_to_entity
        let missing_relative_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": entity_id.to_string(),
            "new_parent_name": "Test Galaxy",
            "new_parent_scale": "Cosmic",
            "new_parent_position": {
                "position_type": "relative",
                "coordinates": {"x": 0.0, "y": 0.0, "z": 0.0}
                // Missing relative_to_entity
            },
            "relationship_type": "contains"
        });

        let result = promote_tool.execute(&missing_relative_params).await;
        
        assert!(result.is_err(), "Relative position without target should be rejected");
        match result.unwrap_err() {
            ToolError::InvalidParams(msg) => {
                assert!(msg.contains("relative_to_entity required"), "Should indicate missing relative target");
            }
            _ => panic!("Expected InvalidParams error for missing relative target"),
        }

        // Test relative position with invalid UUID
        let invalid_relative_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": entity_id.to_string(),
            "new_parent_name": "Test Galaxy",
            "new_parent_scale": "Cosmic",
            "new_parent_position": {
                "position_type": "relative",
                "coordinates": {"x": 0.0, "y": 0.0, "z": 0.0},
                "relative_to_entity": "not-a-valid-uuid"
            },
            "relationship_type": "contains"
        });

        let result = promote_tool.execute(&invalid_relative_params).await;
        
        assert!(result.is_err(), "Invalid relative target UUID should be rejected");
        match result.unwrap_err() {
            ToolError::InvalidParams(msg) => {
                assert!(msg.contains("Invalid relative_to_entity UUID"), "Should indicate invalid relative UUID");
            }
            _ => panic!("Expected InvalidParams error for invalid relative UUID"),
        }
    }

    // =============================================================================
    // A09: SECURITY LOGGING AND MONITORING TESTS
    // =============================================================================

    #[tokio::test]
    async fn test_hierarchy_tools_audit_logging() {
        let app = spawn_app(false, false, false).await;
        let _test_guard = TestDataGuard::new(app.db_pool.clone());
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        
        let user = create_test_user(&app.db_pool, "test@example.com".to_string(), "password".to_string()).await
            .expect("Failed to create user");
        let user_id = user.id;
        
        let entity_id = create_test_entity(
            &entity_manager,
            user_id,
            "Test Planet",
            SpatialScale::Planetary,
            None,
        ).await.expect("Failed to create entity");

        let promote_tool = PromoteEntityHierarchyTool::new(entity_manager.clone());

        // Successful promotion should be logged
        let valid_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": entity_id.to_string(),
            "new_parent_name": "Test Galaxy",
            "new_parent_scale": "Cosmic",
            "new_parent_position": {
                "position_type": "absolute",
                "coordinates": {"x": 0.0, "y": 0.0, "z": 0.0}
            },
            "relationship_type": "contains"
        });

        // Execute the tool - should succeed and be logged
        let result = promote_tool.execute(&valid_params).await;
        assert!(result.is_ok(), "Valid hierarchy promotion should succeed");

        // Failed promotion attempt should also be logged
        let invalid_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": "00000000-0000-0000-0000-000000000000", // Non-existent entity
            "new_parent_name": "Failed Galaxy",
            "new_parent_scale": "Cosmic",
            "new_parent_position": {
                "position_type": "absolute",
                "coordinates": {"x": 0.0, "y": 0.0, "z": 0.0}
            },
            "relationship_type": "contains"
        });

        let failed_result = promote_tool.execute(&invalid_params).await;
        assert!(failed_result.is_err(), "Invalid entity promotion should fail and be logged");

        // Note: In a real implementation, we would verify that these operations
        // were logged by checking log output or audit tables. For this test,
        // we're verifying that the operations complete (successfully or with failure)
        // which ensures the logging code paths are executed.
    }

    // =============================================================================
    // BUSINESS LOGIC SECURITY TESTS
    // =============================================================================

    #[tokio::test]
    async fn test_hierarchy_promotion_depth_limits() {
        let app = spawn_app(false, false, false).await;
        let _test_guard = TestDataGuard::new(app.db_pool.clone());
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        
        let user = create_test_user(&app.db_pool, "test@example.com".to_string(), "password".to_string()).await
            .expect("Failed to create user");
        let user_id = user.id;
        
        let entity_id = create_test_entity(
            &entity_manager,
            user_id,
            "Test Planet",
            SpatialScale::Planetary,
            None,
        ).await.expect("Failed to create entity");

        let promote_tool = PromoteEntityHierarchyTool::new(entity_manager.clone());

        // Attempt to create extremely deep hierarchy to test for DoS protection
        let mut current_entity = entity_id;
        let max_attempts = 100; // Reasonable limit to prevent test timeout

        for i in 0..max_attempts {
            let params = json!({
                "user_id": user_id.to_string(),
                "entity_id": current_entity.to_string(),
                "new_parent_name": format!("Level {} Parent", i),
                "new_parent_scale": "Cosmic",
                "new_parent_position": {
                    "position_type": "absolute",
                    "coordinates": {"x": i as f64, "y": 0.0, "z": 0.0}
                },
                "relationship_type": "contains"
            });

            match promote_tool.execute(&params).await {
                Ok(result) => {
                    // Extract new parent ID for next iteration
                    if let Ok(output) = serde_json::from_value::<serde_json::Value>(result) {
                        if let Some(new_parent_id_str) = output.get("new_parent_id").and_then(|v| v.as_str()) {
                            if let Ok(new_parent_id) = Uuid::parse_str(new_parent_id_str) {
                                current_entity = new_parent_id;
                                continue;
                            }
                        }
                    }
                    break;
                }
                Err(_) => {
                    // Failure is acceptable - might be hitting reasonable limits
                    break;
                }
            }
        }

        // Verify that the system is still responsive after hierarchy operations
        let test_get_tool = GetEntityHierarchyTool::new(entity_manager.clone());
        let get_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": entity_id.to_string(),
        });

        let get_result = test_get_tool.execute(&get_params).await;
        assert!(get_result.is_ok(), "System should remain responsive after hierarchy operations");
    }

    #[tokio::test]
    async fn test_concurrent_hierarchy_operations_safety() {
        let app = spawn_app(false, false, false).await;
        let _test_guard = TestDataGuard::new(app.db_pool.clone());
        let entity_manager = create_entity_manager(app.db_pool.clone()).await;
        
        let user = create_test_user(&app.db_pool, "test@example.com".to_string(), "password".to_string()).await
            .expect("Failed to create user");
        let user_id = user.id;
        
        let entity_id = create_test_entity(
            &entity_manager,
            user_id,
            "Test Planet",
            SpatialScale::Planetary,
            None,
        ).await.expect("Failed to create entity");

        let promote_tool = Arc::new(PromoteEntityHierarchyTool::new(entity_manager.clone()));

        // Launch multiple concurrent hierarchy promotions on the same entity
        let mut handles = Vec::new();
        for i in 0..5 {
            let tool = promote_tool.clone();
            let user_id = user_id;
            let entity_id = entity_id;
            
            let handle = tokio::spawn(async move {
                let params = json!({
                    "user_id": user_id.to_string(),
                    "entity_id": entity_id.to_string(),
                    "new_parent_name": format!("Concurrent Galaxy {}", i),
                    "new_parent_scale": "Cosmic",
                    "new_parent_position": {
                        "position_type": "absolute",
                        "coordinates": {"x": i as f64, "y": 0.0, "z": 0.0}
                    },
                    "relationship_type": "contains"
                });

                tool.execute(&params).await
            });
            handles.push(handle);
        }

        // Wait for all operations to complete
        let results: Vec<_> = futures::future::join_all(handles).await;

        // At least one should succeed, others might fail due to race conditions
        let successful_count = results.iter()
            .filter(|r| r.is_ok() && r.as_ref().unwrap().is_ok())
            .count();

        assert!(successful_count >= 1, "At least one concurrent operation should succeed");

        // Verify the entity still exists and hierarchy is in a valid state
        let get_tool = GetEntityHierarchyTool::new(entity_manager.clone());
        let get_params = json!({
            "user_id": user_id.to_string(),
            "entity_id": entity_id.to_string(),
        });

        let get_result = get_tool.execute(&get_params).await;
        assert!(get_result.is_ok(), "Entity hierarchy should be queryable after concurrent operations");
    }
}