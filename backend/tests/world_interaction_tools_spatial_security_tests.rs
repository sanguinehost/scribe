//! OWASP Top 10 Security Tests for World Interaction Tools - Spatial functionality
//!
//! This test suite validates security aspects of spatial hierarchy queries and movement tools
//! based on the OWASP Top 10 (2021) security risks.

use scribe_backend::{
    models::ecs::{
        SpatialScale, SpatialArchetypeComponent,
        ParentLinkComponent, NameComponent, PositionComponent,
    },
    services::{
        EcsEntityManager, EntityManagerConfig,
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
    CreateEntityTool, FindEntityTool,
};

// Import spatial tools (to be implemented)
// use scribe_backend::services::agentic::tools::world_interaction_tools::{
//     GetContainedEntitiesTool, FindEntitiesWithinTool, MoveEntityTool,
// };

#[cfg(test)]
mod world_interaction_spatial_security_tests {
    use super::*;

    // A01: Broken Access Control Tests
    #[tokio::test]
    async fn test_a01_spatial_query_cross_user_isolation() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());

        let user1 = create_test_user(&_app.db_pool, "user1@example.com".to_string(), "user1".to_string()).await.unwrap();
        let user2 = create_test_user(&_app.db_pool, "user2@example.com".to_string(), "user2".to_string()).await.unwrap();

        // User1 creates a hierarchy
        let galaxy_params = json!({
            "user_id": user1.id.to_string(),
            "entity_name": "User1 Private Galaxy",
            "archetype_signature": "Name|SpatialArchetype",
            "components": {
                "Name": {"name": "User1 Private Galaxy", "display_name": "Private Galaxy", "aliases": []},
                "SpatialArchetype": {"scale": "Cosmic", "hierarchical_level": 0, "level_name": "Galaxy"}
            }
        });
        let galaxy_result = create_tool.execute(&galaxy_params).await.expect("Galaxy creation failed");
        let galaxy_id = galaxy_result.get("entity_id").unwrap().as_str().unwrap();

        let planet_params = json!({
            "user_id": user1.id.to_string(),
            "entity_name": "Secret Planet",
            "archetype_signature": "Name|SpatialArchetype|ParentLink",
            "parent_entity_id": galaxy_id,
            "components": {
                "Name": {"name": "Secret Planet", "display_name": "Secret", "aliases": []},
                "SpatialArchetype": {"scale": "Planetary", "hierarchical_level": 0, "level_name": "World"}
            }
        });
        create_tool.execute(&planet_params).await.expect("Planet creation failed");

        // When GetContainedEntitiesTool is implemented:
        // User2 attempts to query contents of User1's galaxy
        // Should return empty results or access denied error
    }

    #[tokio::test]
    async fn test_a01_movement_cross_user_prevention() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());

        let user1 = create_test_user(&_app.db_pool, "user1@example.com".to_string(), "user1".to_string()).await.unwrap();
        let user2 = create_test_user(&_app.db_pool, "user2@example.com".to_string(), "user2".to_string()).await.unwrap();

        // User1 creates a location
        let location1_params = json!({
            "user_id": user1.id.to_string(),
            "entity_name": "User1 Base",
            "archetype_signature": "Name|SpatialArchetype",
            "components": {
                "Name": {"name": "User1 Base", "display_name": "Secure Base", "aliases": []},
                "SpatialArchetype": {"scale": "Intimate", "hierarchical_level": 0, "level_name": "Building"}
            }
        });
        let location1_result = create_tool.execute(&location1_params).await.expect("Location creation failed");
        let location1_id = location1_result.get("entity_id").unwrap().as_str().unwrap();

        // User2 creates an entity
        let entity2_params = json!({
            "user_id": user2.id.to_string(),
            "entity_name": "User2 Spy",
            "archetype_signature": "Name",
            "components": {
                "Name": {"name": "User2 Spy", "display_name": "Spy", "aliases": []}
            }
        });
        let entity2_result = create_tool.execute(&entity2_params).await.expect("Entity creation failed");
        let entity2_id = entity2_result.get("entity_id").unwrap().as_str().unwrap();

        // When MoveEntityTool is implemented:
        // User2 attempts to move their entity into User1's location
        // Should fail with access denied error
    }

    #[tokio::test]
    async fn test_a01_descendant_query_ownership_filter() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());

        let user1 = create_test_user(&_app.db_pool, "user1@example.com".to_string(), "user1".to_string()).await.unwrap();
        let user2 = create_test_user(&_app.db_pool, "user2@example.com".to_string(), "user2".to_string()).await.unwrap();

        // Create shared parent (imagine a public space)
        // In practice, this would be owned by a system user
        let shared_params = json!({
            "user_id": user1.id.to_string(),
            "entity_name": "Public Space",
            "archetype_signature": "Name|SpatialArchetype",
            "components": {
                "Name": {"name": "Public Space", "display_name": "Town Square", "aliases": []},
                "SpatialArchetype": {"scale": "Intimate", "hierarchical_level": 3, "level_name": "Area"}
            }
        });
        let shared_result = create_tool.execute(&shared_params).await.expect("Shared space creation failed");
        let shared_id = shared_result.get("entity_id").unwrap().as_str().unwrap();

        // User1 creates entity in shared space
        let entity1_params = json!({
            "user_id": user1.id.to_string(),
            "entity_name": "User1 Shop",
            "archetype_signature": "Name|ParentLink",
            "parent_entity_id": shared_id,
            "components": {
                "Name": {"name": "User1 Shop", "display_name": "Private Shop", "aliases": []}
            }
        });
        create_tool.execute(&entity1_params).await.expect("Entity1 creation failed");

        // When GetContainedEntitiesTool is implemented:
        // User2 queries descendants of shared space
        // Should only see entities they own, not User1's entities
    }

    // A03: Injection Tests
    #[tokio::test]
    async fn test_a03_sql_injection_in_spatial_queries() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // When spatial query tools are implemented:
        // Attempt SQL injection in parent entity ID
        // let malicious_parent_id = "'; DROP TABLE ecs_entities; --";
        // Tool should properly escape or parameterize queries
    }

    #[tokio::test]
    async fn test_a03_json_injection_in_movement_params() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // When MoveEntityTool is implemented:
        // Attempt JSON injection in movement parameters
        // Include malicious __proto__ or constructor properties
        // Tool should sanitize JSON input
    }

    // A04: Insecure Design Tests
    #[tokio::test]
    async fn test_a04_recursive_hierarchy_dos_prevention() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // When spatial tools are implemented:
        // Create a very deep hierarchy (1000+ levels)
        // Query for all descendants
        // Should have depth limits or timeout to prevent DoS
    }

    #[tokio::test]
    async fn test_a04_circular_hierarchy_prevention() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Create two entities
        let entity1_params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Entity A",
            "archetype_signature": "Name",
            "components": {
                "Name": {"name": "Entity A", "display_name": "A", "aliases": []}
            }
        });
        let entity1_result = create_tool.execute(&entity1_params).await.expect("Entity1 creation failed");
        let entity1_id = entity1_result.get("entity_id").unwrap().as_str().unwrap();

        let entity2_params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Entity B",
            "archetype_signature": "Name|ParentLink",
            "parent_entity_id": entity1_id,
            "components": {
                "Name": {"name": "Entity B", "display_name": "B", "aliases": []}
            }
        });
        let entity2_result = create_tool.execute(&entity2_params).await.expect("Entity2 creation failed");
        let entity2_id = entity2_result.get("entity_id").unwrap().as_str().unwrap();

        // When MoveEntityTool is implemented:
        // Attempt to make entity1 a child of entity2 (creating a cycle)
        // Should be prevented to avoid infinite loops in hierarchy traversal
    }

    // A05: Security Misconfiguration Tests
    #[tokio::test]
    async fn test_a05_depth_limit_enforcement() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // When GetContainedEntitiesTool is implemented:
        // Attempt to query with extremely high depth value (e.g., 999999)
        // Should enforce reasonable maximum depth limit
    }

    #[tokio::test]
    async fn test_a05_result_limit_enforcement() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // When spatial query tools are implemented:
        // Create hierarchy with 1000+ entities
        // Query without limit or with excessive limit
        // Should enforce reasonable maximum result limit
    }

    #[tokio::test]
    async fn test_a05_movement_validation_rules() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // When MoveEntityTool is implemented:
        // Test various invalid movements:
        // - Moving to non-existent parent
        // - Moving to self
        // - Moving incompatible scales (planet into room)
        // All should be properly validated and rejected
    }

    // A07: Authentication Failures Tests
    #[tokio::test]
    async fn test_a07_spatial_query_requires_auth() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;

        // When spatial tools are implemented:
        // Attempt queries with:
        // - Missing user_id
        // - Invalid user_id format
        // - Non-existent user_id
        // All should fail with appropriate auth errors
    }

    // A08: Data Integrity Tests
    #[tokio::test]
    async fn test_a08_concurrent_movement_integrity() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // When MoveEntityTool is implemented:
        // Create entity and two locations
        // Attempt concurrent movements to different locations
        // Entity should end up in exactly one location
    }

    #[tokio::test]
    async fn test_a08_hierarchy_consistency_validation() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // When spatial tools are implemented:
        // Verify that:
        // - depth_from_root is correctly maintained
        // - Parent-child relationships are bidirectional
        // - No orphaned entities in hierarchy
    }

    // A09: Logging & Monitoring Tests
    #[tokio::test]
    async fn test_a09_spatial_operation_logging() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // When spatial tools are implemented:
        // Perform various operations:
        // - Query deep hierarchy
        // - Move entity across scales
        // - Failed movement attempt
        // Verify all operations are properly logged
    }

    #[tokio::test]
    async fn test_a09_performance_metric_logging() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // When spatial tools are implemented:
        // Execute expensive queries (deep hierarchy, many entities)
        // Verify performance metrics are logged:
        // - Query time
        // - Entities scanned
        // - Cache hit/miss
    }

    // A10: SSRF Tests
    #[tokio::test]
    async fn test_a10_external_reference_in_spatial_data() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // When spatial tools process component data:
        // Ensure no external URLs are fetched
        // Validate that webhook/callback URLs are ignored
    }
}