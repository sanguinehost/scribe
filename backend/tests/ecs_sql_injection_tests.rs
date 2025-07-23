//! SQL Injection Prevention Tests for ECS Entity Manager
//!
//! This test suite validates that the ECS entity manager properly handles
//! potentially malicious inputs that could lead to SQL injection attacks.

use scribe_backend::{
    models::ecs::{
        SpatialScale, SpatialArchetypeComponent,
        NameComponent, TemporalComponent, PositionComponent,
    },
    services::{
        EcsEntityManager, EntityManagerConfig,
        ComponentQuery,
    },
    test_helpers::{spawn_app, db::create_test_user},
    errors::AppError,
    PgPool,
};
use serde_json::json;
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

/// Helper function to create a test entity with a specific name
async fn create_test_entity_with_name(
    entity_manager: &Arc<EcsEntityManager>,
    user_id: Uuid,
    name: &str,
) -> Result<Uuid, AppError> {
    let entity_id = Uuid::new_v4();
    
    let spatial_archetype = SpatialArchetypeComponent::new(
        SpatialScale::Intimate,
        0,
        "Building".to_string(),
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
mod ecs_sql_injection_tests {
    use super::*;

    #[tokio::test]
    async fn test_sql_injection_entity_names_with_apostrophes() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Test Case 1: Names with single apostrophes
        let entity1_id = create_test_entity_with_name(
            &entity_manager,
            user.id,
            "O'Brien's Tavern",
        ).await.expect("Failed to create entity with apostrophe");

        // Test Case 2: Names with multiple apostrophes
        let entity2_id = create_test_entity_with_name(
            &entity_manager,
            user.id,
            "O'Malley's 'Special' Place",
        ).await.expect("Failed to create entity with multiple apostrophes");

        // Test Case 3: Names with SQL injection attempt
        let entity3_id = create_test_entity_with_name(
            &entity_manager,
            user.id,
            "'; DROP TABLE ecs_entities; --",
        ).await.expect("Failed to create entity with SQL injection attempt");

        // Test Case 4: Names with escaped quotes
        let entity4_id = create_test_entity_with_name(
            &entity_manager,
            user.id,
            r#"Alice's "Wonderland" Cafe"#,
        ).await.expect("Failed to create entity with mixed quotes");

        // Verify all entities can be found by name using ComponentDataMatches
        let queries = vec![ComponentQuery::ComponentDataMatches(
            "Name".to_string(),
            "name".to_string(),
            "O'Brien".to_string(),
        )];
        let results = entity_manager.query_entities(user.id, queries, Some(10), None).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entity.id, entity1_id);

        // Search for O'Malley's entity
        let queries = vec![ComponentQuery::ComponentDataMatches(
            "Name".to_string(),
            "name".to_string(),
            "O'Malley".to_string(),
        )];
        let results = entity_manager.query_entities(user.id, queries, Some(10), None).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entity.id, entity2_id);

        // Search for SQL injection attempt - should find it as a regular entity
        let queries = vec![ComponentQuery::ComponentDataMatches(
            "Name".to_string(),
            "name".to_string(),
            "DROP TABLE".to_string(),
        )];
        let results = entity_manager.query_entities(user.id, queries, Some(10), None).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entity.id, entity3_id);

        // Search for entity with mixed quotes
        let queries = vec![ComponentQuery::ComponentDataMatches(
            "Name".to_string(),
            "name".to_string(),
            "Wonderland".to_string(),
        )];
        let results = entity_manager.query_entities(user.id, queries, Some(10), None).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entity.id, entity4_id);

        // Verify ComponentDataEquals works with special characters
        let queries = vec![ComponentQuery::ComponentDataEquals(
            "Name".to_string(),
            "name".to_string(),
            json!("O'Brien's Tavern"),
        )];
        let results = entity_manager.query_entities(user.id, queries, Some(10), None).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entity.id, entity1_id);

        // Verify numeric comparisons still work
        let queries = vec![ComponentQuery::ComponentDataGreaterThan(
            "Position".to_string(),
            "x".to_string(),
            -1.0,
        )];
        let results = entity_manager.query_entities(user.id, queries, Some(10), None).await.unwrap();
        eprintln!("Found {} entities with x > -1.0", results.len());
        for result in &results {
            eprintln!("Entity ID: {}", result.entity.id);
        }
        assert_eq!(results.len(), 4); // All entities have x=0.0 which is > -1.0
    }

    #[tokio::test]
    async fn test_sql_injection_path_traversal_attempts() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Create a normal entity
        let entity_id = create_test_entity_with_name(
            &entity_manager,
            user.id,
            "Normal Entity",
        ).await.expect("Failed to create entity");

        // Test malicious path attempts in queries
        let malicious_paths = vec![
            "../../../etc/passwd",
            "name' OR '1'='1",
            "name; SELECT * FROM users; --",
            "name')->'password",
            r#"name")->>'secret"#,
        ];

        for path in malicious_paths {
            // ComponentDataEquals with malicious path should return empty results (path doesn't exist)
            let queries = vec![ComponentQuery::ComponentDataEquals(
                "Name".to_string(),
                path.to_string(),
                json!("any_value"),
            )];
            let results = entity_manager.query_entities(user.id, queries, Some(10), None).await.unwrap();
            assert_eq!(results.len(), 0, "Malicious path '{}' should return no results", path);

            // ComponentDataMatches with malicious path should also return empty results
            let queries = vec![ComponentQuery::ComponentDataMatches(
                "Name".to_string(),
                path.to_string(),
                "any_pattern".to_string(),
            )];
            let results = entity_manager.query_entities(user.id, queries, Some(10), None).await.unwrap();
            assert_eq!(results.len(), 0, "Malicious path '{}' should return no results", path);
        }

        // Verify normal queries still work
        let queries = vec![ComponentQuery::ComponentDataMatches(
            "Name".to_string(),
            "name".to_string(),
            "Normal".to_string(),
        )];
        let results = entity_manager.query_entities(user.id, queries, Some(10), None).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entity.id, entity_id);
    }
}