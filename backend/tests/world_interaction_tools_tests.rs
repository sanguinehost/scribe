//! Tests for World Interaction Tools
//!
//! This test suite validates the find_entity and get_entity_details tools
//! ensuring they correctly interact with the ECS system and return proper results.

use scribe_backend::{
    models::ecs::{
        SpatialScale, SpatialArchetypeComponent,
        ParentLinkComponent, NameComponent, TemporalComponent,
        PositionComponent, RelationshipsComponent, Relationship,
    },
    services::{
        EcsEntityManager, EntityManagerConfig, ComponentUpdate, ComponentOperation,
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

/// Helper function to create a test entity with proper components
async fn create_test_entity(
    entity_manager: &Arc<EcsEntityManager>,
    user_id: Uuid,
    name: &str,
    scale: SpatialScale,
    hierarchical_level: u32,
    parent_id: Option<Uuid>,
) -> Result<Uuid, AppError> {
    let entity_id = Uuid::new_v4();
    
    let level_name = scale.level_name(hierarchical_level)
        .ok_or_else(|| AppError::InternalServerErrorGeneric(format!("Invalid level {} for scale {:?}", hierarchical_level, scale)))?;

    let spatial_archetype = SpatialArchetypeComponent::new(
        scale,
        hierarchical_level,
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

    let mut components = vec![
        ("SpatialArchetype".to_string(), serde_json::to_value(spatial_archetype)?),
        ("Name".to_string(), serde_json::to_value(name_component)?),
        ("Temporal".to_string(), serde_json::to_value(temporal_component)?),
        ("Position".to_string(), serde_json::to_value(position_component)?),
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

#[cfg(test)]
mod world_interaction_tools_tests {
    use super::*;

    #[tokio::test]
    async fn test_find_entity_by_name() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let find_tool = FindEntityTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Create test entities
        let _planet_id = create_test_entity(
            &entity_manager,
            user.id,
            "Earth",
            SpatialScale::Planetary,
            0,
            None,
        ).await.expect("Failed to create planet entity");

        let _city_id = create_test_entity(
            &entity_manager,
            user.id,
            "New York",
            SpatialScale::Intimate,
            0,
            None,
        ).await.expect("Failed to create city entity");

        // Test finding by name
        let params = json!({
            "user_id": user.id.to_string(),
            "criteria": {
                "type": "ByName",
                "name": "Earth"
            },
            "limit": 10
        });

        let result = find_tool.execute(&params).await.expect("Tool execution failed");
        
        let output: JsonValue = result;
        assert!(output.get("entities").unwrap().as_array().unwrap().len() > 0);
        assert_eq!(output.get("total_found").unwrap().as_u64().unwrap(), 1);
        
        let entity = &output.get("entities").unwrap().as_array().unwrap()[0];
        assert_eq!(entity.get("name").unwrap().as_str().unwrap(), "Earth");
    }

    #[tokio::test]
    async fn test_find_entity_by_scale() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let find_tool = FindEntityTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Create test entities with different scales
        let _planet_id = create_test_entity(
            &entity_manager,
            user.id,
            "Mars",
            SpatialScale::Planetary,
            0,
            None,
        ).await.expect("Failed to create planet entity");

        let _intimate_id = create_test_entity(
            &entity_manager,
            user.id,
            "Living Room",
            SpatialScale::Intimate,
            0,
            None,
        ).await.expect("Failed to create intimate entity");

        // Test finding by scale
        let params = json!({
            "user_id": user.id.to_string(),
            "criteria": {
                "type": "ByScale",
                "scale": "Planetary"
            },
            "limit": 10
        });

        let result = find_tool.execute(&params).await.expect("Tool execution failed");
        
        let output: JsonValue = result;
        assert!(output.get("entities").unwrap().as_array().unwrap().len() > 0);
        
        let entity = &output.get("entities").unwrap().as_array().unwrap()[0];
        assert_eq!(entity.get("name").unwrap().as_str().unwrap(), "Mars");
        assert_eq!(entity.get("scale").unwrap().as_str().unwrap(), "Planetary");
    }

    #[tokio::test]
    async fn test_find_entity_by_parent() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let find_tool = FindEntityTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Create parent entity
        let parent_id = create_test_entity(
            &entity_manager,
            user.id,
            "Solar System",
            SpatialScale::Cosmic,
            0,
            None,
        ).await.expect("Failed to create parent entity");

        // Create child entity
        let _child_id = create_test_entity(
            &entity_manager,
            user.id,
            "Venus",
            SpatialScale::Planetary,
            1,
            Some(parent_id),
        ).await.expect("Failed to create child entity");

        // Test finding by parent
        let params = json!({
            "user_id": user.id.to_string(),
            "criteria": {
                "type": "ByParent",
                "parent_id": parent_id.to_string()
            },
            "limit": 10
        });

        let result = find_tool.execute(&params).await.expect("Tool execution failed");
        
        let output: JsonValue = result;
        assert!(output.get("entities").unwrap().as_array().unwrap().len() > 0);
        
        let entity = &output.get("entities").unwrap().as_array().unwrap()[0];
        assert_eq!(entity.get("name").unwrap().as_str().unwrap(), "Venus");
        assert_eq!(entity.get("parent_id").unwrap().as_str().unwrap(), parent_id.to_string());
    }

    #[tokio::test]
    async fn test_find_entity_by_component() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let find_tool = FindEntityTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Create test entity
        let _entity_id = create_test_entity(
            &entity_manager,
            user.id,
            "Test Location",
            SpatialScale::Intimate,
            0,
            None,
        ).await.expect("Failed to create entity");

        // Test finding by component
        let params = json!({
            "user_id": user.id.to_string(),
            "criteria": {
                "type": "ByComponent",
                "component_type": "Position"
            },
            "limit": 10
        });

        let result = find_tool.execute(&params).await.expect("Tool execution failed");
        
        let output: JsonValue = result;
        assert!(output.get("entities").unwrap().as_array().unwrap().len() > 0);
        
        let entity = &output.get("entities").unwrap().as_array().unwrap()[0];
        assert_eq!(entity.get("name").unwrap().as_str().unwrap(), "Test Location");
        assert!(entity.get("component_types").unwrap().as_array().unwrap().contains(&json!("Position")));
    }

    #[tokio::test]
    async fn test_get_entity_details_basic() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let details_tool = GetEntityDetailsTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Create test entity
        let entity_id = create_test_entity(
            &entity_manager,
            user.id,
            "Detailed Entity",
            SpatialScale::Intimate,
            0,
            None,
        ).await.expect("Failed to create entity");

        // Test getting entity details
        let params = json!({
            "user_id": user.id.to_string(),
            "entity_id": entity_id.to_string(),
            "include_hierarchy": false,
            "include_relationships": false
        });

        let result = details_tool.execute(&params).await.expect("Tool execution failed");
        
        let output: JsonValue = result;
        assert_eq!(output.get("entity_id").unwrap().as_str().unwrap(), entity_id.to_string());
        assert_eq!(output.get("name").unwrap().as_str().unwrap(), "Detailed Entity");
        assert!(output.get("components").unwrap().as_object().unwrap().contains_key("Name"));
        assert!(output.get("components").unwrap().as_object().unwrap().contains_key("SpatialArchetype"));
        assert!(output.get("components").unwrap().as_object().unwrap().contains_key("Position"));
    }

    #[tokio::test]
    async fn test_get_entity_details_with_hierarchy() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let details_tool = GetEntityDetailsTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Create parent entity
        let parent_id = create_test_entity(
            &entity_manager,
            user.id,
            "Parent Location",
            SpatialScale::Planetary,
            0,
            None,
        ).await.expect("Failed to create parent entity");

        // Create child entity
        let child_id = create_test_entity(
            &entity_manager,
            user.id,
            "Child Location",
            SpatialScale::Intimate,
            1,
            Some(parent_id),
        ).await.expect("Failed to create child entity");

        // Test getting entity details with hierarchy
        let params = json!({
            "user_id": user.id.to_string(),
            "entity_id": child_id.to_string(),
            "include_hierarchy": true,
            "include_relationships": false
        });

        let result = details_tool.execute(&params).await.expect("Tool execution failed");
        
        let output: JsonValue = result;
        assert_eq!(output.get("entity_id").unwrap().as_str().unwrap(), child_id.to_string());
        assert_eq!(output.get("name").unwrap().as_str().unwrap(), "Child Location");
        
        // Check if hierarchy path is included
        if let Some(hierarchy) = output.get("hierarchy_path") {
            assert!(hierarchy.is_array());
        }
        
        // Check if children information is included
        if let Some(children) = output.get("children") {
            assert!(children.is_array());
        }
    }

    #[tokio::test]
    async fn test_get_entity_details_with_relationships() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let details_tool = GetEntityDetailsTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Create entities for relationships
        let entity1_id = create_test_entity(
            &entity_manager,
            user.id,
            "Entity One",
            SpatialScale::Intimate,
            0,
            None,
        ).await.expect("Failed to create entity 1");

        let entity2_id = create_test_entity(
            &entity_manager,
            user.id,
            "Entity Two",
            SpatialScale::Intimate,
            0,
            None,
        ).await.expect("Failed to create entity 2");

        // Add relationships component to entity1
        let relationships_component = RelationshipsComponent {
            relationships: vec![
                Relationship {
                    target_entity_id: entity2_id,
                    relationship_type: "friends_with".to_string(),
                    trust: 0.8,
                    affection: 0.7,
                    metadata: std::collections::HashMap::new(),
                }
            ],
        };

        entity_manager.update_components(
            user.id,
            entity1_id,
            vec![ComponentUpdate {
                entity_id: entity1_id,
                component_type: "Relationships".to_string(),
                component_data: serde_json::to_value(relationships_component).unwrap(),
                operation: ComponentOperation::Add,
            }],
        ).await.expect("Failed to add relationships");

        // Test getting entity details with relationships
        let params = json!({
            "user_id": user.id.to_string(),
            "entity_id": entity1_id.to_string(),
            "include_hierarchy": false,
            "include_relationships": true
        });

        let result = details_tool.execute(&params).await.expect("Tool execution failed");
        
        let output: JsonValue = result;
        assert_eq!(output.get("entity_id").unwrap().as_str().unwrap(), entity1_id.to_string());
        
        // Check if relationships information is included
        if let Some(relationships) = output.get("relationships") {
            assert!(relationships.is_array());
            let rel_array = relationships.as_array().unwrap();
            if !rel_array.is_empty() {
                let rel = &rel_array[0];
                assert_eq!(rel.get("target_entity_id").unwrap().as_str().unwrap(), entity2_id.to_string());
                assert_eq!(rel.get("relationship_type").unwrap().as_str().unwrap(), "friends_with");
                let strength = rel.get("strength").unwrap().as_f64().unwrap();
                assert!((strength - 0.8).abs() < 0.001, "Expected strength around 0.8, got {}", strength);
            }
        }
    }

    #[tokio::test]
    async fn test_find_entity_invalid_params() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let find_tool = FindEntityTool::new(entity_manager.clone());

        // Test invalid user ID
        let params = json!({
            "user_id": "invalid-uuid",
            "criteria": {
                "type": "ByName",
                "name": "Test"
            }
        });

        let result = find_tool.execute(&params).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ToolError::InvalidParams(_)));
    }

    #[tokio::test]
    async fn test_get_entity_details_not_found() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let details_tool = GetEntityDetailsTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();
        let nonexistent_id = Uuid::new_v4();

        // Test getting details for non-existent entity
        let params = json!({
            "user_id": user.id.to_string(),
            "entity_id": nonexistent_id.to_string()
        });

        let result = details_tool.execute(&params).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ToolError::ExecutionFailed(_)));
    }
}