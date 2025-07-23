//! Tests for World Interaction Tools - Create and Update functionality
//!
//! This test suite validates the create_entity and update_entity tools
//! ensuring they correctly interact with the ECS system and enforce proper security.

use scribe_backend::{
    services::{
        EcsEntityManager, EntityManagerConfig,
        agentic::tools::{ScribeTool, ToolError},
    },
    test_helpers::{spawn_app, db::create_test_user},
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
    CreateEntityTool, UpdateEntityTool,
};

#[cfg(test)]
mod world_interaction_create_update_tests {
    use super::*;

    #[tokio::test]
    async fn test_create_entity_basic() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Test basic entity creation
        let params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Test Room",
            "archetype_signature": "Name|Position|SpatialArchetype|Temporal",
            "components": {
                "Name": {
                    "name": "Test Room",
                    "display_name": "A Test Room",
                    "aliases": []
                },
                "SpatialArchetype": {
                    "scale": "Intimate",
                    "hierarchical_level": 0,
                    "level_name": "Room"
                },
                "Position": {
                    "x": 0.0,
                    "y": 0.0,
                    "z": 0.0,
                    "zone": "test_zone"
                },
                "Temporal": {
                    "temporal_mode": "Persistent"
                }
            }
        });

        let result = create_tool.execute(&params).await.expect("Tool execution failed");
        
        let output: JsonValue = result;
        assert!(output.get("entity_id").unwrap().as_str().is_some());
        assert_eq!(output.get("name").unwrap().as_str().unwrap(), "Test Room");
        assert!(output.get("created").unwrap().as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_create_entity_with_parent_and_salience() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // First create a parent entity
        let parent_params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Building",
            "archetype_signature": "Name|SpatialArchetype|Position|Temporal",
            "components": {
                "Name": {"name": "Building", "display_name": "Main Building", "aliases": []},
                "SpatialArchetype": {"scale": "Planetary", "hierarchical_level": 0, "level_name": "Building"},
                "Position": {"x": 0.0, "y": 0.0, "z": 0.0, "zone": "city_center"},
                "Temporal": {"temporal_mode": "Persistent"}
            }
        });

        let parent_result = create_tool.execute(&parent_params).await.expect("Parent creation failed");
        let parent_id = parent_result.get("entity_id").unwrap().as_str().unwrap();

        // Create child entity with parent and salience
        let child_params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Office 101",
            "archetype_signature": "Name|SpatialArchetype|Position|Temporal|ParentLink|Salience",
            "parent_entity_id": parent_id,
            "salience_tier": "Secondary",
            "components": {
                "Name": {"name": "Office 101", "display_name": "Office 101", "aliases": ["Room 101"]},
                "SpatialArchetype": {"scale": "Intimate", "hierarchical_level": 1, "level_name": "Room"},
                "Position": {"x": 10.0, "y": 0.0, "z": 1.0, "zone": "first_floor"},
                "Temporal": {"temporal_mode": "Persistent"}
            }
        });

        let result = create_tool.execute(&child_params).await.expect("Child creation failed");
        
        let output: JsonValue = result;
        assert!(output.get("entity_id").unwrap().as_str().is_some());
        assert_eq!(output.get("name").unwrap().as_str().unwrap(), "Office 101");
        assert_eq!(output.get("parent_id").unwrap().as_str().unwrap(), parent_id);
        assert_eq!(output.get("salience").unwrap().as_str().unwrap(), "Secondary");
    }

    #[tokio::test]
    async fn test_update_entity_basic() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());
        let update_tool = UpdateEntityTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // First create an entity
        let create_params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Test Entity",
            "archetype_signature": "Name|Position",
            "components": {
                "Name": {"name": "Test Entity", "display_name": "Test Entity", "aliases": []},
                "Position": {"x": 0.0, "y": 0.0, "z": 0.0, "zone": "origin"}
            }
        });

        let create_result = create_tool.execute(&create_params).await.expect("Creation failed");
        let entity_id = create_result.get("entity_id").unwrap().as_str().unwrap();

        // Update the entity
        let update_params = json!({
            "user_id": user.id.to_string(),
            "entity_id": entity_id,
            "updates": [
                {
                    "component_type": "Position",
                    "operation": "Update",
                    "data": {"x": 10.0, "y": 20.0, "z": 5.0, "zone": "new_zone"}
                },
                {
                    "component_type": "Name",
                    "operation": "Update", 
                    "data": {"name": "Updated Entity", "display_name": "Updated Test Entity", "aliases": ["Old Name"]}
                }
            ]
        });

        let result = update_tool.execute(&update_params).await.expect("Update failed");
        
        let output: JsonValue = result;
        assert_eq!(output.get("entity_id").unwrap().as_str().unwrap(), entity_id);
        assert_eq!(output.get("updated_components").unwrap().as_array().unwrap().len(), 2);
        assert!(output.get("success").unwrap().as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_update_entity_add_component() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());
        let update_tool = UpdateEntityTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Create basic entity
        let create_params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Character",
            "archetype_signature": "Name|Position",
            "components": {
                "Name": {"name": "Character", "display_name": "Test Character", "aliases": []},
                "Position": {"x": 0.0, "y": 0.0, "z": 0.0, "zone": "start"}
            }
        });

        let create_result = create_tool.execute(&create_params).await.expect("Creation failed");
        let entity_id = create_result.get("entity_id").unwrap().as_str().unwrap();

        // Add relationships component
        let update_params = json!({
            "user_id": user.id.to_string(),
            "entity_id": entity_id,
            "updates": [
                {
                    "component_type": "Relationships",
                    "operation": "Add",
                    "data": {
                        "relationships": [
                            {
                                "target_entity_id": Uuid::new_v4().to_string(),
                                "relationship_type": "allied_with",
                                "trust": 0.7,
                                "affection": 0.6,
                                "metadata": {}
                            }
                        ]
                    }
                }
            ]
        });

        let result = update_tool.execute(&update_params).await.expect("Update failed");
        
        let output: JsonValue = result;
        assert_eq!(output.get("entity_id").unwrap().as_str().unwrap(), entity_id);
        assert_eq!(output.get("updated_components").unwrap().as_array().unwrap()[0].get("component_type").unwrap().as_str().unwrap(), "Relationships");
        assert_eq!(output.get("updated_components").unwrap().as_array().unwrap()[0].get("operation").unwrap().as_str().unwrap(), "Add");
    }

    #[tokio::test]
    async fn test_update_entity_remove_component() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());
        let update_tool = UpdateEntityTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();

        // Create entity with temporal component
        let create_params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Temporary Entity",
            "archetype_signature": "Name|Position|Temporal",
            "components": {
                "Name": {"name": "Temporary Entity", "display_name": "Temp", "aliases": []},
                "Position": {"x": 0.0, "y": 0.0, "z": 0.0, "zone": "temp_zone"},
                "Temporal": {"temporal_mode": "Ephemeral", "duration_seconds": 300}
            }
        });

        let create_result = create_tool.execute(&create_params).await.expect("Creation failed");
        let entity_id = create_result.get("entity_id").unwrap().as_str().unwrap();

        // Remove temporal component
        let update_params = json!({
            "user_id": user.id.to_string(),
            "entity_id": entity_id,
            "updates": [
                {
                    "component_type": "Temporal",
                    "operation": "Remove"
                }
            ]
        });

        let result = update_tool.execute(&update_params).await.expect("Update failed");
        
        let output: JsonValue = result;
        assert_eq!(output.get("entity_id").unwrap().as_str().unwrap(), entity_id);
        assert_eq!(output.get("updated_components").unwrap().as_array().unwrap()[0].get("component_type").unwrap().as_str().unwrap(), "Temporal");
        assert_eq!(output.get("updated_components").unwrap().as_array().unwrap()[0].get("operation").unwrap().as_str().unwrap(), "Remove");
    }

    #[tokio::test]
    async fn test_create_entity_invalid_params() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let create_tool = CreateEntityTool::new(entity_manager.clone());

        // Test with invalid user ID
        let params = json!({
            "user_id": "invalid-uuid",
            "entity_name": "Test",
            "archetype_signature": "Name",
            "components": {
                "Name": {"name": "Test", "display_name": "Test", "aliases": []}
            }
        });

        let result = create_tool.execute(&params).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ToolError::InvalidParams(_)));
    }

    #[tokio::test]
    async fn test_update_entity_not_found() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        let update_tool = UpdateEntityTool::new(entity_manager.clone());

        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();
        let nonexistent_id = Uuid::new_v4();

        // Try to update non-existent entity
        let update_params = json!({
            "user_id": user.id.to_string(),
            "entity_id": nonexistent_id.to_string(),
            "updates": [
                {
                    "component_type": "Name",
                    "operation": "Update",
                    "data": {"name": "Ghost", "display_name": "Ghost Entity", "aliases": []}
                }
            ]
        });

        let result = update_tool.execute(&update_params).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ToolError::ExecutionFailed(_)));
    }
}