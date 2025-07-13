//! Functional Tests for World Interaction Tools - Spatial Hierarchy functionality
//!
//! This test suite validates spatial hierarchy queries, movements, and scale transitions
//! as outlined in Task 2.3 of the Living World Implementation Roadmap.

use scribe_backend::{
    models::ecs::{
        SpatialScale, SpatialArchetypeComponent,
        ParentLinkComponent, NameComponent, PositionComponent,
        PositionType, HierarchicalCoordinates, SalienceTier,
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
    CreateEntityTool, FindEntityTool, GetEntityDetailsTool,
};

// Import spatial tools
use scribe_backend::services::agentic::tools::world_interaction_tools::{
    GetContainedEntitiesTool, GetSpatialContextTool,
};

#[cfg(test)]
mod world_interaction_spatial_tests {
    use super::*;

    /// Helper function to create a hierarchical world structure for testing
    async fn create_test_hierarchy(
        entity_manager: Arc<EcsEntityManager>,
        user_id: Uuid,
    ) -> (Uuid, Uuid, Uuid, Uuid, Uuid, Uuid) {
        let create_tool = CreateEntityTool::new(entity_manager.clone());

        // Create Galaxy (root)
        let galaxy_params = json!({
            "user_id": user_id.to_string(),
            "entity_name": "Far Far Away Galaxy",
            "archetype_signature": "Name|SpatialArchetype|Position",
            "salience_tier": "Core",
            "components": {
                "Name": {"name": "Far Far Away Galaxy", "display_name": "Far Far Away", "aliases": []},
                "SpatialArchetype": {"scale": "Cosmic", "hierarchical_level": 0, "level_name": "Galaxy"},
                "Position": {"x": 0.0, "y": 0.0, "z": 0.0, "zone": "universe"}
            }
        });
        let galaxy_result = create_tool.execute(&galaxy_params).await.expect("Galaxy creation failed");
        let galaxy_id = Uuid::parse_str(galaxy_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        // Create System within Galaxy
        let system_params = json!({
            "user_id": user_id.to_string(),
            "entity_name": "Tatooine System",
            "archetype_signature": "Name|SpatialArchetype|Position|ParentLink",
            "parent_entity_id": galaxy_id.to_string(),
            "salience_tier": "Secondary",
            "components": {
                "Name": {"name": "Tatooine System", "display_name": "Tatooine System", "aliases": []},
                "SpatialArchetype": {"scale": "Cosmic", "hierarchical_level": 1, "level_name": "System"},
                "Position": {"x": 1000.0, "y": 500.0, "z": -200.0, "zone": "outer_rim"}
            }
        });
        let system_result = create_tool.execute(&system_params).await.expect("System creation failed");
        let system_id = Uuid::parse_str(system_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        // Create Planet within System
        let planet_params = json!({
            "user_id": user_id.to_string(),
            "entity_name": "Tatooine",
            "archetype_signature": "Name|SpatialArchetype|Position|ParentLink",
            "parent_entity_id": system_id.to_string(),
            "salience_tier": "Core",
            "components": {
                "Name": {"name": "Tatooine", "display_name": "Tatooine", "aliases": ["Desert Planet"]},
                "SpatialArchetype": {"scale": "Planetary", "hierarchical_level": 0, "level_name": "World"},
                "Position": {"x": 100.0, "y": 0.0, "z": 0.0, "zone": "habitable"}
            }
        });
        let planet_result = create_tool.execute(&planet_params).await.expect("Planet creation failed");
        let planet_id = Uuid::parse_str(planet_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        // Create City on Planet
        let city_params = json!({
            "user_id": user_id.to_string(),
            "entity_name": "Mos Eisley",
            "archetype_signature": "Name|SpatialArchetype|Position|ParentLink",
            "parent_entity_id": planet_id.to_string(),
            "salience_tier": "Secondary",
            "components": {
                "Name": {"name": "Mos Eisley", "display_name": "Mos Eisley Spaceport", "aliases": ["Wretched Hive"]},
                "SpatialArchetype": {"scale": "Planetary", "hierarchical_level": 3, "level_name": "City"},
                "Position": {"x": 45.3, "y": -12.7, "z": 0.0, "zone": "northern_dune_sea"}
            }
        });
        let city_result = create_tool.execute(&city_params).await.expect("City creation failed");
        let city_id = Uuid::parse_str(city_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        // Create Building in City
        let building_params = json!({
            "user_id": user_id.to_string(),
            "entity_name": "Mos Eisley Cantina",
            "archetype_signature": "Name|SpatialArchetype|Position|ParentLink",
            "parent_entity_id": city_id.to_string(),
            "salience_tier": "Core",
            "components": {
                "Name": {"name": "Mos Eisley Cantina", "display_name": "Chalmun's Cantina", "aliases": ["Cantina"]},
                "SpatialArchetype": {"scale": "Intimate", "hierarchical_level": 0, "level_name": "Building"},
                "Position": {"x": 12.5, "y": 8.3, "z": 0.0, "zone": "entertainment_district"}
            }
        });
        let building_result = create_tool.execute(&building_params).await.expect("Building creation failed");
        let building_id = Uuid::parse_str(building_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        // Create Room in Building
        let room_params = json!({
            "user_id": user_id.to_string(),
            "entity_name": "Main Hall",
            "archetype_signature": "Name|SpatialArchetype|Position|ParentLink",
            "parent_entity_id": building_id.to_string(),
            "salience_tier": "Flavor",
            "components": {
                "Name": {"name": "Main Hall", "display_name": "Cantina Main Hall", "aliases": []},
                "SpatialArchetype": {"scale": "Intimate", "hierarchical_level": 2, "level_name": "Room"},
                "Position": {"x": 0.0, "y": 0.0, "z": 0.0, "zone": "ground_floor"}
            }
        });
        let room_result = create_tool.execute(&room_params).await.expect("Room creation failed");
        let room_id = Uuid::parse_str(room_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        (galaxy_id, system_id, planet_id, city_id, building_id, room_id)
    }

    /// Helper function to create test characters
    async fn create_test_characters(
        entity_manager: Arc<EcsEntityManager>,
        user_id: Uuid,
        location_id: Uuid,
    ) -> (Uuid, Uuid) {
        let create_tool = CreateEntityTool::new(entity_manager.clone());

        // Create protagonist
        let hero_params = json!({
            "user_id": user_id.to_string(),
            "entity_name": "Luke Skywalker",
            "archetype_signature": "Name|Position|ParentLink",
            "parent_entity_id": location_id.to_string(),
            "salience_tier": "Core",
            "components": {
                "Name": {"name": "Luke Skywalker", "display_name": "Luke", "aliases": ["Young Skywalker"]},
                "Position": {"x": 5.0, "y": 3.0, "z": 0.0, "zone": "near_bar"}
            }
        });
        let hero_result = create_tool.execute(&hero_params).await.expect("Hero creation failed");
        let hero_id = Uuid::parse_str(hero_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        // Create NPC
        let npc_params = json!({
            "user_id": user_id.to_string(),
            "entity_name": "Greedo",
            "archetype_signature": "Name|Position|ParentLink",
            "parent_entity_id": location_id.to_string(),
            "salience_tier": "Secondary",
            "components": {
                "Name": {"name": "Greedo", "display_name": "Greedo", "aliases": ["Bounty Hunter"]},
                "Position": {"x": 7.0, "y": 3.0, "z": 0.0, "zone": "booth_4"}
            }
        });
        let npc_result = create_tool.execute(&npc_params).await.expect("NPC creation failed");
        let npc_id = Uuid::parse_str(npc_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        (hero_id, npc_id)
    }

    // Test 1: Basic immediate children query (depth=1)
    #[tokio::test]
    async fn test_get_contained_entities_immediate_children() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        
        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();
        let (galaxy_id, system_id, planet_id, city_id, building_id, room_id) = 
            create_test_hierarchy(entity_manager.clone(), user.id).await;

        // Test GetContainedEntitiesTool for immediate children only
        let get_contained_tool = GetContainedEntitiesTool::new(entity_manager.clone());
        let params = json!({
            "user_id": user.id.to_string(),
            "parent_entity_id": galaxy_id.to_string(),
            "options": {
                "depth": 1, // immediate children only
                "include_parent": false,
                "limit": 10
            }
        });

        let result = get_contained_tool.execute(&params).await.expect("GetContainedEntities failed");
        let entities = result.get("entities").unwrap().as_array().unwrap();
        assert_eq!(entities.len(), 1, "Galaxy should have exactly 1 immediate child (System)");
        
        let system = &entities[0];
        assert_eq!(system.get("name").unwrap().as_str().unwrap(), "Tatooine System");
        assert_eq!(system.get("depth_from_parent").unwrap().as_u64().unwrap(), 1);
    }

    // Test 2: All descendants query (unlimited depth)
    #[tokio::test]
    async fn test_get_contained_entities_all_descendants() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        
        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();
        let (galaxy_id, system_id, planet_id, city_id, building_id, room_id) = 
            create_test_hierarchy(entity_manager.clone(), user.id).await;

        // Test GetContainedEntitiesTool for all descendants
        let get_contained_tool = GetContainedEntitiesTool::new(entity_manager.clone());
        let params = json!({
            "user_id": user.id.to_string(),
            "parent_entity_id": planet_id.to_string(),
            "options": {
                "depth": null, // unlimited depth
                "include_parent": false,
                "limit": 20
            }
        });

        let result = get_contained_tool.execute(&params).await.expect("GetContainedEntities failed");
        let entities = result.get("entities").unwrap().as_array().unwrap();
        
        // Planet should contain: City (depth 1), Building (depth 2), Room (depth 3)
        assert_eq!(entities.len(), 3, "Planet should have 3 descendants at various depths");
        
        // Verify we have entities at different depths
        let depths: Vec<u64> = entities.iter()
            .map(|e| e.get("depth_from_parent").unwrap().as_u64().unwrap())
            .collect();
        
        // From planet: City (depth 1), Building (depth 2), Room (depth 3)
        assert!(depths.contains(&1), "Should contain City at depth 1"); 
        assert!(depths.contains(&2), "Should contain Building at depth 2");
    }

    // Test 3: Scale-filtered descendants query
    #[tokio::test]
    async fn test_get_contained_entities_scale_filtered() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        
        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();
        let (galaxy_id, system_id, planet_id, city_id, building_id, room_id) = 
            create_test_hierarchy(entity_manager.clone(), user.id).await;

        // Add another system to the galaxy
        let create_tool = CreateEntityTool::new(entity_manager.clone());
        let system2_params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Coruscant System",
            "archetype_signature": "Name|SpatialArchetype|Position|ParentLink",
            "parent_entity_id": galaxy_id.to_string(),
            "salience_tier": "Core",
            "components": {
                "Name": {"name": "Coruscant System", "display_name": "Core Worlds", "aliases": []},
                "SpatialArchetype": {"scale": "Cosmic", "hierarchical_level": 1, "level_name": "System"},
                "Position": {"x": 0.0, "y": 0.0, "z": 0.0, "zone": "core"}
            }
        });
        create_tool.execute(&system2_params).await.expect("System 2 creation failed");

        // Test GetContainedEntitiesTool with scale filter for systems only
        let get_contained_tool = GetContainedEntitiesTool::new(entity_manager.clone());
        let params = json!({
            "user_id": user.id.to_string(),
            "parent_entity_id": galaxy_id.to_string(),
            "options": {
                "depth": null, // unlimited depth to traverse hierarchy
                "scale_filter": "Cosmic", // only Cosmic scale entities (Systems)
                "include_parent": false,
                "limit": 20
            }
        });

        let result = get_contained_tool.execute(&params).await.expect("GetContainedEntities failed");
        let entities = result.get("entities").unwrap().as_array().unwrap();
        
        // Should return 2 systems, ignoring planets and lower levels
        assert_eq!(entities.len(), 2, "Galaxy should contain exactly 2 Systems when filtered by Cosmic scale");
        
        // Verify all returned entities are Systems (Cosmic scale)
        for entity in entities {
            let scale = entity.get("scale").unwrap().as_str().unwrap();
            assert_eq!(scale, "Cosmic", "All entities should be Cosmic scale when filtered");
        }
    }

    // Test 4: Component-filtered descendants query
    #[tokio::test]
    async fn test_get_contained_entities_component_filtered() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        
        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();
        let (galaxy_id, system_id, planet_id, city_id, building_id, room_id) = 
            create_test_hierarchy(entity_manager.clone(), user.id).await;
        
        // Create characters in different locations
        let (hero_id, npc_id) = create_test_characters(entity_manager.clone(), user.id, room_id).await;

        // When implemented:
        // Query for all entities with Position component on the planet
        // Should return characters and locations with Position components
    }

    // Test 5: Movement within same scale
    #[tokio::test]
    async fn test_move_entity_same_scale() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        
        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();
        let (galaxy_id, system_id, planet_id, city_id, building_id, room_id) = 
            create_test_hierarchy(entity_manager.clone(), user.id).await;

        // Create a second room in the building
        let create_tool = CreateEntityTool::new(entity_manager.clone());
        let room2_params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Back Room",
            "archetype_signature": "Name|SpatialArchetype|Position|ParentLink",
            "parent_entity_id": building_id.to_string(),
            "salience_tier": "Flavor",
            "components": {
                "Name": {"name": "Back Room", "display_name": "Cantina Back Room", "aliases": []},
                "SpatialArchetype": {"scale": "Intimate", "hierarchical_level": 2, "level_name": "Room"},
                "Position": {"x": 0.0, "y": -10.0, "z": 0.0, "zone": "ground_floor"}
            }
        });
        let room2_result = create_tool.execute(&room2_params).await.expect("Room 2 creation failed");
        let room2_id = Uuid::parse_str(room2_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        // Create character to move
        let (hero_id, _) = create_test_characters(entity_manager.clone(), user.id, room_id).await;

        // When MoveEntityTool is implemented:
        // Move hero from Main Hall to Back Room
        // Verify ParentLink is updated correctly
    }

    // Test 6: Movement across scales (planetary travel)
    #[tokio::test]
    async fn test_move_entity_across_scales() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        
        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();
        
        // Create two planetary systems
        let (galaxy_id, system1_id, planet1_id, _, _, _) = 
            create_test_hierarchy(entity_manager.clone(), user.id).await;
        
        // Create second system and planet
        let create_tool = CreateEntityTool::new(entity_manager.clone());
        let system2_params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Coruscant System",
            "archetype_signature": "Name|SpatialArchetype|Position|ParentLink",
            "parent_entity_id": galaxy_id.to_string(),
            "salience_tier": "Core",
            "components": {
                "Name": {"name": "Coruscant System", "display_name": "Core System", "aliases": []},
                "SpatialArchetype": {"scale": "Cosmic", "hierarchical_level": 1, "level_name": "System"},
                "Position": {"x": 0.0, "y": 0.0, "z": 0.0, "zone": "core"}
            }
        });
        let system2_result = create_tool.execute(&system2_params).await.expect("System 2 creation failed");
        let system2_id = Uuid::parse_str(system2_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        let planet2_params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Coruscant",
            "archetype_signature": "Name|SpatialArchetype|Position|ParentLink",
            "parent_entity_id": system2_id.to_string(),
            "salience_tier": "Core",
            "components": {
                "Name": {"name": "Coruscant", "display_name": "Coruscant", "aliases": ["Imperial Center"]},
                "SpatialArchetype": {"scale": "Planetary", "hierarchical_level": 0, "level_name": "World"},
                "Position": {"x": 0.0, "y": 0.0, "z": 0.0, "zone": "core"}
            }
        });
        let planet2_result = create_tool.execute(&planet2_params).await.expect("Planet 2 creation failed");
        let planet2_id = Uuid::parse_str(planet2_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        // When MoveEntityTool is implemented:
        // Create spaceship on planet1
        // Move spaceship from planet1 to planet2
        // Verify movement path and constraints
    }

    // Test 7: Invalid movement (scale constraint violation)
    #[tokio::test]
    async fn test_move_entity_invalid_scale() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        
        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();
        let (galaxy_id, system_id, planet_id, city_id, building_id, room_id) = 
            create_test_hierarchy(entity_manager.clone(), user.id).await;

        // When MoveEntityTool is implemented:
        // Try to move planet into a room (should fail)
        // Verify appropriate error is returned
    }

    // Test 8: Get spatial context (ancestors and descendants)
    #[tokio::test]
    async fn test_get_spatial_context() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        
        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();
        let (galaxy_id, system_id, planet_id, city_id, building_id, room_id) = 
            create_test_hierarchy(entity_manager.clone(), user.id).await;

        // Test GetSpatialContextTool to get full spatial context for city
        let get_spatial_context_tool = GetSpatialContextTool::new(entity_manager.clone());
        let params = json!({
            "user_id": user.id.to_string(),
            "entity_id": city_id.to_string(),
            "options": {
                "ancestor_levels": null, // all ancestors
                "descendant_depth": null, // all descendants
                "include_siblings": false,
                "descendant_limit": 20
            }
        });

        let result = get_spatial_context_tool.execute(&params).await.expect("GetSpatialContext failed");
        
        // Verify we have the focal entity
        let entity = result.get("entity").unwrap();
        assert_eq!(entity.get("name").unwrap().as_str().unwrap(), "Mos Eisley");
        
        // Verify ancestors (should go up to Galaxy)
        let ancestors = result.get("ancestors").unwrap().as_array().unwrap();
        assert!(ancestors.len() >= 2, "City should have at least 2 ancestors (Planet, System, potentially Galaxy)");
        
        // Verify descendants (should include Building and Room)
        let descendants = result.get("descendants").unwrap().as_array().unwrap();
        assert_eq!(descendants.len(), 2, "City should have 2 descendants (Building, Room)");
        
        // Verify descendant names
        let descendant_names: Vec<&str> = descendants.iter()
            .map(|d| d.get("name").unwrap().as_str().unwrap())
            .collect();
        assert!(descendant_names.contains(&"Mos Eisley Cantina"));
        assert!(descendant_names.contains(&"Main Hall"));
    }

    // Test 9: Performance test for deep hierarchies
    #[tokio::test]
    async fn test_deep_hierarchy_performance() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        
        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();
        
        // Create a deep hierarchy with many entities
        // Galaxy -> 10 Systems -> 10 Planets each -> 10 Cities each
        // Total: 1 + 10 + 100 + 1000 = 1111 entities
        
        // When spatial query tools are implemented:
        // Test query performance for getting all descendants of galaxy
        // Ensure response time is reasonable (< 1 second)
    }

    // Test 10: Salience-aware spatial queries
    #[tokio::test]
    async fn test_spatial_queries_with_salience() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        
        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();
        let (galaxy_id, system_id, planet_id, city_id, building_id, room_id) = 
            create_test_hierarchy(entity_manager.clone(), user.id).await;

        // Create mix of Core, Secondary, and Flavor entities
        let create_tool = CreateEntityTool::new(entity_manager.clone());
        
        // Create Flavor entities (background scenery)
        for i in 0..5 {
            let scenery_params = json!({
                "user_id": user.id.to_string(),
                "entity_name": format!("Background Building {}", i),
                "archetype_signature": "Name|Position|ParentLink",
                "parent_entity_id": city_id.to_string(),
                "salience_tier": "Flavor",
                "components": {
                    "Name": {"name": format!("Building {}", i), "display_name": format!("Building {}", i), "aliases": []},
                    "Position": {"x": i as f64 * 10.0, "y": 0.0, "z": 0.0, "zone": "outskirts"}
                }
            });
            create_tool.execute(&scenery_params).await.expect("Scenery creation failed");
        }

        // When spatial queries support salience filtering:
        // Query for Core entities only within the city
        // Should return only important buildings, not background scenery
    }
}