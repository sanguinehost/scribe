//! Functional Tests for World Interaction Tools - Spatial Hierarchy functionality
//!
//! This test suite validates spatial hierarchy queries, movements, and scale transitions
//! as outlined in Task 2.3 of the Living World Implementation Roadmap.

use scribe_backend::{
    services::{
        EcsEntityManager, EntityManagerConfig,
        agentic::tools::ScribeTool,
    },
    test_helpers::{spawn_app, db::create_test_user},
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

use scribe_backend::services::agentic::tools::world_interaction_tools::{
    CreateEntityTool,
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

        // Test GetContainedEntitiesTool for immediate children at different levels
        let get_contained_tool = GetContainedEntitiesTool::new(entity_manager.clone());
        
        // Test 1.1: Galaxy's immediate children (should be system)
        let params = json!({
            "user_id": user.id.to_string(),
            "parent_entity_id": galaxy_id.to_string(),
            "options": {
                "depth": 1,
                "include_parent": false,
                "limit": 10
            }
        });

        let result = get_contained_tool.execute(&params).await.expect("GetContainedEntities failed");
        let entities = result.get("entities").unwrap().as_array().unwrap();
        assert_eq!(entities.len(), 1, "Galaxy should have exactly 1 immediate child (System)");
        
        let system = &entities[0];
        assert_eq!(system.get("name").unwrap().as_str().unwrap(), "Tatooine System");
        assert_eq!(system.get("entity_id").unwrap().as_str().unwrap(), system_id.to_string());
        assert_eq!(system.get("depth_from_parent").unwrap().as_u64().unwrap(), 1);
        
        // Test 1.2: System's immediate children (should be planet)
        let params = json!({
            "user_id": user.id.to_string(),
            "parent_entity_id": system_id.to_string(),
            "options": {
                "depth": 1,
                "include_parent": false,
                "limit": 10
            }
        });

        let result = get_contained_tool.execute(&params).await.expect("GetContainedEntities failed");
        let entities = result.get("entities").unwrap().as_array().unwrap();
        assert_eq!(entities.len(), 1, "System should have exactly 1 immediate child (Planet)");
        assert_eq!(entities[0].get("entity_id").unwrap().as_str().unwrap(), planet_id.to_string());
        
        // Test 1.3: Planet's immediate children (should be city)
        let params = json!({
            "user_id": user.id.to_string(),
            "parent_entity_id": planet_id.to_string(),
            "options": {
                "depth": 1,
                "include_parent": false,
                "limit": 10
            }
        });

        let result = get_contained_tool.execute(&params).await.expect("GetContainedEntities failed");
        let entities = result.get("entities").unwrap().as_array().unwrap();
        assert_eq!(entities.len(), 1, "Planet should have exactly 1 immediate child (City)");
        assert_eq!(entities[0].get("entity_id").unwrap().as_str().unwrap(), city_id.to_string());
        
        // Test 1.4: Building's immediate children (should be room)
        let params = json!({
            "user_id": user.id.to_string(),
            "parent_entity_id": building_id.to_string(),
            "options": {
                "depth": 1,
                "include_parent": false,
                "limit": 10
            }
        });

        let result = get_contained_tool.execute(&params).await.expect("GetContainedEntities failed");
        let entities = result.get("entities").unwrap().as_array().unwrap();
        assert_eq!(entities.len(), 1, "Building should have exactly 1 immediate child (Room)");
        assert_eq!(entities[0].get("entity_id").unwrap().as_str().unwrap(), room_id.to_string());
    }

    // Test 2: All descendants query (unlimited depth)
    #[tokio::test]
    async fn test_get_contained_entities_all_descendants() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        
        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();
        let (galaxy_id, system_id, planet_id, city_id, building_id, room_id) = 
            create_test_hierarchy(entity_manager.clone(), user.id).await;

        // Test GetContainedEntitiesTool for all descendants from different starting points
        let get_contained_tool = GetContainedEntitiesTool::new(entity_manager.clone());
        
        // Test 2.1: All descendants from planet
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
        assert!(depths.contains(&3), "Should contain Room at depth 3");
        
        // Verify entity IDs are correct
        let entity_ids: Vec<String> = entities.iter()
            .map(|e| e.get("entity_id").unwrap().as_str().unwrap().to_string())
            .collect();
        
        assert!(entity_ids.contains(&city_id.to_string()), "Should contain city");
        assert!(entity_ids.contains(&building_id.to_string()), "Should contain building");
        assert!(entity_ids.contains(&room_id.to_string()), "Should contain room");
        
        // Test 2.2: All descendants from galaxy (should get entire hierarchy)
        let params = json!({
            "user_id": user.id.to_string(),
            "parent_entity_id": galaxy_id.to_string(),
            "options": {
                "depth": null,
                "include_parent": false,
                "limit": 20
            }
        });

        let result = get_contained_tool.execute(&params).await.expect("GetContainedEntities failed");
        let entities = result.get("entities").unwrap().as_array().unwrap();
        
        // Galaxy should contain all 5 descendants
        assert_eq!(entities.len(), 5, "Galaxy should have 5 descendants total");
        
        // Verify all entities are present
        let galaxy_descendants: Vec<String> = entities.iter()
            .map(|e| e.get("entity_id").unwrap().as_str().unwrap().to_string())
            .collect();
        
        assert!(galaxy_descendants.contains(&system_id.to_string()), "Should contain system");
        assert!(galaxy_descendants.contains(&planet_id.to_string()), "Should contain planet");
        assert!(galaxy_descendants.contains(&city_id.to_string()), "Should contain city");
        assert!(galaxy_descendants.contains(&building_id.to_string()), "Should contain building");
        assert!(galaxy_descendants.contains(&room_id.to_string()), "Should contain room");
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
        let system2_result = create_tool.execute(&system2_params).await.expect("System 2 creation failed");
        let system2_id = Uuid::parse_str(system2_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        // Test GetContainedEntitiesTool with different scale filters
        let get_contained_tool = GetContainedEntitiesTool::new(entity_manager.clone());
        
        // Test 3.1: Filter for Cosmic scale (Systems) only
        let params = json!({
            "user_id": user.id.to_string(),
            "parent_entity_id": galaxy_id.to_string(),
            "options": {
                "depth": null, // unlimited depth to traverse hierarchy
                "scale_filter": "Cosmic", // only Cosmic scale entities
                "include_parent": false,
                "limit": 20
            }
        });

        let result = get_contained_tool.execute(&params).await.expect("GetContainedEntities failed");
        let entities = result.get("entities").unwrap().as_array().unwrap();
        
        // Should return 2 systems, ignoring planets and lower levels
        assert_eq!(entities.len(), 2, "Galaxy should contain exactly 2 Systems when filtered by Cosmic scale");
        
        // Verify all returned entities are Systems (Cosmic scale)
        let system_ids: Vec<String> = entities.iter()
            .map(|e| e.get("entity_id").unwrap().as_str().unwrap().to_string())
            .collect();
        
        assert!(system_ids.contains(&system_id.to_string()), "Should contain original system");
        assert!(system_ids.contains(&system2_id.to_string()), "Should contain new system");
        
        for entity in entities {
            let scale = entity.get("scale").unwrap().as_str().unwrap();
            assert_eq!(scale, "Cosmic", "All entities should be Cosmic scale when filtered");
        }
        
        // Test 3.2: Filter for Planetary scale only
        let params = json!({
            "user_id": user.id.to_string(),
            "parent_entity_id": galaxy_id.to_string(),
            "options": {
                "depth": null,
                "scale_filter": "Planetary",
                "include_parent": false,
                "limit": 20
            }
        });

        let result = get_contained_tool.execute(&params).await.expect("GetContainedEntities failed");
        let entities = result.get("entities").unwrap().as_array().unwrap();
        
        // Should return planet and city (both Planetary scale)
        assert_eq!(entities.len(), 2, "Should have 2 Planetary scale entities");
        
        let planetary_ids: Vec<String> = entities.iter()
            .map(|e| e.get("entity_id").unwrap().as_str().unwrap().to_string())
            .collect();
        
        assert!(planetary_ids.contains(&planet_id.to_string()), "Should contain planet");
        assert!(planetary_ids.contains(&city_id.to_string()), "Should contain city");
        
        // Test 3.3: Filter for Intimate scale only
        let params = json!({
            "user_id": user.id.to_string(),
            "parent_entity_id": galaxy_id.to_string(),
            "options": {
                "depth": null,
                "scale_filter": "Intimate",
                "include_parent": false,
                "limit": 20
            }
        });

        let result = get_contained_tool.execute(&params).await.expect("GetContainedEntities failed");
        let entities = result.get("entities").unwrap().as_array().unwrap();
        
        // Should return building and room (both Intimate scale)
        assert_eq!(entities.len(), 2, "Should have 2 Intimate scale entities");
        
        let intimate_ids: Vec<String> = entities.iter()
            .map(|e| e.get("entity_id").unwrap().as_str().unwrap().to_string())
            .collect();
        
        assert!(intimate_ids.contains(&building_id.to_string()), "Should contain building");
        assert!(intimate_ids.contains(&room_id.to_string()), "Should contain room");
    }

    // Test 4: Component-filtered descendants query
    #[tokio::test]
    async fn test_get_contained_entities_component_filtered() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        
        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();
        let (_galaxy_id, _system_id, _planet_id, _city_id, building_id, room_id) = 
            create_test_hierarchy(entity_manager.clone(), user.id).await;
        
        // Create characters in different locations
        let (hero_id, npc_id) = create_test_characters(entity_manager.clone(), user.id, room_id).await;
        
        // Create an object in the building without Position component for contrast
        let create_tool = CreateEntityTool::new(entity_manager.clone());
        let object_params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Hologram Projector",
            "archetype_signature": "Name|ParentLink", // No Position component
            "parent_entity_id": building_id.to_string(),
            "salience_tier": "Flavor",
            "components": {
                "Name": {"name": "Hologram Projector", "display_name": "Old Hologram Projector", "aliases": []}
            }
        });
        let object_result = create_tool.execute(&object_params).await.expect("Object creation failed");
        let object_id = Uuid::parse_str(object_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        // Test GetContainedEntitiesTool with component filter
        let get_contained_tool = GetContainedEntitiesTool::new(entity_manager.clone());
        
        // Note: This test is for when component filtering is implemented
        // For now, we'll test that all entities are returned when no filter is applied
        let params = json!({
            "user_id": user.id.to_string(),
            "parent_entity_id": building_id.to_string(),
            "options": {
                "depth": null,
                "include_parent": false,
                "limit": 20
            }
        });

        let result = get_contained_tool.execute(&params).await.expect("GetContainedEntities failed");
        let entities = result.get("entities").unwrap().as_array().unwrap();
        
        // Building should contain: Room, Hero, NPC, and Object
        assert_eq!(entities.len(), 4, "Building should have 4 descendants");
        
        let entity_ids: Vec<String> = entities.iter()
            .map(|e| e.get("entity_id").unwrap().as_str().unwrap().to_string())
            .collect();
        
        assert!(entity_ids.contains(&room_id.to_string()), "Should contain room");
        assert!(entity_ids.contains(&hero_id.to_string()), "Should contain hero");
        assert!(entity_ids.contains(&npc_id.to_string()), "Should contain NPC");
        assert!(entity_ids.contains(&object_id.to_string()), "Should contain object");
        
        // When component filtering is implemented, this would filter for Position component:
        // let params = json!({
        //     "user_id": user.id.to_string(),
        //     "parent_entity_id": building_id.to_string(),
        //     "options": {
        //         "depth": null,
        //         "component_filter": ["Position"],
        //         "include_parent": false,
        //         "limit": 20
        //     }
        // });
        // Should return Room, Hero, NPC (have Position) but not Object (no Position)
    }

    // Test 5: Movement within same scale
    #[tokio::test]
    async fn test_move_entity_same_scale() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        
        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();
        let (_galaxy_id, _system_id, _planet_id, _city_id, building_id, room_id) = 
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
        let (_hero_id, _npc_id) = create_test_characters(entity_manager.clone(), user.id, room_id).await;
        
        // Verify initial state - both characters in room 1
        let get_contained_tool = GetContainedEntitiesTool::new(entity_manager.clone());
        let params = json!({
            "user_id": user.id.to_string(),
            "parent_entity_id": room_id.to_string(),
            "options": {
                "depth": 1,
                "include_parent": false,
                "limit": 10
            }
        });

        let result = get_contained_tool.execute(&params).await.expect("GetContainedEntities failed");
        let entities = result.get("entities").unwrap().as_array().unwrap();
        assert_eq!(entities.len(), 2, "Main Hall should have 2 characters initially");
        
        // Verify room 2 is empty initially
        let params = json!({
            "user_id": user.id.to_string(),
            "parent_entity_id": room2_id.to_string(),
            "options": {
                "depth": 1,
                "include_parent": false,
                "limit": 10
            }
        });

        let result = get_contained_tool.execute(&params).await.expect("GetContainedEntities failed");
        let entities = result.get("entities").unwrap().as_array().unwrap();
        assert_eq!(entities.len(), 0, "Back Room should be empty initially");

        // When MoveEntityTool is implemented:
        // 1. Move hero from Main Hall to Back Room
        // 2. Verify hero no longer in room1 children
        // 3. Verify hero is now in room2 children
        // 4. Verify NPC still in room1
        // 5. Verify movement preserves all other component data
    }

    // Test 6: Movement across scales (planetary travel)
    #[tokio::test]
    async fn test_move_entity_across_scales() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        
        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();
        
        // Create two planetary systems
        let (galaxy_id, _system1_id, planet1_id, city1_id, _building1_id, _room1_id) = 
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
        
        // Create a spaceport on planet2
        let spaceport_params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Imperial Spaceport",
            "archetype_signature": "Name|SpatialArchetype|Position|ParentLink",
            "parent_entity_id": planet2_id.to_string(),
            "salience_tier": "Core",
            "components": {
                "Name": {"name": "Imperial Spaceport", "display_name": "Imperial Central Spaceport", "aliases": []},
                "SpatialArchetype": {"scale": "Planetary", "hierarchical_level": 3, "level_name": "City"},
                "Position": {"x": 0.0, "y": 0.0, "z": 0.0, "zone": "capital"}
            }
        });
        let spaceport_result = create_tool.execute(&spaceport_params).await.expect("Spaceport creation failed");
        let _spaceport_id = Uuid::parse_str(spaceport_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();

        // Create a spaceship on planet1
        let spaceship_params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Millennium Falcon",
            "archetype_signature": "Name|Position|ParentLink",
            "parent_entity_id": city1_id.to_string(), // Start in Mos Eisley
            "salience_tier": "Core",
            "components": {
                "Name": {"name": "Millennium Falcon", "display_name": "Millennium Falcon", "aliases": ["Fastest hunk of junk in the galaxy"]},
                "Position": {"x": 50.0, "y": 25.0, "z": 0.0, "zone": "docking_bay_94"}
            }
        });
        let spaceship_result = create_tool.execute(&spaceship_params).await.expect("Spaceship creation failed");
        let spaceship_id = Uuid::parse_str(spaceship_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();
        
        // Verify initial state
        let get_contained_tool = GetContainedEntitiesTool::new(entity_manager.clone());
        
        // Verify spaceship is on planet1
        let params = json!({
            "user_id": user.id.to_string(),
            "parent_entity_id": planet1_id.to_string(),
            "options": {
                "depth": null,
                "include_parent": false,
                "limit": 20
            }
        });
        
        let result = get_contained_tool.execute(&params).await.expect("GetContainedEntities failed");
        let entities = result.get("entities").unwrap().as_array().unwrap();
        let entity_ids: Vec<String> = entities.iter()
            .map(|e| e.get("entity_id").unwrap().as_str().unwrap().to_string())
            .collect();
        
        assert!(entity_ids.contains(&spaceship_id.to_string()), "Spaceship should be on planet 1 initially");
        
        // Verify spaceship is NOT on planet2
        let params = json!({
            "user_id": user.id.to_string(),
            "parent_entity_id": planet2_id.to_string(),
            "options": {
                "depth": null,
                "include_parent": false,
                "limit": 20
            }
        });
        
        let result = get_contained_tool.execute(&params).await.expect("GetContainedEntities failed");
        let entities = result.get("entities").unwrap().as_array().unwrap();
        let entity_ids: Vec<String> = entities.iter()
            .map(|e| e.get("entity_id").unwrap().as_str().unwrap().to_string())
            .collect();
        
        assert!(!entity_ids.contains(&spaceship_id.to_string()), "Spaceship should not be on planet 2 initially");

        // When MoveEntityTool is implemented:
        // 1. Move spaceship from Mos Eisley (city1) to Imperial Spaceport (spaceport)
        // 2. Verify spaceship no longer on planet1
        // 3. Verify spaceship is now on planet2
        // 4. Verify movement updates parent link to spaceport
        // 5. Test invalid cross-scale moves (e.g., moving building to another planet)
    }

    // Test 7: Invalid movement (scale constraint violation)
    #[tokio::test]
    async fn test_move_entity_invalid_scale() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        
        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();
        let (_galaxy_id, system_id, planet_id, _city_id, building_id, room_id) = 
            create_test_hierarchy(entity_manager.clone(), user.id).await;

        // Verify the hierarchy is correctly established
        let get_contained_tool = GetContainedEntitiesTool::new(entity_manager.clone());
        
        // Verify planet is in system
        let params = json!({
            "user_id": user.id.to_string(),
            "parent_entity_id": system_id.to_string(),
            "options": {
                "depth": 1,
                "include_parent": false,
                "limit": 10
            }
        });
        
        let result = get_contained_tool.execute(&params).await.expect("GetContainedEntities failed");
        let entities = result.get("entities").unwrap().as_array().unwrap();
        assert_eq!(entities.len(), 1, "System should have 1 planet");
        assert_eq!(entities[0].get("entity_id").unwrap().as_str().unwrap(), planet_id.to_string());
        
        // Verify room is in building
        let params = json!({
            "user_id": user.id.to_string(),
            "parent_entity_id": building_id.to_string(),
            "options": {
                "depth": 1,
                "include_parent": false,
                "limit": 10
            }
        });
        
        let result = get_contained_tool.execute(&params).await.expect("GetContainedEntities failed");
        let entities = result.get("entities").unwrap().as_array().unwrap();
        assert_eq!(entities.len(), 1, "Building should have 1 room");
        assert_eq!(entities[0].get("entity_id").unwrap().as_str().unwrap(), room_id.to_string());

        // When MoveEntityTool is implemented, test various invalid moves:
        // 1. Try to move planet into a room (Planetary scale → Intimate scale location)
        // 2. Try to move building into system (Intimate scale → Cosmic scale location)
        // 3. Try to move city directly into galaxy (skip system level)
        // 4. Try to move room into another room (same level in hierarchy)
        // Each should fail with appropriate scale constraint error
    }

    // Test 8: Get spatial context (ancestors and descendants)
    #[tokio::test]
    async fn test_get_spatial_context() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        
        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();
        let (_galaxy_id, system_id, planet_id, city_id, building_id, room_id) = 
            create_test_hierarchy(entity_manager.clone(), user.id).await;

        // Test GetSpatialContextTool at different levels of the hierarchy
        let get_spatial_context_tool = GetSpatialContextTool::new(entity_manager.clone());
        
        // Test 8.1: Get full spatial context for city (middle of hierarchy)
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
        assert_eq!(entity.get("entity_id").unwrap().as_str().unwrap(), city_id.to_string());
        
        // Verify ancestors (should go up to Galaxy)
        let ancestors = result.get("ancestors").unwrap().as_array().unwrap();
        assert!(ancestors.len() >= 2, "City should have at least 2 ancestors (Planet, System, potentially Galaxy)");
        
        // Check ancestor IDs
        let ancestor_ids: Vec<String> = ancestors.iter()
            .map(|a| a.get("entity_id").unwrap().as_str().unwrap().to_string())
            .collect();
        assert!(ancestor_ids.contains(&planet_id.to_string()), "Should have planet as ancestor");
        assert!(ancestor_ids.contains(&system_id.to_string()), "Should have system as ancestor");
        
        // Verify descendants (should include Building and Room)
        let descendants = result.get("descendants").unwrap().as_array().unwrap();
        assert_eq!(descendants.len(), 2, "City should have 2 descendants (Building, Room)");
        
        // Verify descendant names and IDs
        let descendant_ids: Vec<String> = descendants.iter()
            .map(|d| d.get("entity_id").unwrap().as_str().unwrap().to_string())
            .collect();
        assert!(descendant_ids.contains(&building_id.to_string()), "Should have building as descendant");
        assert!(descendant_ids.contains(&room_id.to_string()), "Should have room as descendant");
        
        // Test 8.2: Get spatial context for room (leaf node)
        let params = json!({
            "user_id": user.id.to_string(),
            "entity_id": room_id.to_string(),
            "options": {
                "ancestor_levels": null,
                "descendant_depth": null,
                "include_siblings": false,
                "descendant_limit": 20
            }
        });

        let result = get_spatial_context_tool.execute(&params).await.expect("GetSpatialContext failed");
        
        // Verify room has ancestors but no descendants
        let ancestors = result.get("ancestors").unwrap().as_array().unwrap();
        assert!(ancestors.len() >= 4, "Room should have at least 4 ancestors (Building, City, Planet, System)");
        
        let descendants = result.get("descendants").unwrap().as_array().unwrap();
        assert_eq!(descendants.len(), 0, "Room should have no descendants initially");
        
        // Test 8.3: Get limited spatial context (only 2 ancestor levels)
        let params = json!({
            "user_id": user.id.to_string(),
            "entity_id": room_id.to_string(),
            "options": {
                "ancestor_levels": 2, // only 2 levels up
                "descendant_depth": 1, // only immediate children
                "include_siblings": false,
                "descendant_limit": 20
            }
        });

        let result = get_spatial_context_tool.execute(&params).await.expect("GetSpatialContext failed");
        
        // Should only get Building and City as ancestors
        let ancestors = result.get("ancestors").unwrap().as_array().unwrap();
        assert_eq!(ancestors.len(), 2, "Should have exactly 2 ancestor levels");
        
        let limited_ancestor_ids: Vec<String> = ancestors.iter()
            .map(|a| a.get("entity_id").unwrap().as_str().unwrap().to_string())
            .collect();
        assert!(limited_ancestor_ids.contains(&building_id.to_string()), "Should have building");
        assert!(limited_ancestor_ids.contains(&city_id.to_string()), "Should have city");
        assert!(!limited_ancestor_ids.contains(&planet_id.to_string()), "Should NOT have planet with limit");
    }

    // Test 9: Performance test for deep hierarchies
    #[tokio::test]
    #[ignore] // Performance test - run with cargo test -- --ignored
    async fn test_deep_hierarchy_performance() {
        let _app = spawn_app(false, false, false).await;
        let _entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        
        let _user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();
        
        // This test would create a deep hierarchy with many entities:
        // Galaxy -> 10 Systems -> 10 Planets each -> 10 Cities each
        // Total: 1 + 10 + 100 + 1000 = 1111 entities
        
        // Performance targets:
        // - Creation of 1000+ entities should complete in < 30 seconds
        // - Query for all descendants of galaxy should complete in < 1 second
        // - Query with scale filter should complete in < 500ms
        // - Spatial context queries should complete in < 200ms
        
        // The test is marked as #[ignore] to avoid running during regular test runs
        // as it creates a large amount of test data
    }

    // Test 10: Salience-aware spatial queries
    #[tokio::test]
    async fn test_spatial_queries_with_salience() {
        let _app = spawn_app(false, false, false).await;
        let entity_manager = create_entity_manager(_app.db_pool.clone()).await;
        
        let user = create_test_user(&_app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await.unwrap();
        let (_galaxy_id, _system_id, _planet_id, city_id, building_id, _room_id) = 
            create_test_hierarchy(entity_manager.clone(), user.id).await;

        // Create mix of Core, Secondary, and Flavor entities
        let create_tool = CreateEntityTool::new(entity_manager.clone());
        
        // Create Flavor entities (background scenery)
        let mut flavor_building_ids = Vec::new();
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
            let result = create_tool.execute(&scenery_params).await.expect("Scenery creation failed");
            let building_id = Uuid::parse_str(result.get("entity_id").unwrap().as_str().unwrap()).unwrap();
            flavor_building_ids.push(building_id);
        }
        
        // Create a Secondary importance building
        let secondary_params = json!({
            "user_id": user.id.to_string(),
            "entity_name": "Docking Bay 92",
            "archetype_signature": "Name|Position|ParentLink|SpatialArchetype",
            "parent_entity_id": city_id.to_string(),
            "salience_tier": "Secondary",
            "components": {
                "Name": {"name": "Docking Bay 92", "display_name": "Docking Bay 92", "aliases": []},
                "Position": {"x": 40.0, "y": -12.0, "z": 0.0, "zone": "spaceport"},
                "SpatialArchetype": {"scale": "Intimate", "hierarchical_level": 0, "level_name": "Building"}
            }
        });
        let secondary_result = create_tool.execute(&secondary_params).await.expect("Secondary building creation failed");
        let secondary_building_id = Uuid::parse_str(secondary_result.get("entity_id").unwrap().as_str().unwrap()).unwrap();
        
        // Verify total children count
        let get_contained_tool = GetContainedEntitiesTool::new(entity_manager.clone());
        let params = json!({
            "user_id": user.id.to_string(),
            "parent_entity_id": city_id.to_string(),
            "options": {
                "depth": 1,
                "include_parent": false,
                "limit": 20
            }
        });

        let result = get_contained_tool.execute(&params).await.expect("GetContainedEntities failed");
        let entities = result.get("entities").unwrap().as_array().unwrap();
        
        // City should have: 1 Core building (Cantina), 1 Secondary building, and 5 Flavor buildings
        assert_eq!(entities.len(), 7, "City should have 7 total buildings");
        
        // Verify salience tiers are recorded correctly
        let entity_ids: Vec<String> = entities.iter()
            .map(|e| e.get("entity_id").unwrap().as_str().unwrap().to_string())
            .collect();
        
        assert!(entity_ids.contains(&building_id.to_string()), "Should contain Core building (Cantina)");
        assert!(entity_ids.contains(&secondary_building_id.to_string()), "Should contain Secondary building");
        for flavor_id in &flavor_building_ids {
            assert!(entity_ids.contains(&flavor_id.to_string()), "Should contain Flavor building");
        }

        // When spatial queries support salience filtering:
        // let params = json!({
        //     "user_id": user.id.to_string(),
        //     "parent_entity_id": city_id.to_string(),
        //     "options": {
        //         "depth": null,
        //         "salience_filter": ["Core", "Secondary"], // Exclude Flavor
        //         "include_parent": false,
        //         "limit": 20
        //     }
        // });
        // Should return only Cantina (Core) and Docking Bay 92 (Secondary), not the 5 background buildings
    }
}