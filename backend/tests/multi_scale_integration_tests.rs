// Multi-Scale Integration Tests
//
// Tests for Task 0.1.4: Write Multi-Scale Integration Tests
// These tests verify that the entire hierarchical spatial system works together
// across different scales, from cosmic to intimate, with proper entity creation,
// movement, and querying capabilities.

use scribe_backend::{
    models::ecs::{
        Component, EnhancedPositionComponent, PositionType, HierarchicalCoordinates,
        SpatialScale, SpatialArchetypeComponent, ParentLinkComponent, SpatialComponent,
        SpatialType, SpatialSize, SpatialConstraints, NameComponent, TemporalComponent,
    },
    services::{
        EcsEntityManager, 
        ecs_entity_manager::{ComponentQuery, EntityQueryResult},
    },
    test_helpers::{spawn_app, TestDataGuard, db::create_test_user},
    errors::AppError,
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

#[cfg(test)]
mod multi_scale_integration_tests {
    use super::*;

    // Helper function to create a spatial entity with full component suite
    async fn create_spatial_entity(
        entity_manager: &Arc<EcsEntityManager>,
        user_id: Uuid,
        name: &str,
        scale: SpatialScale,
        hierarchical_level: u32,
        parent_id: Option<Uuid>,
        position_type: PositionType,
    ) -> Result<Uuid, AppError> {
        let entity_id = Uuid::new_v4();
        
        // Create spatial archetype component
        let level_name = scale.level_name(hierarchical_level)
            .ok_or_else(|| AppError::InternalServerErrorGeneric(format!("Invalid level {} for scale {:?}", hierarchical_level, scale)))?;
        
        let spatial_archetype = SpatialArchetypeComponent::new(
            scale,
            hierarchical_level,
            level_name.to_string(),
        ).map_err(|e| AppError::InternalServerErrorGeneric(e))?;

        // Create enhanced position component
        let enhanced_position = EnhancedPositionComponent {
            position_type,
            movement_constraints: Vec::new(),
            last_updated: chrono::Utc::now(),
        };

        // Create name component
        let name_component = NameComponent {
            name: name.to_string(),
            display_name: name.to_string(),
            aliases: Vec::new(),
        };

        // Create temporal component
        let temporal_component = TemporalComponent::default();

        // Create spatial component based on level
        let spatial_component = if hierarchical_level == 0 {
            // Root level - can contain others
            SpatialComponent {
                spatial_type: SpatialType::Container {
                    capacity: None,
                    allowed_types: vec!["Location".to_string(), "Actor".to_string()],
                },
                constraints: SpatialConstraints {
                    allow_multiple_locations: false,
                    movable: false,
                    rules: Vec::new(),
                },
                metadata: std::collections::HashMap::new(),
            }
        } else {
            // Non-root level - both container and containable
            SpatialComponent {
                spatial_type: SpatialType::Nested {
                    container_props: Box::new(SpatialType::Container {
                        capacity: None,
                        allowed_types: vec!["Location".to_string(), "Actor".to_string()],
                    }),
                    containable_props: Box::new(SpatialType::Containable {
                        size: SpatialSize::Massive,
                        requires: vec!["Container".to_string()],
                    }),
                },
                constraints: SpatialConstraints {
                    allow_multiple_locations: false,
                    movable: false,
                    rules: Vec::new(),
                },
                metadata: std::collections::HashMap::new(),
            }
        };

        // Prepare components as (type, data) tuples
        let mut components = vec![
            ("SpatialArchetype".to_string(), spatial_archetype.to_json().map_err(|e| AppError::SerializationError(e.to_string()))?),
            ("EnhancedPosition".to_string(), enhanced_position.to_json().map_err(|e| AppError::SerializationError(e.to_string()))?),
            ("Name".to_string(), name_component.to_json().map_err(|e| AppError::SerializationError(e.to_string()))?),
            ("Temporal".to_string(), temporal_component.to_json().map_err(|e| AppError::SerializationError(e.to_string()))?),
            ("Spatial".to_string(), spatial_component.to_json().map_err(|e| AppError::SerializationError(e.to_string()))?),
        ];

        // Add parent link if this entity has a parent
        if let Some(parent_id) = parent_id {
            let parent_link = ParentLinkComponent {
                parent_entity_id: parent_id,
                depth_from_root: hierarchical_level,
                spatial_relationship: "contained_within".to_string(),
            };
            
            components.push(("ParentLink".to_string(), parent_link.to_json().map_err(|e| AppError::SerializationError(e.to_string()))?));
        }

        // Create the entity with all components
        entity_manager.create_entity(
            user_id,
            Some(entity_id),
            format!("SpatialArchetype|EnhancedPosition|Name|Temporal|Spatial{}", 
                    if parent_id.is_some() { "|ParentLink" } else { "" }),
            components,
        ).await?;

        Ok(entity_id)
    }

    #[tokio::test]
    async fn test_cosmic_hierarchy_star_wars() {
        // Test cosmic hierarchy: Create "Star Wars Universe" → "Outer Rim" → "Tatooine System" → "Tatooine"
        let app = spawn_app(false, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());
        
        let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string())
            .await.unwrap();

        let entity_manager = Arc::new(EcsEntityManager::new(
            Arc::new(app.db_pool.clone()),
            Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
            None,
        ));

        // Create cosmic hierarchy
        let universe_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Star Wars Universe",
            SpatialScale::Cosmic,
            0, // Universe level
            None,
            PositionType::Absolute {
                coordinates: HierarchicalCoordinates::new(0.0, 0.0, 0.0, SpatialScale::Cosmic),
            },
        ).await.expect("Failed to create universe");

        let galaxy_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Galaxy Far Far Away",
            SpatialScale::Cosmic,
            1, // Galaxy level
            Some(universe_id),
            PositionType::Relative {
                relative_to_entity: universe_id,
                coordinates: HierarchicalCoordinates::new(1000.0, 2000.0, 500.0, SpatialScale::Cosmic),
            },
        ).await.expect("Failed to create galaxy");

        let system_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Tatooine System",
            SpatialScale::Cosmic,
            2, // System level
            Some(galaxy_id),
            PositionType::Relative {
                relative_to_entity: galaxy_id,
                coordinates: HierarchicalCoordinates::new(500.0, 300.0, 100.0, SpatialScale::Cosmic),
            },
        ).await.expect("Failed to create system");

        let world_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Tatooine",
            SpatialScale::Cosmic,
            3, // World level
            Some(system_id),
            PositionType::Relative {
                relative_to_entity: system_id,
                coordinates: HierarchicalCoordinates::new(0.0, 0.0, 0.0, SpatialScale::Cosmic),
            },
        ).await.expect("Failed to create world");

        // Verify the hierarchy exists
        assert!(universe_id != Uuid::nil());
        assert!(galaxy_id != Uuid::nil());
        assert!(system_id != Uuid::nil());
        assert!(world_id != Uuid::nil());

        // Verify hierarchy relationships by checking ParentLink components
        let galaxy_entity = entity_manager.get_entity(user.id, galaxy_id).await
            .expect("Failed to get galaxy entity")
            .expect("Galaxy entity should exist");
        
        let galaxy_parent_link = galaxy_entity.components.iter()
            .find(|c| c.component_type == "ParentLink")
            .expect("Galaxy should have ParentLink component");
        
        let parent_link: ParentLinkComponent = serde_json::from_value(galaxy_parent_link.component_data.clone())
            .expect("Failed to deserialize ParentLink");
        
        assert_eq!(parent_link.parent_entity_id, universe_id);
        assert_eq!(parent_link.depth_from_root, 1);
        assert_eq!(parent_link.spatial_relationship, "contained_within");

        // Test cosmic scale entity movement across vast distances
        let spaceship_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Millennium Falcon",
            SpatialScale::Cosmic,
            3, // At world level initially
            Some(world_id),
            PositionType::Relative {
                relative_to_entity: world_id,
                coordinates: HierarchicalCoordinates::with_metadata(
                    100.0, 200.0, 50.0,
                    SpatialScale::Cosmic,
                    json!({
                        "docked_at": "Mos Eisley Spaceport",
                        "ship_type": "YT-1300 Light Freighter"
                    }).as_object().unwrap().clone(),
                ),
            },
        ).await.expect("Failed to create spaceship");

        // Verify spaceship was created successfully
        let spaceship_entity = entity_manager.get_entity(user.id, spaceship_id).await
            .expect("Failed to get spaceship entity")
            .expect("Spaceship entity should exist");
        
        let spaceship_position = spaceship_entity.components.iter()
            .find(|c| c.component_type == "EnhancedPosition")
            .expect("Spaceship should have EnhancedPosition component");
        
        let position: EnhancedPositionComponent = serde_json::from_value(spaceship_position.component_data.clone())
            .expect("Failed to deserialize EnhancedPosition");
        
        assert_eq!(position.scale(), SpatialScale::Cosmic);
        if let PositionType::Relative { relative_to_entity, coordinates } = &position.position_type {
            assert_eq!(*relative_to_entity, world_id);
            assert_eq!(coordinates.x, 100.0);
            assert_eq!(coordinates.metadata["docked_at"], "Mos Eisley Spaceport");
        } else {
            panic!("Expected relative position for spaceship");
        }

        println!("✅ Cosmic hierarchy test passed: Star Wars Universe → Galaxy → System → World");
    }

    #[tokio::test]
    async fn test_planetary_hierarchy_earth() {
        // Test planetary hierarchy: Create "Earth" → "Europe" → "France" → "Paris" → "Apartment"
        let app = spawn_app(false, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());
        
        let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string())
            .await.unwrap();

        let entity_manager = Arc::new(EcsEntityManager::new(
            Arc::new(app.db_pool.clone()),
            Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
            None,
        ));

        // Create planetary hierarchy
        let world_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Earth",
            SpatialScale::Planetary,
            0, // World level
            None,
            PositionType::Absolute {
                coordinates: HierarchicalCoordinates::with_metadata(
                    0.0, 0.0, 0.0,
                    SpatialScale::Planetary,
                    json!({
                        "planet_type": "terrestrial",
                        "population": 8000000000_u64,
                        "atmosphere": "oxygen_nitrogen"
                    }).as_object().unwrap().clone(),
                ),
            },
        ).await.expect("Failed to create Earth");

        let continent_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Europe",
            SpatialScale::Planetary,
            1, // Continent level
            Some(world_id),
            PositionType::Relative {
                relative_to_entity: world_id,
                coordinates: HierarchicalCoordinates::with_metadata(
                    48.8566, 2.3522, 0.0, // Approximate center of Europe
                    SpatialScale::Planetary,
                    json!({
                        "continent_code": "EU",
                        "time_zone": "CET"
                    }).as_object().unwrap().clone(),
                ),
            },
        ).await.expect("Failed to create Europe");

        let country_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "France",
            SpatialScale::Planetary,
            2, // Country level
            Some(continent_id),
            PositionType::Relative {
                relative_to_entity: continent_id,
                coordinates: HierarchicalCoordinates::with_metadata(
                    46.2276, 2.2137, 0.0, // Center of France
                    SpatialScale::Planetary,
                    json!({
                        "country_code": "FR",
                        "capital": "Paris",
                        "language": "French"
                    }).as_object().unwrap().clone(),
                ),
            },
        ).await.expect("Failed to create France");

        let city_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Paris",
            SpatialScale::Planetary,
            3, // City level
            Some(country_id),
            PositionType::Relative {
                relative_to_entity: country_id,
                coordinates: HierarchicalCoordinates::with_metadata(
                    48.8566, 2.3522, 35.0, // Paris coordinates with elevation
                    SpatialScale::Planetary,
                    json!({
                        "city_type": "capital",
                        "population": 2161000,
                        "arrondissements": 20
                    }).as_object().unwrap().clone(),
                ),
            },
        ).await.expect("Failed to create Paris");

        let district_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "7th Arrondissement",
            SpatialScale::Planetary,
            4, // District level
            Some(city_id),
            PositionType::Relative {
                relative_to_entity: city_id,
                coordinates: HierarchicalCoordinates::with_metadata(
                    48.8584, 2.2945, 35.0, // 7th arrondissement
                    SpatialScale::Planetary,
                    json!({
                        "district_name": "Palais-Bourbon",
                        "landmarks": ["Eiffel Tower", "Invalides"]
                    }).as_object().unwrap().clone(),
                ),
            },
        ).await.expect("Failed to create district");

        let building_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Haussmann Apartment Building",
            SpatialScale::Planetary,
            5, // Building level
            Some(district_id),
            PositionType::Relative {
                relative_to_entity: district_id,
                coordinates: HierarchicalCoordinates::with_metadata(
                    48.8584, 2.2945, 45.0, // Building with height
                    SpatialScale::Planetary,
                    json!({
                        "building_type": "residential",
                        "floors": 6,
                        "built_year": 1870
                    }).as_object().unwrap().clone(),
                ),
            },
        ).await.expect("Failed to create building");

        let apartment_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Apartment 3B",
            SpatialScale::Planetary,
            6, // Room level (maximum for planetary scale)
            Some(building_id),
            PositionType::Relative {
                relative_to_entity: building_id,
                coordinates: HierarchicalCoordinates::with_metadata(
                    3.0, 2.0, 8.5, // Apartment coordinates within building
                    SpatialScale::Planetary,
                    json!({
                        "floor": 3,
                        "apartment_type": "2_bedroom",
                        "tenant": "Office Worker"
                    }).as_object().unwrap().clone(),
                ),
            },
        ).await.expect("Failed to create apartment");

        // Verify complete planetary hierarchy
        let apartment_entity = entity_manager.get_entity(user.id, apartment_id).await
            .expect("Failed to get apartment entity")
            .expect("Apartment entity should exist");
        
        let apartment_parent_link = apartment_entity.components.iter()
            .find(|c| c.component_type == "ParentLink")
            .expect("Apartment should have ParentLink component");
        
        let parent_link: ParentLinkComponent = serde_json::from_value(apartment_parent_link.component_data.clone())
            .expect("Failed to deserialize ParentLink");
        
        assert_eq!(parent_link.parent_entity_id, building_id);
        assert_eq!(parent_link.depth_from_root, 6);

        // Test querying entities at different scales
        let all_entities = entity_manager.query_entities(
            user.id,
            vec![ComponentQuery::HasComponent("SpatialArchetype".to_string())],
            Some(100),
            None,
        ).await.expect("Failed to query entities");

        assert!(all_entities.len() >= 7); // At least 7 entities in the hierarchy

        println!("✅ Planetary hierarchy test passed: Earth → Europe → France → Paris → District → Building → Apartment");
    }

    #[tokio::test] 
    async fn test_entity_movement_across_scales() {
        // Test entity movement across scales: Player travels from "Tatooine" to "Coruscant" via "Hyperdrive"
        let app = spawn_app(false, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());
        
        let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string())
            .await.unwrap();

        let entity_manager = Arc::new(EcsEntityManager::new(
            Arc::new(app.db_pool.clone()),
            Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
            None,
        ));

        // Create a simplified galactic setup
        let galaxy_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Galaxy Far Far Away",
            SpatialScale::Cosmic,
            0, // Galaxy as root
            None,
            PositionType::Absolute {
                coordinates: HierarchicalCoordinates::new(0.0, 0.0, 0.0, SpatialScale::Cosmic),
            },
        ).await.expect("Failed to create galaxy");

        let tatooine_system_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Tatooine System",
            SpatialScale::Cosmic,
            1, // System level
            Some(galaxy_id),
            PositionType::Relative {
                relative_to_entity: galaxy_id,
                coordinates: HierarchicalCoordinates::new(1000.0, 500.0, 100.0, SpatialScale::Cosmic),
            },
        ).await.expect("Failed to create Tatooine system");

        let coruscant_system_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Coruscant System",
            SpatialScale::Cosmic,
            1, // System level
            Some(galaxy_id),
            PositionType::Relative {
                relative_to_entity: galaxy_id,
                coordinates: HierarchicalCoordinates::new(-500.0, 200.0, 300.0, SpatialScale::Cosmic),
            },
        ).await.expect("Failed to create Coruscant system");

        let tatooine_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Tatooine",
            SpatialScale::Cosmic,
            2, // World level
            Some(tatooine_system_id),
            PositionType::Relative {
                relative_to_entity: tatooine_system_id,
                coordinates: HierarchicalCoordinates::new(0.0, 0.0, 0.0, SpatialScale::Cosmic),
            },
        ).await.expect("Failed to create Tatooine");

        let coruscant_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Coruscant",
            SpatialScale::Cosmic,
            2, // World level
            Some(coruscant_system_id),
            PositionType::Relative {
                relative_to_entity: coruscant_system_id,
                coordinates: HierarchicalCoordinates::new(0.0, 0.0, 0.0, SpatialScale::Cosmic),
            },
        ).await.expect("Failed to create Coruscant");

        // Create a player character initially on Tatooine
        let player_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Luke Skywalker",
            SpatialScale::Cosmic,
            2, // At world level
            Some(tatooine_id),
            PositionType::Relative {
                relative_to_entity: tatooine_id,
                coordinates: HierarchicalCoordinates::with_metadata(
                    50.0, 100.0, 0.0,
                    SpatialScale::Cosmic,
                    json!({
                        "location": "Moisture Farm",
                        "status": "yearning_for_adventure"
                    }).as_object().unwrap().clone(),
                ),
            },
        ).await.expect("Failed to create player");

        // Verify initial position
        let initial_entity = entity_manager.get_entity(user.id, player_id).await
            .expect("Failed to get initial player entity")
            .expect("Player entity should exist");
        
        let initial_position = initial_entity.components.iter()
            .find(|c| c.component_type == "EnhancedPosition")
            .expect("Player should have EnhancedPosition component");
        
        let initial_pos: EnhancedPositionComponent = serde_json::from_value(initial_position.component_data.clone())
            .expect("Failed to deserialize initial position");
        
        if let PositionType::Relative { relative_to_entity, .. } = &initial_pos.position_type {
            assert_eq!(*relative_to_entity, tatooine_id);
        } else {
            panic!("Expected relative position on Tatooine");
        }

        // Simulate hyperdrive travel: Move player to Coruscant
        let new_position = EnhancedPositionComponent {
            position_type: PositionType::Relative {
                relative_to_entity: coruscant_id,
                coordinates: HierarchicalCoordinates::with_metadata(
                    200.0, 300.0, 1000.0, // High altitude arrival
                    SpatialScale::Cosmic,
                    json!({
                        "location": "Coruscant Space Traffic Control Zone",
                        "travel_method": "hyperdrive",
                        "arrival_time": chrono::Utc::now().to_rfc3339()
                    }).as_object().unwrap().clone(),
                ),
            },
            movement_constraints: vec!["requires_landing_clearance".to_string()],
            last_updated: chrono::Utc::now(),
        };

        // Update player position and parent link
        use scribe_backend::services::ecs_entity_manager::ComponentUpdate;
        
        let position_update = ComponentUpdate {
            entity_id: player_id,
            component_type: "EnhancedPosition".to_string(),
            component_data: new_position.to_json().expect("Failed to serialize new position"),
            operation: scribe_backend::services::ecs_entity_manager::ComponentOperation::Update,
        };

        let new_parent_link = ParentLinkComponent {
            parent_entity_id: coruscant_id,
            depth_from_root: 2,
            spatial_relationship: "contained_within".to_string(),
        };

        let parent_link_update = ComponentUpdate {
            entity_id: player_id,
            component_type: "ParentLink".to_string(),
            component_data: new_parent_link.to_json().expect("Failed to serialize new parent link"),
            operation: scribe_backend::services::ecs_entity_manager::ComponentOperation::Update,
        };

        entity_manager.update_components(user.id, player_id, vec![position_update, parent_link_update])
            .await.expect("Failed to update player components");

        // Verify movement was successful
        let final_entity = entity_manager.get_entity(user.id, player_id).await
            .expect("Failed to get final player entity")
            .expect("Player entity should exist");
        
        let final_position = final_entity.components.iter()
            .find(|c| c.component_type == "EnhancedPosition")
            .expect("Player should have EnhancedPosition component");
        
        let final_pos: EnhancedPositionComponent = serde_json::from_value(final_position.component_data.clone())
            .expect("Failed to deserialize final position");
        
        if let PositionType::Relative { relative_to_entity, coordinates } = &final_pos.position_type {
            assert_eq!(*relative_to_entity, coruscant_id);
            assert_eq!(coordinates.metadata["travel_method"], "hyperdrive");
            assert!(final_pos.has_constraint("requires_landing_clearance"));
        } else {
            panic!("Expected relative position on Coruscant");
        }

        let final_parent_link = final_entity.components.iter()
            .find(|c| c.component_type == "ParentLink")
            .expect("Player should have ParentLink component");
        
        let final_parent: ParentLinkComponent = serde_json::from_value(final_parent_link.component_data.clone())
            .expect("Failed to deserialize final parent link");
        
        assert_eq!(final_parent.parent_entity_id, coruscant_id);

        println!("✅ Cross-scale movement test passed: Luke traveled from Tatooine to Coruscant via hyperdrive");
    }

    #[tokio::test]
    async fn test_scale_appropriate_queries() {
        // Test scale-appropriate queries: "What's in this room?" vs "What systems are in this galaxy?"
        let app = spawn_app(false, false, false).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());
        
        let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string())
            .await.unwrap();

        let entity_manager = Arc::new(EcsEntityManager::new(
            Arc::new(app.db_pool.clone()),
            Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
            None,
        ));

        // Create a mixed-scale hierarchy for testing queries
        
        // Galaxy level
        let galaxy_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Test Galaxy",
            SpatialScale::Cosmic,
            0,
            None,
            PositionType::Absolute {
                coordinates: HierarchicalCoordinates::new(0.0, 0.0, 0.0, SpatialScale::Cosmic),
            },
        ).await.expect("Failed to create galaxy");

        // Multiple systems in the galaxy
        let system1_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Alpha System",
            SpatialScale::Cosmic,
            1,
            Some(galaxy_id),
            PositionType::Relative {
                relative_to_entity: galaxy_id,
                coordinates: HierarchicalCoordinates::new(100.0, 200.0, 50.0, SpatialScale::Cosmic),
            },
        ).await.expect("Failed to create Alpha system");

        let system2_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Beta System",
            SpatialScale::Cosmic,
            1,
            Some(galaxy_id),
            PositionType::Relative {
                relative_to_entity: galaxy_id,
                coordinates: HierarchicalCoordinates::new(-150.0, 300.0, -75.0, SpatialScale::Cosmic),
            },
        ).await.expect("Failed to create Beta system");

        let system3_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Gamma System",
            SpatialScale::Cosmic,
            1,
            Some(galaxy_id),
            PositionType::Relative {
                relative_to_entity: galaxy_id,
                coordinates: HierarchicalCoordinates::new(0.0, -100.0, 200.0, SpatialScale::Cosmic),
            },
        ).await.expect("Failed to create Gamma system");

        // Create a world in one system and drill down to room level
        let world_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Test World",
            SpatialScale::Cosmic,
            2,
            Some(system1_id),
            PositionType::Relative {
                relative_to_entity: system1_id,
                coordinates: HierarchicalCoordinates::new(0.0, 0.0, 0.0, SpatialScale::Cosmic),
            },
        ).await.expect("Failed to create world");

        // Switch to intimate scale for building/room level
        let building_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Test Building",
            SpatialScale::Intimate,
            0, // Building is root for intimate scale
            None,
            PositionType::Absolute {
                coordinates: HierarchicalCoordinates::with_metadata(
                    0.0, 0.0, 0.0,
                    SpatialScale::Intimate,
                    json!({
                        "building_type": "research_facility",
                        "parent_world": world_id.to_string()
                    }).as_object().unwrap().clone(),
                ),
            },
        ).await.expect("Failed to create building");

        let floor_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Floor 1",
            SpatialScale::Intimate,
            1,
            Some(building_id),
            PositionType::Relative {
                relative_to_entity: building_id,
                coordinates: HierarchicalCoordinates::new(0.0, 0.0, 3.0, SpatialScale::Intimate),
            },
        ).await.expect("Failed to create floor");

        let room_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Research Lab",
            SpatialScale::Intimate,
            2,
            Some(floor_id),
            PositionType::Relative {
                relative_to_entity: floor_id,
                coordinates: HierarchicalCoordinates::new(5.0, 10.0, 0.0, SpatialScale::Intimate),
            },
        ).await.expect("Failed to create room");

        // Add some objects/furniture in the room
        let _table_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Lab Table",
            SpatialScale::Intimate,
            3, // Area level
            Some(room_id),
            PositionType::Relative {
                relative_to_entity: room_id,
                coordinates: HierarchicalCoordinates::new(2.0, 3.0, 0.8, SpatialScale::Intimate),
            },
        ).await.expect("Failed to create table");

        let _chair_id = create_spatial_entity(
            &entity_manager,
            user.id,
            "Desk Chair",
            SpatialScale::Intimate,
            3, // Area level
            Some(room_id),
            PositionType::Relative {
                relative_to_entity: room_id,
                coordinates: HierarchicalCoordinates::new(2.5, 2.0, 0.4, SpatialScale::Intimate),
            },
        ).await.expect("Failed to create chair");

        // Query 1: "What systems are in this galaxy?" (Cosmic scale query)
        // Query for entities that have SpatialArchetype (this will include all spatial entities)
        let all_spatial_entities_query = vec![
            ComponentQuery::HasComponent("SpatialArchetype".to_string()),
        ];

        let all_entities = entity_manager.query_entities(user.id, all_spatial_entities_query, Some(50), None)
            .await.expect("Failed to query entities");

        // Filter entities that have galaxy as parent and are at system level
        let mut galaxy_systems = Vec::new();
        for entity_data in &all_entities {
            if let Some(parent_link_component) = entity_data.components.iter()
                .find(|c| c.component_type == "ParentLink") {
                
                let parent_link: ParentLinkComponent = serde_json::from_value(parent_link_component.component_data.clone())
                    .expect("Failed to deserialize ParentLink");
                
                if parent_link.parent_entity_id == galaxy_id && parent_link.depth_from_root == 1 {
                    if let Some(name_component) = entity_data.components.iter()
                        .find(|c| c.component_type == "Name") {
                        
                        let name: NameComponent = serde_json::from_value(name_component.component_data.clone())
                            .expect("Failed to deserialize Name");
                        
                        galaxy_systems.push(name.name);
                    }
                }
            }
        }

        galaxy_systems.sort();
        assert_eq!(galaxy_systems, vec!["Alpha System", "Beta System", "Gamma System"]);

        // Query 2: "What's in this room?" (Intimate scale query)
        let mut room_contents = Vec::new();
        for entity_data in &all_entities {
            if let Some(parent_link_component) = entity_data.components.iter()
                .find(|c| c.component_type == "ParentLink") {
                
                let parent_link: ParentLinkComponent = serde_json::from_value(parent_link_component.component_data.clone())
                    .expect("Failed to deserialize ParentLink");
                
                if parent_link.parent_entity_id == room_id {
                    if let Some(name_component) = entity_data.components.iter()
                        .find(|c| c.component_type == "Name") {
                        
                        let name: NameComponent = serde_json::from_value(name_component.component_data.clone())
                            .expect("Failed to deserialize Name");
                        
                        room_contents.push(name.name);
                    }
                }
            }
        }

        room_contents.sort();
        assert_eq!(room_contents, vec!["Desk Chair", "Lab Table"]);

        // Query 3: Test scale filtering by checking SpatialArchetype components
        let mut cosmic_entities = Vec::new();
        let mut intimate_entities = Vec::new();

        for entity_data in &all_entities {
            if let Some(spatial_archetype_component) = entity_data.components.iter()
                .find(|c| c.component_type == "SpatialArchetype") {
                
                let spatial_archetype: SpatialArchetypeComponent = serde_json::from_value(spatial_archetype_component.component_data.clone())
                    .expect("Failed to deserialize SpatialArchetype");
                
                if let Some(name_component) = entity_data.components.iter()
                    .find(|c| c.component_type == "Name") {
                    
                    let name: NameComponent = serde_json::from_value(name_component.component_data.clone())
                        .expect("Failed to deserialize Name");
                    
                    match spatial_archetype.scale {
                        SpatialScale::Cosmic => cosmic_entities.push(name.name),
                        SpatialScale::Intimate => intimate_entities.push(name.name),
                        _ => {}
                    }
                }
            }
        }

        cosmic_entities.sort();
        intimate_entities.sort();

        // Verify cosmic scale entities (galaxy, systems, world)
        assert!(cosmic_entities.contains(&"Test Galaxy".to_string()));
        assert!(cosmic_entities.contains(&"Alpha System".to_string()));
        assert!(cosmic_entities.contains(&"Beta System".to_string()));
        assert!(cosmic_entities.contains(&"Gamma System".to_string()));
        assert!(cosmic_entities.contains(&"Test World".to_string()));

        // Verify intimate scale entities (building, floor, room, furniture)
        assert!(intimate_entities.contains(&"Test Building".to_string()));
        assert!(intimate_entities.contains(&"Floor 1".to_string()));
        assert!(intimate_entities.contains(&"Research Lab".to_string()));
        assert!(intimate_entities.contains(&"Lab Table".to_string()));
        assert!(intimate_entities.contains(&"Desk Chair".to_string()));

        println!("✅ Scale-appropriate queries test passed:");
        println!("   Cosmic query found {} systems in galaxy: {:?}", galaxy_systems.len(), galaxy_systems);
        println!("   Intimate query found {} items in room: {:?}", room_contents.len(), room_contents);
        println!("   Scale filtering found {} cosmic and {} intimate entities", cosmic_entities.len(), intimate_entities.len());
    }
}