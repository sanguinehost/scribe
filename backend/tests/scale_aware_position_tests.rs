// Scale-Aware Position System Tests
//
// Tests for Task 0.1.3: Implement Scale-Aware Position System
// These tests verify that the enhanced Position component works with hierarchical coordinates
// and supports both absolute coordinates (for gods/spaceships) and relative coordinates (for mortals)

use scribe_backend::models::ecs::{
    Component, PositionComponent, SpatialScale, SpatialArchetypeComponent,
    ParentLinkComponent, EnhancedPositionComponent, PositionType, HierarchicalCoordinates,
};
use serde_json::json;
use uuid::Uuid;

#[cfg(test)]
mod enhanced_position_tests {
    use super::*;

    #[test]
    fn test_enhanced_position_component_type() {
        assert_eq!(EnhancedPositionComponent::component_type(), "EnhancedPosition");
    }

    #[test]
    fn test_relative_position_creation() {
        let tatooine_cantina_id = Uuid::new_v4();
        
        // Example: Position(relative_to: "Tatooine Cantina", coordinates: (15.2, 8.5, 0.0))
        let relative_position = EnhancedPositionComponent {
            position_type: PositionType::Relative {
                relative_to_entity: tatooine_cantina_id,
                coordinates: HierarchicalCoordinates {
                    x: 15.2,
                    y: 8.5,
                    z: 0.0,
                    scale: SpatialScale::Intimate,
                    metadata: json!({
                        "description": "Near the bar, facing the entrance"
                    }).as_object().unwrap().clone(),
                },
            },
            movement_constraints: vec!["requires_walking".to_string()],
            last_updated: chrono::Utc::now(),
        };

        // Test serialization/deserialization
        let json_value = relative_position.to_json().unwrap();
        let deserialized = EnhancedPositionComponent::from_json(&json_value).unwrap();
        assert_eq!(relative_position, deserialized);

        // Verify position type
        if let PositionType::Relative { relative_to_entity, coordinates } = &relative_position.position_type {
            assert_eq!(*relative_to_entity, tatooine_cantina_id);
            assert_eq!(coordinates.x, 15.2);
            assert_eq!(coordinates.y, 8.5);
            assert_eq!(coordinates.z, 0.0);
            assert_eq!(coordinates.scale, SpatialScale::Intimate);
        } else {
            panic!("Expected Relative position type");
        }
    }

    #[test]
    fn test_absolute_position_creation() {
        // Example: Galactic coordinates for a spaceship traveling between star systems
        let absolute_position = EnhancedPositionComponent {
            position_type: PositionType::Absolute {
                coordinates: HierarchicalCoordinates {
                    x: 12543.7,
                    y: -8921.4,
                    z: 2156.8,
                    scale: SpatialScale::Cosmic,
                    metadata: json!({
                        "coordinate_system": "galactic_standard",
                        "sector": "Outer Rim",
                        "velocity": [150.0, 75.0, -25.0]
                    }).as_object().unwrap().clone(),
                },
            },
            movement_constraints: vec!["requires_hyperdrive".to_string(), "needs_navigation".to_string()],
            last_updated: chrono::Utc::now(),
        };

        // Test serialization/deserialization
        let json_value = absolute_position.to_json().unwrap();
        let deserialized = EnhancedPositionComponent::from_json(&json_value).unwrap();
        assert_eq!(absolute_position, deserialized);

        // Verify position type
        if let PositionType::Absolute { coordinates } = &absolute_position.position_type {
            assert_eq!(coordinates.x, 12543.7);
            assert_eq!(coordinates.scale, SpatialScale::Cosmic);
            assert!(coordinates.metadata.contains_key("coordinate_system"));
            assert_eq!(coordinates.metadata["sector"], "Outer Rim");
        } else {
            panic!("Expected Absolute position type");
        }
    }

    #[test]
    fn test_hierarchical_coordinates_scale_validation() {
        // Test that coordinates can be created with different scales
        let cosmic_coords = HierarchicalCoordinates {
            x: 1000.0,
            y: 2000.0,
            z: 3000.0,
            scale: SpatialScale::Cosmic,
            metadata: serde_json::Map::new(),
        };

        let planetary_coords = HierarchicalCoordinates {
            x: 40.7128,
            y: -74.0060,
            z: 10.0,
            scale: SpatialScale::Planetary,
            metadata: json!({
                "city": "New York",
                "country": "USA"
            }).as_object().unwrap().clone(),
        };

        let intimate_coords = HierarchicalCoordinates {
            x: 5.5,
            y: 12.3,
            z: 1.2,
            scale: SpatialScale::Intimate,
            metadata: json!({
                "room": "Conference Room",
                "floor": "42nd"
            }).as_object().unwrap().clone(),
        };

        // Test that different scales can be serialized
        let cosmic_json = serde_json::to_string(&cosmic_coords).unwrap();
        let planetary_json = serde_json::to_string(&planetary_coords).unwrap();
        let intimate_json = serde_json::to_string(&intimate_coords).unwrap();

        // Test deserialization
        let cosmic_deserialized: HierarchicalCoordinates = serde_json::from_str(&cosmic_json).unwrap();
        let planetary_deserialized: HierarchicalCoordinates = serde_json::from_str(&planetary_json).unwrap();
        let intimate_deserialized: HierarchicalCoordinates = serde_json::from_str(&intimate_json).unwrap();

        assert_eq!(cosmic_coords, cosmic_deserialized);
        assert_eq!(planetary_coords, planetary_deserialized);
        assert_eq!(intimate_coords, intimate_deserialized);
    }

    #[test]
    fn test_scale_aware_movement_constraints() {
        // Test different movement constraints for different scales
        
        // Cosmic scale: spaceship movement
        let spaceship_position = EnhancedPositionComponent {
            position_type: PositionType::Absolute {
                coordinates: HierarchicalCoordinates {
                    x: 0.0,
                    y: 0.0,
                    z: 0.0,
                    scale: SpatialScale::Cosmic,
                    metadata: serde_json::Map::new(),
                },
            },
            movement_constraints: vec![
                "requires_hyperdrive".to_string(),
                "needs_navigation_computer".to_string(),
                "requires_pilot".to_string(),
            ],
            last_updated: chrono::Utc::now(),
        };

        // Planetary scale: character movement
        let character_position = EnhancedPositionComponent {
            position_type: PositionType::Relative {
                relative_to_entity: Uuid::new_v4(),
                coordinates: HierarchicalCoordinates {
                    x: 10.0,
                    y: 15.0,
                    z: 0.0,
                    scale: SpatialScale::Planetary,
                    metadata: serde_json::Map::new(),
                },
            },
            movement_constraints: vec![
                "requires_walking".to_string(),
                "limited_by_terrain".to_string(),
            ],
            last_updated: chrono::Utc::now(),
        };

        // Intimate scale: object movement
        let object_position = EnhancedPositionComponent {
            position_type: PositionType::Relative {
                relative_to_entity: Uuid::new_v4(),
                coordinates: HierarchicalCoordinates {
                    x: 2.5,
                    y: 1.8,
                    z: 0.9,
                    scale: SpatialScale::Intimate,
                    metadata: serde_json::Map::new(),
                },
            },
            movement_constraints: vec!["requires_carrying".to_string()],
            last_updated: chrono::Utc::now(),
        };

        // Verify constraints are preserved
        assert_eq!(spaceship_position.movement_constraints.len(), 3);
        assert!(spaceship_position.movement_constraints.contains(&"requires_hyperdrive".to_string()));
        
        assert_eq!(character_position.movement_constraints.len(), 2);
        assert!(character_position.movement_constraints.contains(&"requires_walking".to_string()));
        
        assert_eq!(object_position.movement_constraints.len(), 1);
        assert!(object_position.movement_constraints.contains(&"requires_carrying".to_string()));
    }

    #[test]
    fn test_position_integration_with_parent_link() {
        // Test that position works correctly with ParentLink component
        let tatooine_id = Uuid::new_v4();
        let cantina_id = Uuid::new_v4();
        
        // Character is in the cantina, which is on Tatooine
        let parent_link = ParentLinkComponent {
            parent_entity_id: cantina_id,
            depth_from_root: 3,
            spatial_relationship: "contained_within".to_string(),
        };

        let character_position = EnhancedPositionComponent {
            position_type: PositionType::Relative {
                relative_to_entity: cantina_id,
                coordinates: HierarchicalCoordinates {
                    x: 8.5,
                    y: 12.0,
                    z: 0.0,
                    scale: SpatialScale::Intimate,
                    metadata: json!({
                        "description": "Standing near the bar"
                    }).as_object().unwrap().clone(),
                },
            },
            movement_constraints: vec!["requires_walking".to_string()],
            last_updated: chrono::Utc::now(),
        };

        // Verify that parent link and position reference the same entity (cantina)
        if let PositionType::Relative { relative_to_entity, .. } = &character_position.position_type {
            assert_eq!(*relative_to_entity, parent_link.parent_entity_id);
        }

        assert_eq!(parent_link.depth_from_root, 3);
        assert_eq!(parent_link.spatial_relationship, "contained_within");
    }

    #[test]
    fn test_enhanced_position_serialization() {
        let entity_id = Uuid::new_v4();
        let position = EnhancedPositionComponent {
            position_type: PositionType::Relative {
                relative_to_entity: entity_id,
                coordinates: HierarchicalCoordinates {
                    x: 25.0,
                    y: 30.0,
                    z: 5.0,
                    scale: SpatialScale::Planetary,
                    metadata: json!({
                        "terrain": "urban",
                        "elevation": 150.5
                    }).as_object().unwrap().clone(),
                },
            },
            movement_constraints: vec!["requires_transportation".to_string()],
            last_updated: chrono::Utc::now(),
        };

        // Test JSON serialization round-trip
        let json_string = serde_json::to_string(&position).unwrap();
        let deserialized: EnhancedPositionComponent = serde_json::from_str(&json_string).unwrap();
        
        assert_eq!(position, deserialized);

        // Test Component trait methods
        let json_value = position.to_json().unwrap();
        let component_deserialized = EnhancedPositionComponent::from_json(&json_value).unwrap();
        
        assert_eq!(position, component_deserialized);
    }

    #[test]
    fn test_backward_compatibility_with_basic_position() {
        // Test that the enhanced system can still work with basic position data
        let basic_position = PositionComponent {
            x: 100.0,
            y: 200.0,
            z: 50.0,
            zone: "Tatooine_Desert".to_string(),
        };

        // Convert basic position to enhanced position
        let enhanced_from_basic = EnhancedPositionComponent::from_basic_position(
            &basic_position,
            SpatialScale::Planetary,
        );

        if let PositionType::Absolute { coordinates } = &enhanced_from_basic.position_type {
            assert_eq!(coordinates.x, 100.0);
            assert_eq!(coordinates.y, 200.0);
            assert_eq!(coordinates.z, 50.0);
            assert_eq!(coordinates.scale, SpatialScale::Planetary);
            assert_eq!(coordinates.metadata["zone"], "Tatooine_Desert");
        } else {
            panic!("Expected Absolute position type for converted basic position");
        }
    }

    #[test]
    fn test_star_wars_example_tatooine_cantina() {
        // Test the specific example from the roadmap:
        // Position(relative_to: "Tatooine Cantina", coordinates: (15.2, 8.5, 0.0))
        let cantina_id = Uuid::new_v4();
        
        let sol_position = EnhancedPositionComponent {
            position_type: PositionType::Relative {
                relative_to_entity: cantina_id,
                coordinates: HierarchicalCoordinates {
                    x: 15.2,
                    y: 8.5,
                    z: 0.0,
                    scale: SpatialScale::Intimate,
                    metadata: json!({
                        "container_name": "Tatooine Cantina",
                        "area": "Main Hall",
                        "facing": "entrance"
                    }).as_object().unwrap().clone(),
                },
            },
            movement_constraints: vec!["requires_walking".to_string()],
            last_updated: chrono::Utc::now(),
        };

        // Verify the exact coordinates match the roadmap example
        if let PositionType::Relative { coordinates, .. } = &sol_position.position_type {
            assert_eq!(coordinates.x, 15.2);
            assert_eq!(coordinates.y, 8.5);
            assert_eq!(coordinates.z, 0.0);
            assert_eq!(coordinates.scale, SpatialScale::Intimate);
            assert_eq!(coordinates.metadata["container_name"], "Tatooine Cantina");
        }
    }

    #[test]
    fn test_position_metadata_extensibility() {
        // Test that position metadata can be extended for different use cases
        let position_with_rich_metadata = EnhancedPositionComponent {
            position_type: PositionType::Absolute {
                coordinates: HierarchicalCoordinates {
                    x: 0.0,
                    y: 0.0,
                    z: 0.0,
                    scale: SpatialScale::Cosmic,
                    metadata: json!({
                        "coordinate_system": "galactic_standard",
                        "reference_frame": "core_worlds",
                        "velocity": {
                            "x": 150.0,
                            "y": 75.0,
                            "z": -25.0,
                            "units": "light_years_per_hour"
                        },
                        "navigation": {
                            "destination": "Coruscant System",
                            "route": "hyperspace_lane_7",
                            "eta": "2.5 hours"
                        },
                        "sensors": {
                            "range": 1000.0,
                            "scan_mode": "passive"
                        }
                    }).as_object().unwrap().clone(),
                },
            },
            movement_constraints: vec![
                "requires_hyperdrive".to_string(),
                "needs_astromech_droid".to_string(),
                "hyperspace_lane_required".to_string(),
            ],
            last_updated: chrono::Utc::now(),
        };

        // Test that rich metadata is preserved
        if let PositionType::Absolute { coordinates } = &position_with_rich_metadata.position_type {
            assert_eq!(coordinates.metadata["coordinate_system"], "galactic_standard");
            assert!(coordinates.metadata.contains_key("velocity"));
            assert!(coordinates.metadata.contains_key("navigation"));
            assert!(coordinates.metadata.contains_key("sensors"));
            
            // Test nested metadata access
            let velocity = &coordinates.metadata["velocity"];
            assert_eq!(velocity["x"], 150.0);
            assert_eq!(velocity["units"], "light_years_per_hour");
        }

        // Test serialization with rich metadata
        let json_value = position_with_rich_metadata.to_json().unwrap();
        let deserialized = EnhancedPositionComponent::from_json(&json_value).unwrap();
        assert_eq!(position_with_rich_metadata, deserialized);
    }
}