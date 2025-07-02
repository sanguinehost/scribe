#![cfg(test)]

use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

// Import the ECS types we'll be testing (will fail to compile until we implement them)
use scribe_backend::models::ecs::{Component, Entity, ComponentRegistry};

#[test]
fn test_entity_creation() {
    let entity_id = Uuid::new_v4();
    let archetype = "Character|Health|Position";
    
    let entity = Entity::new(entity_id, archetype);
    
    assert_eq!(entity.id(), entity_id);
    assert_eq!(entity.archetype_signature(), archetype);
    assert!(entity.has_component_type("Health"));
    assert!(entity.has_component_type("Position"));
    assert!(!entity.has_component_type("Inventory"));
}

#[test]
fn test_component_trait_implementation() {
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct HealthComponent {
        current: i32,
        max: i32,
        regeneration_rate: f32,
    }
    
    impl Component for HealthComponent {
        fn component_type() -> &'static str {
            "Health"
        }
    }
    
    let health = HealthComponent {
        current: 100,
        max: 100,
        regeneration_rate: 5.0,
    };
    
    // Test serialization
    let json_value = health.to_json().unwrap();
    assert_eq!(json_value["current"], 100);
    assert_eq!(json_value["max"], 100);
    assert_eq!(json_value["regeneration_rate"], 5.0);
    
    // Test deserialization
    let deserialized: HealthComponent = HealthComponent::from_json(&json_value).unwrap();
    assert_eq!(deserialized, health);
    
    // Test component type
    assert_eq!(HealthComponent::component_type(), "Health");
}

#[test]
fn test_position_component() {
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct PositionComponent {
        x: f64,
        y: f64,
        z: f64,
        zone: String,
    }
    
    impl Component for PositionComponent {
        fn component_type() -> &'static str {
            "Position"
        }
    }
    
    let position = PositionComponent {
        x: 10.5,
        y: 20.0,
        z: 0.0,
        zone: "tavern".to_string(),
    };
    
    let json_value = position.to_json().unwrap();
    assert_eq!(json_value["x"], 10.5);
    assert_eq!(json_value["zone"], "tavern");
}

#[test]
fn test_component_registry() {
    let mut registry = ComponentRegistry::new();
    
    // Register component types
    registry.register::<HealthComponent>("Health");
    registry.register::<PositionComponent>("Position");
    
    // Verify registration
    assert!(registry.is_registered("Health"));
    assert!(registry.is_registered("Position"));
    assert!(!registry.is_registered("Inventory"));
    
    // Test component creation from JSON
    let health_json = json!({
        "current": 85,
        "max": 100,
        "regeneration_rate": 3.0
    });
    
    let health_component = registry.create_component::<HealthComponent>("Health", health_json).unwrap();
    assert_eq!(health_component.current, 85);
}

// Example component implementations for testing
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct HealthComponent {
    current: i32,
    max: i32,
    regeneration_rate: f32,
}

impl Component for HealthComponent {
    fn component_type() -> &'static str {
        "Health"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct PositionComponent {
    x: f64,
    y: f64,
    z: f64,
    zone: String,
}

impl Component for PositionComponent {
    fn component_type() -> &'static str {
        "Position"
    }
}