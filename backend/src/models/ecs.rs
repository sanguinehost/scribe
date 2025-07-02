// Entity-Component-System (ECS) core types and traits
// This module provides the foundational types for the ECS architecture
// that works symbiotically with the Chronicle narrative system.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::any::{Any, TypeId};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use thiserror::Error;

/// Errors that can occur in the ECS system
#[derive(Error, Debug)]
pub enum EcsError {
    #[error("Component type '{0}' not registered")]
    ComponentNotRegistered(String),
    
    #[error("Failed to serialize component: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("Component type mismatch: expected '{expected}', got '{actual}'")]
    ComponentTypeMismatch { expected: String, actual: String },
    
    #[error("Invalid archetype signature: {0}")]
    InvalidArchetype(String),
}

/// Core trait that all components must implement
pub trait Component: Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static {
    /// Returns the type name of this component
    fn component_type() -> &'static str;
    
    /// Serialize the component to JSON
    fn to_json(&self) -> Result<JsonValue, EcsError> {
        Ok(serde_json::to_value(self)?)
    }
    
    /// Deserialize the component from JSON
    fn from_json(value: &JsonValue) -> Result<Self, EcsError> 
    where 
        Self: Sized 
    {
        Ok(serde_json::from_value(value.clone())?)
    }
}

/// Represents an entity in the ECS system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    id: Uuid,
    archetype_signature: String,
    component_types: Vec<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl Entity {
    /// Create a new entity with the given ID and archetype signature
    pub fn new(id: Uuid, archetype_signature: &str) -> Self {
        let component_types: Vec<String> = archetype_signature
            .split('|')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
            
        Self {
            id,
            archetype_signature: archetype_signature.to_string(),
            component_types,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
    
    /// Get the entity's ID
    pub fn id(&self) -> Uuid {
        self.id
    }
    
    /// Get the entity's archetype signature
    pub fn archetype_signature(&self) -> &str {
        &self.archetype_signature
    }
    
    /// Check if this entity has a specific component type
    pub fn has_component_type(&self, component_type: &str) -> bool {
        self.component_types.contains(&component_type.to_string())
    }
    
    /// Get all component types for this entity
    pub fn component_types(&self) -> &[String] {
        &self.component_types
    }
    
    /// Update the entity's timestamp
    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }
}

/// Registry for managing component types
pub struct ComponentRegistry {
    /// Maps component type names to their TypeId for runtime type checking
    type_map: HashMap<String, TypeId>,
    /// Stores component constructors
    constructors: HashMap<String, Box<dyn Fn(JsonValue) -> Result<Box<dyn Any + Send + Sync>, EcsError> + Send + Sync>>,
}

impl ComponentRegistry {
    /// Create a new empty component registry
    pub fn new() -> Self {
        Self {
            type_map: HashMap::new(),
            constructors: HashMap::new(),
        }
    }
    
    /// Register a component type with the registry
    pub fn register<T>(&mut self, type_name: &str) 
    where 
        T: Component + Clone + 'static
    {
        let type_id = TypeId::of::<T>();
        self.type_map.insert(type_name.to_string(), type_id);
        
        // Store a constructor function for this component type
        let constructor = move |json: JsonValue| -> Result<Box<dyn Any + Send + Sync>, EcsError> {
            let component = T::from_json(&json)?;
            Ok(Box::new(component))
        };
        
        self.constructors.insert(type_name.to_string(), Box::new(constructor));
    }
    
    /// Check if a component type is registered
    pub fn is_registered(&self, type_name: &str) -> bool {
        self.type_map.contains_key(type_name)
    }
    
    /// Create a component instance from JSON data
    pub fn create_component<T>(&self, type_name: &str, data: JsonValue) -> Result<T, EcsError>
    where
        T: Component + 'static
    {
        let constructor = self.constructors
            .get(type_name)
            .ok_or_else(|| EcsError::ComponentNotRegistered(type_name.to_string()))?;
            
        let boxed_component = constructor(data)?;
        
        // Downcast to the specific type
        boxed_component
            .downcast::<T>()
            .map(|boxed| *boxed)
            .map_err(|_| EcsError::ComponentTypeMismatch {
                expected: std::any::type_name::<T>().to_string(),
                actual: type_name.to_string(),
            })
    }
    
    /// Get the TypeId for a registered component type
    pub fn get_type_id(&self, type_name: &str) -> Option<&TypeId> {
        self.type_map.get(type_name)
    }
}

impl Default for ComponentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// Common component definitions

/// Health component for entities that can take damage
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HealthComponent {
    pub current: i32,
    pub max: i32,
    pub regeneration_rate: f32,
}

impl Component for HealthComponent {
    fn component_type() -> &'static str {
        "Health"
    }
}

/// Position component for entities with a location in the world
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PositionComponent {
    pub x: f64,
    pub y: f64,
    pub z: f64,
    pub zone: String,
}

impl Component for PositionComponent {
    fn component_type() -> &'static str {
        "Position"
    }
}

/// Inventory component for entities that can hold items
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InventoryComponent {
    pub items: Vec<InventoryItem>,
    pub capacity: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InventoryItem {
    pub entity_id: Uuid,
    pub quantity: u32,
    pub slot: Option<usize>,
}

impl Component for InventoryComponent {
    fn component_type() -> &'static str {
        "Inventory"
    }
}

/// Relationships component for tracking entity-to-entity relationships
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelationshipsComponent {
    pub relationships: Vec<Relationship>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Relationship {
    pub target_entity_id: Uuid,
    pub relationship_type: String,
    pub trust: f32,
    pub affection: f32,
    pub metadata: HashMap<String, JsonValue>,
}

impl Component for RelationshipsComponent {
    fn component_type() -> &'static str {
        "Relationships"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_entity_archetype_parsing() {
        let entity = Entity::new(Uuid::new_v4(), "Character|Health|Position|Inventory");
        assert_eq!(entity.component_types().len(), 4);
        assert!(entity.has_component_type("Character"));
        assert!(entity.has_component_type("Health"));
        assert!(entity.has_component_type("Position"));
        assert!(entity.has_component_type("Inventory"));
        assert!(!entity.has_component_type("Magic"));
    }
    
    #[test]
    fn test_empty_archetype() {
        let entity = Entity::new(Uuid::new_v4(), "");
        assert_eq!(entity.component_types().len(), 0);
    }
    
    #[test]
    fn test_component_serialization() {
        let health = HealthComponent {
            current: 85,
            max: 100,
            regeneration_rate: 2.5,
        };
        
        let json = health.to_json().unwrap();
        let deserialized = HealthComponent::from_json(&json).unwrap();
        
        assert_eq!(health, deserialized);
    }
}