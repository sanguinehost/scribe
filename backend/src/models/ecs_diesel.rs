// Diesel models for the ECS database tables
// These models handle database operations for entities, components, and relationships

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::schema::{ecs_entities, ecs_components, ecs_entity_relationships, ecs_outbox};

// ============================================================================
// Entity Models
// ============================================================================

/// Represents an ECS entity in the database
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = ecs_entities)]
#[diesel(primary_key(id))]
pub struct EcsEntity {
    pub id: Uuid,
    pub archetype_signature: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub user_id: Uuid,
}

/// Used to insert a new ECS entity
#[derive(Debug, Clone, Serialize, Deserialize, Insertable)]
#[diesel(table_name = ecs_entities)]
pub struct NewEcsEntity {
    pub id: Uuid,
    pub user_id: Uuid,
    pub archetype_signature: String,
}

/// Used to update an existing ECS entity
#[derive(Debug, Clone, AsChangeset)]
#[diesel(table_name = ecs_entities)]
pub struct UpdateEcsEntity {
    pub archetype_signature: Option<String>,
}

impl EcsEntity {
    /// Parse the archetype signature into component types
    pub fn component_types(&self) -> Vec<String> {
        self.archetype_signature
            .split('|')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }
    
    /// Check if this entity has a specific component type
    pub fn has_component_type(&self, component_type: &str) -> bool {
        self.component_types().contains(&component_type.to_string())
    }
}

// ============================================================================
// Component Models
// ============================================================================

/// Represents an ECS component in the database
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = ecs_components)]
#[diesel(primary_key(id))]
pub struct EcsComponent {
    pub id: Uuid,
    pub entity_id: Uuid,
    pub component_type: String,
    pub component_data: JsonValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub user_id: Uuid,
    pub encrypted_component_data: Option<Vec<u8>>,
    pub component_data_nonce: Option<Vec<u8>>,
}

/// Used to insert a new ECS component
#[derive(Debug, Clone, Serialize, Deserialize, Insertable)]
#[diesel(table_name = ecs_components)]
pub struct NewEcsComponent {
    pub id: Uuid,
    pub entity_id: Uuid,
    pub user_id: Uuid,
    pub component_type: String,
    pub component_data: JsonValue,
}

/// Used to update an existing ECS component
#[derive(Debug, Clone, AsChangeset)]
#[diesel(table_name = ecs_components)]
pub struct UpdateEcsComponent {
    pub component_data: Option<JsonValue>,
}

// ============================================================================
// Entity Relationship Models
// ============================================================================

/// Represents a relationship between two ECS entities
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = ecs_entity_relationships)]
#[diesel(primary_key(id))]
pub struct EcsEntityRelationship {
    pub id: Uuid,
    pub from_entity_id: Uuid,
    pub to_entity_id: Uuid,
    pub user_id: Uuid,
    pub relationship_type: String,
    pub relationship_data: JsonValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Used to insert a new entity relationship
#[derive(Debug, Clone, Serialize, Deserialize, Insertable)]
#[diesel(table_name = ecs_entity_relationships)]
pub struct NewEcsEntityRelationship {
    pub id: Uuid,
    pub from_entity_id: Uuid,
    pub to_entity_id: Uuid,
    pub user_id: Uuid,
    pub relationship_type: String,
    pub relationship_data: JsonValue,
}

/// Used to update an existing entity relationship
#[derive(Debug, Clone, AsChangeset)]
#[diesel(table_name = ecs_entity_relationships)]
pub struct UpdateEcsEntityRelationship {
    pub relationship_data: Option<JsonValue>,
}

// ============================================================================
// Outbox Models
// ============================================================================

/// Represents an ECS outbox event in the database
#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = ecs_outbox)]
#[diesel(primary_key(id))]
pub struct EcsOutboxEvent {
    pub id: Uuid,
    pub user_id: Uuid,
    pub sequence_number: i64,
    pub event_type: String,
    pub entity_id: Option<Uuid>,
    pub component_type: Option<String>,
    pub event_data: JsonValue,
    pub aggregate_id: Option<Uuid>,
    pub aggregate_type: Option<String>,
    pub created_at: DateTime<Utc>,
    pub processed_at: Option<DateTime<Utc>>,
    pub delivery_status: String,
    pub retry_count: i32,
    pub max_retries: i32,
    pub next_retry_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
}

/// Used to insert a new ECS outbox event
#[derive(Debug, Clone, Serialize, Deserialize, Insertable)]
#[diesel(table_name = ecs_outbox)]
pub struct NewEcsOutboxEvent {
    pub user_id: Uuid,
    pub event_type: String,
    pub entity_id: Option<Uuid>,
    pub component_type: Option<String>,
    pub event_data: JsonValue,
    pub aggregate_id: Option<Uuid>,
    pub aggregate_type: Option<String>,
    pub max_retries: Option<i32>,
}

/// Used to update an existing ECS outbox event
#[derive(Debug, Clone, AsChangeset)]
#[diesel(table_name = ecs_outbox)]
pub struct UpdateEcsOutboxEvent {
    pub processed_at: Option<Option<DateTime<Utc>>>,
    pub delivery_status: Option<String>,
    pub retry_count: Option<i32>,
    pub next_retry_at: Option<Option<DateTime<Utc>>>,
    pub error_message: Option<Option<String>>,
}

// ============================================================================
// Join Models and Complex Queries
// ============================================================================

/// Represents an entity with all its components loaded
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityWithComponents {
    pub entity: EcsEntity,
    pub components: Vec<EcsComponent>,
}

/// Represents an entity with its relationships
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityWithRelationships {
    pub entity: EcsEntity,
    pub outgoing_relationships: Vec<EcsEntityRelationship>,
    pub incoming_relationships: Vec<EcsEntityRelationship>,
}

// ============================================================================
// Query Builder Extensions
// ============================================================================

/// Extension trait for entity queries
pub trait EcsEntityExt {
    /// Find entities by component type
    fn with_component_type(self, component_type: &str) -> Self;
}

impl<'a> EcsEntityExt for ecs_entities::BoxedQuery<'a, diesel::pg::Pg> {
    fn with_component_type(self, component_type: &str) -> Self {
        self.filter(ecs_entities::archetype_signature.like(format!("%{}%", component_type)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_entity_component_types_parsing() {
        let entity = EcsEntity {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            archetype_signature: "Character|Health|Position".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        
        let types = entity.component_types();
        assert_eq!(types.len(), 3);
        assert!(types.contains(&"Character".to_string()));
        assert!(types.contains(&"Health".to_string()));
        assert!(types.contains(&"Position".to_string()));
    }
    
    #[test]
    fn test_entity_has_component_type() {
        let entity = EcsEntity {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            archetype_signature: "Character|Health|Position".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        
        assert!(entity.has_component_type("Health"));
        assert!(entity.has_component_type("Position"));
        assert!(!entity.has_component_type("Inventory"));
    }
}