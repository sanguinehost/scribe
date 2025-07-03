use diesel::prelude::*;
use scribe_backend::schema::{ecs_entities, ecs_components, ecs_entity_relationships};
use scribe_backend::test_helpers::spawn_app;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde_json::{json, Value as JsonValue};

// Simple ECS Entity struct for testing
#[derive(Debug, Queryable, Insertable, Selectable)]
#[diesel(table_name = ecs_entities)]
struct EcsEntity {
    pub id: Uuid,
    pub archetype_signature: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = ecs_entities)]
struct NewEcsEntity {
    pub id: Uuid,
    pub archetype_signature: String,
}

// ECS Component structs for testing
#[derive(Debug, Queryable, Insertable, Selectable)]
#[diesel(table_name = ecs_components)]
struct EcsComponent {
    pub id: Uuid,
    pub entity_id: Uuid,
    pub component_type: String,
    pub component_data: JsonValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = ecs_components)]
struct NewEcsComponent {
    pub id: Uuid,
    pub entity_id: Uuid,
    pub component_type: String,
    pub component_data: JsonValue,
}

// ECS Entity Relationship structs for testing
#[derive(Debug, Queryable, Insertable, Selectable)]
#[diesel(table_name = ecs_entity_relationships)]
struct EcsEntityRelationship {
    pub id: Uuid,
    pub from_entity_id: Uuid,
    pub to_entity_id: Uuid,
    pub relationship_type: String,
    pub relationship_data: JsonValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = ecs_entity_relationships)]
struct NewEcsEntityRelationship {
    pub id: Uuid,
    pub from_entity_id: Uuid,
    pub to_entity_id: Uuid,
    pub relationship_type: String,
    pub relationship_data: JsonValue,
}

#[tokio::test]
async fn test_ecs_entities_basic_crud() {
    let guard = spawn_app(false, false, false).await;
    let pool = &guard.db_pool;

    let test_entity_id = Uuid::new_v4();
    let test_archetype = "Character|Health|Position";

    // Test INSERT using diesel schema
    let new_entity = NewEcsEntity {
        id: test_entity_id,
        archetype_signature: test_archetype.to_string(),
    };

    let inserted_entity: EcsEntity = pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&new_entity)
                .returning(EcsEntity::as_returning())
                .get_result(conn)
        })
        .await
        .unwrap()
        .unwrap();

    // Verify the entity was inserted correctly
    assert_eq!(inserted_entity.id, test_entity_id);
    assert_eq!(inserted_entity.archetype_signature, test_archetype);
    assert!(inserted_entity.created_at <= Utc::now());
    assert!(inserted_entity.updated_at <= Utc::now());

    // Test SELECT
    let found_entity: EcsEntity = pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            ecs_entities::table
                .filter(ecs_entities::id.eq(test_entity_id))
                .select(EcsEntity::as_select())
                .first(conn)
        })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(found_entity.id, test_entity_id);
    assert_eq!(found_entity.archetype_signature, test_archetype);

    // Test UPDATE and verify updated_at timestamp changes
    let initial_updated_at = found_entity.updated_at;
    
    // Wait a moment to ensure timestamp difference
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let new_archetype = "Character|Health|Position|Inventory";
    let updated_entity: EcsEntity = pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::update(ecs_entities::table.filter(ecs_entities::id.eq(test_entity_id)))
                .set(ecs_entities::archetype_signature.eq(new_archetype))
                .returning(EcsEntity::as_returning())
                .get_result(conn)
        })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(updated_entity.archetype_signature, new_archetype);
    assert!(updated_entity.updated_at > initial_updated_at, "updated_at should be newer after update");
    assert_eq!(updated_entity.created_at, found_entity.created_at, "created_at should not change");

    // Test DELETE
    let deleted_count: usize = pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::delete(ecs_entities::table.filter(ecs_entities::id.eq(test_entity_id)))
                .execute(conn)
        })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(deleted_count, 1);

    // Verify entity was deleted
    let maybe_entity: Option<EcsEntity> = pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            ecs_entities::table
                .filter(ecs_entities::id.eq(test_entity_id))
                .select(EcsEntity::as_select())
                .first(conn)
                .optional()
        })
        .await
        .unwrap()
        .unwrap();

    assert!(maybe_entity.is_none(), "Entity should be deleted");
}

// ECS Component tests for Task 1.1.2
#[tokio::test]
async fn test_ecs_components_basic_crud() {
    let guard = spawn_app(false, false, false).await;
    let pool = &guard.db_pool;

    // First create an entity to associate components with
    let entity_id = Uuid::new_v4();
    let new_entity = NewEcsEntity {
        id: entity_id,
        archetype_signature: "Character|Health|Position".to_string(),
    };

    pool.get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&new_entity)
                .execute(conn)
        })
        .await
        .unwrap()
        .unwrap();

    // Test component data
    let component_id = Uuid::new_v4();
    let component_type = "Health";
    let component_data = json!({
        "current_health": 100,
        "max_health": 100,
        "regeneration_rate": 5
    });

    // Test INSERT using diesel schema - this validates our hybrid relational-document approach
    let new_component = NewEcsComponent {
        id: component_id,
        entity_id,
        component_type: component_type.to_string(),
        component_data: component_data.clone(),
    };

    let inserted_component: EcsComponent = pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::insert_into(ecs_components::table)
                .values(&new_component)
                .returning(EcsComponent::as_returning())
                .get_result(conn)
        })
        .await
        .unwrap()
        .unwrap();

    // Verify the component was inserted correctly
    assert_eq!(inserted_component.id, component_id);
    assert_eq!(inserted_component.entity_id, entity_id);
    assert_eq!(inserted_component.component_type, component_type);
    assert_eq!(inserted_component.component_data, component_data);
    assert!(inserted_component.created_at <= Utc::now());
    assert!(inserted_component.updated_at <= Utc::now());

    // Test SELECT
    let found_component: EcsComponent = pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            ecs_components::table
                .filter(ecs_components::id.eq(component_id))
                .select(EcsComponent::as_select())
                .first(conn)
        })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(found_component.id, component_id);
    assert_eq!(found_component.entity_id, entity_id);
    assert_eq!(found_component.component_type, component_type);
    assert_eq!(found_component.component_data, component_data);

    // Test UPDATE and verify updated_at timestamp changes
    let initial_updated_at = found_component.updated_at;
    
    // Wait a moment to ensure timestamp difference
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let new_component_data = json!({
        "current_health": 85,
        "max_health": 100,
        "regeneration_rate": 5,
        "status": "injured"
    });

    let new_component_data_clone = new_component_data.clone();
    let updated_component: EcsComponent = pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::update(ecs_components::table.filter(ecs_components::id.eq(component_id)))
                .set(ecs_components::component_data.eq(new_component_data_clone))
                .returning(EcsComponent::as_returning())
                .get_result(conn)
        })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(updated_component.component_data, new_component_data);
    assert!(updated_component.updated_at > initial_updated_at, "updated_at should be newer after update");
    assert_eq!(updated_component.created_at, found_component.created_at, "created_at should not change");

    // Test DELETE
    let deleted_count: usize = pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::delete(ecs_components::table.filter(ecs_components::id.eq(component_id)))
                .execute(conn)
        })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(deleted_count, 1);

    // Verify component was deleted
    let maybe_component: Option<EcsComponent> = pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            ecs_components::table
                .filter(ecs_components::id.eq(component_id))
                .select(EcsComponent::as_select())
                .first(conn)
                .optional()
        })
        .await
        .unwrap()
        .unwrap();

    assert!(maybe_component.is_none(), "Component should be deleted");

    // Clean up entity (this should cascade delete any remaining components)
    pool.get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::delete(ecs_entities::table.filter(ecs_entities::id.eq(entity_id)))
                .execute(conn)
        })
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn test_ecs_entities_archetype_signature_indexing() {
    let guard = spawn_app(false, false, false).await;
    let pool = &guard.db_pool;

    // Create multiple entities with different archetypes
    let archetypes = vec![
        "Character|Health|Position",
        "Character|Health|Position|Inventory", 
        "Item|Stackable",
        "Character|Health|Position|Magic",
    ];

    let mut entity_ids = Vec::new();

    for archetype in &archetypes {
        let entity_id = Uuid::new_v4();
        entity_ids.push(entity_id);
        
        let new_entity = NewEcsEntity {
            id: entity_id,
            archetype_signature: archetype.to_string(),
        };

        pool.get()
            .await
            .unwrap()
            .interact(move |conn| {
                diesel::insert_into(ecs_entities::table)
                    .values(&new_entity)
                    .execute(conn)
            })
            .await
            .unwrap()
            .unwrap();
    }

    // Test querying by archetype signature (this should use the index)
    let character_entities: Vec<EcsEntity> = pool
        .get()
        .await
        .unwrap()
        .interact(|conn| {
            ecs_entities::table
                .filter(ecs_entities::archetype_signature.like("Character%"))
                .select(EcsEntity::as_select())
                .load(conn)
        })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(character_entities.len(), 3);

    // Clean up
    for entity_id in entity_ids {
        pool.get()
            .await
            .unwrap()
            .interact(move |conn| {
                diesel::delete(ecs_entities::table.filter(ecs_entities::id.eq(entity_id)))
                    .execute(conn)
            })
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn test_ecs_components_unique_constraint() {
    let guard = spawn_app(false, false, false).await;
    let pool = &guard.db_pool;

    // Create an entity
    let entity_id = Uuid::new_v4();
    let new_entity = NewEcsEntity {
        id: entity_id,
        archetype_signature: "Character|Health".to_string(),
    };

    pool.get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&new_entity)
                .execute(conn)
        })
        .await
        .unwrap()
        .unwrap();

    // Create first component
    let component1_id = Uuid::new_v4();
    let new_component1 = NewEcsComponent {
        id: component1_id,
        entity_id,
        component_type: "Health".to_string(),
        component_data: json!({"health": 100}),
    };

    pool.get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::insert_into(ecs_components::table)
                .values(&new_component1)
                .execute(conn)
        })
        .await
        .unwrap()
        .unwrap();

    // Try to create duplicate component - should fail due to unique constraint
    let component2_id = Uuid::new_v4();
    let new_component2 = NewEcsComponent {
        id: component2_id,
        entity_id,
        component_type: "Health".to_string(), // Same type
        component_data: json!({"health": 50}),
    };

    let duplicate_result = pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::insert_into(ecs_components::table)
                .values(&new_component2)
                .execute(conn)
        })
        .await
        .unwrap();

    // Should fail with unique constraint violation
    assert!(duplicate_result.is_err(), "Should fail due to unique constraint");

    // Clean up
    pool.get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::delete(ecs_entities::table.filter(ecs_entities::id.eq(entity_id)))
                .execute(conn)
        })
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn test_ecs_components_cascade_deletion() {
    let guard = spawn_app(false, false, false).await;
    let pool = &guard.db_pool;

    // Create an entity
    let entity_id = Uuid::new_v4();
    let new_entity = NewEcsEntity {
        id: entity_id,
        archetype_signature: "Character|Health|Position".to_string(),
    };

    pool.get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&new_entity)
                .execute(conn)
        })
        .await
        .unwrap()
        .unwrap();

    // Create multiple components for the entity
    let component_ids = vec![Uuid::new_v4(), Uuid::new_v4()];
    let component_types = vec!["Health", "Position"];
    
    for (_i, (&component_id, &component_type)) in component_ids.iter().zip(component_types.iter()).enumerate() {
        let component_data = match component_type {
            "Health" => json!({"current_health": 100, "max_health": 100}),
            "Position" => json!({"x": 10.0, "y": 20.0, "z": 0.0}),
            _ => json!({}),
        };

        let new_component = NewEcsComponent {
            id: component_id,
            entity_id,
            component_type: component_type.to_string(),
            component_data,
        };

        pool.get()
            .await
            .unwrap()
            .interact(move |conn| {
                diesel::insert_into(ecs_components::table)
                    .values(&new_component)
                    .execute(conn)
            })
            .await
            .unwrap()
            .unwrap();
    }

    // Verify components exist
    let components_count_before: i64 = pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            ecs_components::table
                .filter(ecs_components::entity_id.eq(entity_id))
                .count()
                .get_result(conn)
        })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(components_count_before, 2);

    // Delete the entity - should cascade delete all components
    pool.get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::delete(ecs_entities::table.filter(ecs_entities::id.eq(entity_id)))
                .execute(conn)
        })
        .await
        .unwrap()
        .unwrap();

    // Verify all components were cascade deleted
    let components_count_after: i64 = pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            ecs_components::table
                .filter(ecs_components::entity_id.eq(entity_id))
                .count()
                .get_result(conn)
        })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(components_count_after, 0, "All components should be cascade deleted");
}

// ECS Entity Relationships tests for Task 1.1.3
#[tokio::test]
async fn test_ecs_entity_relationships_basic_crud() {
    let guard = spawn_app(false, false, false).await;
    let pool = &guard.db_pool;

    // Create two entities to establish a relationship between
    let parent_entity_id = Uuid::new_v4();
    let child_entity_id = Uuid::new_v4();
    
    let parent_entity = NewEcsEntity {
        id: parent_entity_id,
        archetype_signature: "Character|Inventory".to_string(),
    };
    
    let child_entity = NewEcsEntity {
        id: child_entity_id,
        archetype_signature: "Item|Stackable".to_string(),
    };

    // Insert both entities
    pool.get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&parent_entity)
                .execute(conn)
        })
        .await
        .unwrap()
        .unwrap();

    pool.get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&child_entity)
                .execute(conn)
        })
        .await
        .unwrap()
        .unwrap();

    // Testing relationship: parent "contains" child (inventory relationship)
    let relationship_id = Uuid::new_v4();
    let relationship_type = "contains";
    let relationship_data = json!({
        "container_slot": 0,
        "quantity": 5
    });

    // Test INSERT using diesel schema
    let new_relationship = NewEcsEntityRelationship {
        id: relationship_id,
        from_entity_id: parent_entity_id,
        to_entity_id: child_entity_id,
        relationship_type: relationship_type.to_string(),
        relationship_data: relationship_data.clone(),
    };

    let inserted_relationship: EcsEntityRelationship = pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::insert_into(ecs_entity_relationships::table)
                .values(&new_relationship)
                .returning(EcsEntityRelationship::as_returning())
                .get_result(conn)
        })
        .await
        .unwrap()
        .unwrap();

    // Verify the relationship was inserted correctly
    assert_eq!(inserted_relationship.id, relationship_id);
    assert_eq!(inserted_relationship.from_entity_id, parent_entity_id);
    assert_eq!(inserted_relationship.to_entity_id, child_entity_id);
    assert_eq!(inserted_relationship.relationship_type, relationship_type);
    assert_eq!(inserted_relationship.relationship_data, relationship_data);
    assert!(inserted_relationship.created_at <= Utc::now());
    assert!(inserted_relationship.updated_at <= Utc::now());

    // Test SELECT
    let found_relationship: EcsEntityRelationship = pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            ecs_entity_relationships::table
                .filter(ecs_entity_relationships::id.eq(relationship_id))
                .select(EcsEntityRelationship::as_select())
                .first(conn)
        })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(found_relationship.id, relationship_id);
    assert_eq!(found_relationship.from_entity_id, parent_entity_id);
    assert_eq!(found_relationship.to_entity_id, child_entity_id);
    assert_eq!(found_relationship.relationship_type, relationship_type);
    assert_eq!(found_relationship.relationship_data, relationship_data);

    // Test UPDATE and verify updated_at timestamp changes
    let initial_updated_at = found_relationship.updated_at;
    
    // Wait a moment to ensure timestamp difference
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let new_relationship_data = json!({
        "container_slot": 1,
        "quantity": 3,
        "last_moved": "2025-07-02T10:00:00Z"
    });

    let new_relationship_data_clone = new_relationship_data.clone();
    let updated_relationship: EcsEntityRelationship = pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::update(ecs_entity_relationships::table.filter(ecs_entity_relationships::id.eq(relationship_id)))
                .set(ecs_entity_relationships::relationship_data.eq(new_relationship_data_clone))
                .returning(EcsEntityRelationship::as_returning())
                .get_result(conn)
        })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(updated_relationship.relationship_data, new_relationship_data);
    assert!(updated_relationship.updated_at > initial_updated_at, "updated_at should be newer after update");
    assert_eq!(updated_relationship.created_at, found_relationship.created_at, "created_at should not change");

    // Test DELETE
    let deleted_count: usize = pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::delete(ecs_entity_relationships::table.filter(ecs_entity_relationships::id.eq(relationship_id)))
                .execute(conn)
        })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(deleted_count, 1);

    // Verify relationship was deleted
    let maybe_relationship: Option<EcsEntityRelationship> = pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            ecs_entity_relationships::table
                .filter(ecs_entity_relationships::id.eq(relationship_id))
                .select(EcsEntityRelationship::as_select())
                .first(conn)
                .optional()
        })
        .await
        .unwrap()
        .unwrap();

    assert!(maybe_relationship.is_none(), "Relationship should be deleted");

    // Clean up entities (this should cascade delete any remaining relationships)
    for entity_id in [parent_entity_id, child_entity_id] {
        pool.get()
            .await
            .unwrap()
            .interact(move |conn| {
                diesel::delete(ecs_entities::table.filter(ecs_entities::id.eq(entity_id)))
                    .execute(conn)
            })
            .await
            .unwrap()
            .unwrap();
    }
}