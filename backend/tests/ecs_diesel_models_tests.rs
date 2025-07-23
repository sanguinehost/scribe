#![cfg(test)]

use diesel::prelude::*;
use scribe_backend::models::ecs_diesel::{
    EcsEntity, NewEcsEntity, UpdateEcsEntity,
    EcsComponent, NewEcsComponent, UpdateEcsComponent,
    EcsEntityRelationship, NewEcsEntityRelationship,
};
use scribe_backend::schema::{ecs_entities, ecs_components, ecs_entity_relationships};
use scribe_backend::test_helpers::spawn_app;
use uuid::Uuid;
use serde_json::json;

#[tokio::test]
async fn test_ecs_entity_diesel_model() {
    let guard = spawn_app(false, false, false).await;
    let pool = &guard.db_pool;
    
    // Test entity creation with Diesel model
    let entity_id = Uuid::new_v4();
    let new_entity = NewEcsEntity {
        id: entity_id,
        user_id: Uuid::new_v4(), // Add required user_id field
        archetype_signature: "Character|Health|Position".to_string(),
    };
    
    let inserted_entity: EcsEntity = pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&new_entity)
                .get_result(conn)
        })
        .await
        .unwrap()
        .unwrap();
        
    assert_eq!(inserted_entity.id, entity_id);
    assert_eq!(inserted_entity.archetype_signature, "Character|Health|Position");
    
    // Test entity update
    let update = UpdateEcsEntity {
        archetype_signature: Some("Character|Health|Position|Inventory".to_string()),
    };
    
    let updated_entity: EcsEntity = pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::update(ecs_entities::table.find(entity_id))
                .set(&update)
                .get_result(conn)
        })
        .await
        .unwrap()
        .unwrap();
        
    assert_eq!(updated_entity.archetype_signature, "Character|Health|Position|Inventory");
    
    // Clean up
    pool.get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::delete(ecs_entities::table.find(entity_id))
                .execute(conn)
        })
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn test_ecs_component_diesel_model() {
    let guard = spawn_app(false, false, false).await;
    let pool = &guard.db_pool;
    
    // First create an entity
    let entity_id = Uuid::new_v4();
    let new_entity = NewEcsEntity {
        id: entity_id,
        user_id: Uuid::new_v4(), // Add required user_id field
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
        
    // Test component creation
    let component_id = Uuid::new_v4();
    let health_data = json!({
        "current": 100,
        "max": 100,
        "regeneration_rate": 5
    });
    
    let new_component = NewEcsComponent {
        id: component_id,
        entity_id,
        user_id: Uuid::new_v4(), // Add required user_id field
        component_type: "Health".to_string(),
        component_data: health_data.clone(),
    };
    
    let inserted_component: EcsComponent = pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::insert_into(ecs_components::table)
                .values(&new_component)
                .get_result(conn)
        })
        .await
        .unwrap()
        .unwrap();
        
    assert_eq!(inserted_component.component_type, "Health");
    assert_eq!(inserted_component.component_data, health_data);
    
    // Test component update
    let updated_health = json!({
        "current": 85,
        "max": 100,
        "regeneration_rate": 5
    });
    
    let update = UpdateEcsComponent {
        component_data: Some(updated_health.clone()),
    };
    
    let updated_component: EcsComponent = pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::update(ecs_components::table.find(component_id))
                .set(&update)
                .get_result(conn)
        })
        .await
        .unwrap()
        .unwrap();
        
    assert_eq!(updated_component.component_data, updated_health);
    
    // Clean up
    pool.get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::delete(ecs_entities::table.find(entity_id))
                .execute(conn)
        })
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test] 
async fn test_ecs_entity_relationship_diesel_model() {
    let guard = spawn_app(false, false, false).await;
    let pool = &guard.db_pool;
    
    // Create two entities
    let entity1_id = Uuid::new_v4();
    let entity2_id = Uuid::new_v4();
    
    for (id, archetype) in [(entity1_id, "Character"), (entity2_id, "Item")] {
        let new_entity = NewEcsEntity {
            id,
            user_id: Uuid::new_v4(), // Add required user_id field
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
    
    // Test relationship creation
    let relationship_id = Uuid::new_v4();
    let relationship_data = json!({
        "slot": 0,
        "quantity": 1
    });
    
    let new_relationship = NewEcsEntityRelationship {
        id: relationship_id,
        from_entity_id: entity1_id,
        to_entity_id: entity2_id,
        user_id: Uuid::new_v4(), // Add required user_id field
        relationship_type: "contains".to_string(),
        relationship_data: relationship_data.clone(),
        relationship_category: Some("spatial".to_string()),
        strength: Some(1.0),
        causal_metadata: None,
        temporal_validity: None,
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
        
    assert_eq!(inserted_relationship.relationship_type, "contains");
    assert_eq!(inserted_relationship.relationship_data, relationship_data);
    
    // Clean up
    for id in [entity1_id, entity2_id] {
        pool.get()
            .await
            .unwrap()
            .interact(move |conn| {
                diesel::delete(ecs_entities::table.find(id))
                    .execute(conn)
            })
            .await
            .unwrap()
            .unwrap();
    }
}