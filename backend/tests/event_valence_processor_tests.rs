#![cfg(test)]
// backend/tests/event_valence_processor_tests.rs
//
// Tests for the Event Valence Processing service that handles emotional and
// relational impacts from chronicle events

use std::sync::Arc;
use anyhow::Result as AnyhowResult;
use scribe_backend::{
    models::{
        narrative_ontology::{EventValence, ValenceType},
        ecs_diesel::{NewEcsEntity, EcsComponent, NewEcsComponent, EcsEntityRelationship, NewEcsEntityRelationship},
    },
    services::{
        event_valence_processor::{EventValenceProcessor, ValenceProcessingConfig},
    },
    schema::{ecs_entities, ecs_components, ecs_entity_relationships},
    test_helpers::{TestDataGuard, TestApp, spawn_app_permissive_rate_limiting},
};
use uuid::Uuid;
use serde_json::json;
use diesel::{RunQueryDsl, prelude::*};
use secrecy::{SecretString, ExposeSecret};
use bcrypt;

/// Helper to create a test user
async fn create_test_user(test_app: &TestApp) -> anyhow::Result<Uuid> {
    use scribe_backend::models::users::{NewUser, UserRole, AccountStatus, UserDbQuery};
    use scribe_backend::schema::users;
    
    let conn = test_app.db_pool.get().await?;
    
    let hashed_password = bcrypt::hash("testpassword", bcrypt::DEFAULT_COST)?;
    let username = format!("valence_test_user_{}", Uuid::new_v4().simple());
    let email = format!("{}@test.com", username);
    
    // Generate proper crypto keys
    let kek_salt = scribe_backend::crypto::generate_salt()?;
    let dek = scribe_backend::crypto::generate_dek()?;
    
    let secret_password = SecretString::new("testpassword".to_string().into());
    let kek = scribe_backend::crypto::derive_kek(&secret_password, &kek_salt)?;
    
    let (encrypted_dek, dek_nonce) = scribe_backend::crypto::encrypt_gcm(dek.expose_secret(), &kek)?;
    
    let new_user = NewUser {
        username,
        password_hash: hashed_password,
        email,
        kek_salt,
        encrypted_dek,
        encrypted_dek_by_recovery: None,
        role: UserRole::User,
        recovery_kek_salt: None,
        dek_nonce,
        recovery_dek_nonce: None,
        account_status: AccountStatus::Active,
    };
    
    let user_db: UserDbQuery = conn
        .interact(move |conn| {
            diesel::insert_into(users::table)
                .values(&new_user)
                .returning(UserDbQuery::as_returning())
                .get_result(conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))??;
    
    Ok(user_db.id)
}

/// Helper to create a test entity in the database
async fn create_test_entity(test_app: &TestApp, user_id: Uuid, entity_id: Uuid, archetype: &str) -> AnyhowResult<()> {
    let conn = test_app.db_pool.get().await?;
    
    let new_entity = NewEcsEntity {
        id: entity_id,
        user_id,
        archetype_signature: archetype.to_string(),
    };
    
    conn.interact(move |conn| {
        diesel::insert_into(ecs_entities::table)
            .values(&new_entity)
            .execute(conn)
    })
    .await
    .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))??;
    
    Ok(())
}

/// Helper to create a test component in the database
async fn create_test_component(
    test_app: &TestApp, 
    user_id: Uuid,
    entity_id: Uuid, 
    component_type: &str, 
    data: serde_json::Value
) -> AnyhowResult<()> {
    let conn = test_app.db_pool.get().await?;
    
    let new_component = NewEcsComponent {
        id: Uuid::new_v4(),
        entity_id,
        user_id,
        component_type: component_type.to_string(),
        component_data: data,
    };
    
    conn.interact(move |conn| {
        diesel::insert_into(ecs_components::table)
            .values(&new_component)
            .execute(conn)
    })
    .await
    .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))??;
    
    Ok(())
}

/// Helper to create a test relationship in the database
async fn create_test_relationship(
    test_app: &TestApp,
    user_id: Uuid,
    from_entity_id: Uuid,
    to_entity_id: Uuid,
    relationship_type: &str,
    data: serde_json::Value,
) -> AnyhowResult<()> {
    let conn = test_app.db_pool.get().await?;
    
    let new_relationship = NewEcsEntityRelationship {
        id: Uuid::new_v4(),
        from_entity_id,
        to_entity_id,
        user_id,
        relationship_type: relationship_type.to_string(),
        relationship_data: data,
    };
    
    conn.interact(move |conn| {
        diesel::insert_into(ecs_entity_relationships::table)
            .values(&new_relationship)
            .execute(conn)
    })
    .await
    .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))??;
    
    Ok(())
}

#[tokio::test]
async fn test_process_individual_valence_health_change() {
    // Test that health valence changes update individual entity components
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_test_user(&test_app).await.unwrap();
    let entity_id = Uuid::new_v4();
    
    // Create test entity and health component
    create_test_entity(&test_app, user_id, entity_id, "Health|Position").await.unwrap();
    create_test_component(&test_app, user_id, entity_id, "Health", json!({
        "current": 75.0,
        "max": 100.0
    })).await.unwrap();
    
    // Create processor with custom config to allow larger health changes
    let config = ValenceProcessingConfig {
        max_change_per_event: 0.0, // Disable change clamping for this test
        ..Default::default()
    };
    let processor = EventValenceProcessor::with_config(Arc::new(test_app.db_pool.clone()), config);
    
    // Create health valence change (damage)
    let valence_changes = vec![
        EventValence {
            target: entity_id,
            valence_type: ValenceType::Health,
            change: -25.0,
            description: Some("Took damage in combat".to_string()),
        }
    ];
    
    // Process the valence changes
    let result = processor
        .process_valence_changes(&valence_changes, None, Some(Uuid::new_v4()), user_id)
        .await
        .expect("Valence processing should succeed");
    
    // Verify the result
    assert_eq!(result.component_updates.len(), 1);
    assert_eq!(result.relationship_updates.len(), 0);
    
    let component_update = &result.component_updates[0];
    assert_eq!(component_update.entity_id, entity_id);
    assert_eq!(component_update.component_type, "Health");
    assert_eq!(component_update.attribute, "current");
    assert_eq!(component_update.previous_value, 75.0);
    assert_eq!(component_update.new_value, 50.0);
    assert_eq!(component_update.change_amount, -25.0);
    
    println!("✅ Successfully processed individual health valence change");
}

#[tokio::test]
async fn test_process_relational_valence_trust_change() {
    // Test that trust valence changes update relationship components
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_test_user(&test_app).await.unwrap();
    let character_a_id = Uuid::new_v4();
    let character_b_id = Uuid::new_v4();
    
    // Create test entities
    create_test_entity(&test_app, user_id, character_a_id, "Health|Position|Relationships").await.unwrap();
    create_test_entity(&test_app, user_id, character_b_id, "Health|Position|Relationships").await.unwrap();
    
    // Create existing trust relationship
    create_test_relationship(&test_app, user_id, character_a_id, character_b_id, "trust", json!({
        "trust": 0.3,
        "created_at": "2023-01-01T00:00:00Z"
    })).await.unwrap();
    
    // Create processor
    let processor = EventValenceProcessor::new(Arc::new(test_app.db_pool.clone()));
    
    // Create trust valence change (increase)
    let valence_changes = vec![
        EventValence {
            target: character_b_id,
            valence_type: ValenceType::Trust,
            change: 0.4,
            description: Some("Helped in battle".to_string()),
        }
    ];
    
    // Process the valence changes
    let result = processor
        .process_valence_changes(&valence_changes, Some(character_a_id), Some(Uuid::new_v4()), user_id)
        .await
        .expect("Valence processing should succeed");
    
    // Verify the result
    assert_eq!(result.component_updates.len(), 0);
    assert_eq!(result.relationship_updates.len(), 1);
    
    let relationship_update = &result.relationship_updates[0];
    assert_eq!(relationship_update.from_entity_id, character_a_id);
    assert_eq!(relationship_update.to_entity_id, character_b_id);
    assert_eq!(relationship_update.relationship_type, "trust");
    assert_eq!(relationship_update.attribute, "trust");
    assert_eq!(relationship_update.previous_value, 0.3);
    assert!((relationship_update.new_value - 0.7).abs() < 0.001, "Expected 0.7, got {}", relationship_update.new_value);
    assert_eq!(relationship_update.change_amount, 0.4);
    
    println!("✅ Successfully processed relational trust valence change");
}

#[tokio::test]
async fn test_process_multiple_valence_changes() {
    // Test processing multiple valence changes of different types
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_test_user(&test_app).await.unwrap();
    let character_a_id = Uuid::new_v4();
    let character_b_id = Uuid::new_v4();
    
    // Create test entities
    create_test_entity(&test_app, user_id, character_a_id, "Health|Position|Relationships").await.unwrap();
    create_test_entity(&test_app, user_id, character_b_id, "Health|Position|Relationships").await.unwrap();
    
    // Create reputation component for character A
    create_test_component(&test_app, user_id, character_a_id, "Reputation", json!({
        "score": 0.5
    })).await.unwrap();
    
    // Create processor
    let processor = EventValenceProcessor::new(Arc::new(test_app.db_pool.clone()));
    
    // Create multiple valence changes
    let valence_changes = vec![
        // Character A's reputation decreases (individual)
        EventValence {
            target: character_a_id,
            valence_type: ValenceType::Reputation,
            change: -0.2,
            description: Some("Reputation damaged by scandal".to_string()),
        },
        // Character B's trust in A decreases (relational)
        EventValence {
            target: character_b_id,
            valence_type: ValenceType::Trust,
            change: -0.3,
            description: Some("Lost trust due to scandal".to_string()),
        },
        // Character B's fear of A increases (relational)
        EventValence {
            target: character_b_id,
            valence_type: ValenceType::Fear,
            change: 0.2,
            description: Some("Now fears A's unpredictability".to_string()),
        }
    ];
    
    // Process the valence changes
    let result = processor
        .process_valence_changes(&valence_changes, Some(character_a_id), Some(Uuid::new_v4()), user_id)
        .await
        .expect("Valence processing should succeed");
    
    // Verify the result
    assert_eq!(result.component_updates.len(), 1); // Reputation update
    assert_eq!(result.relationship_updates.len(), 2); // Trust and fear updates
    assert_eq!(result.history_records.len(), 3); // All changes recorded
    
    // Check reputation update
    let reputation_update = &result.component_updates[0];
    assert_eq!(reputation_update.entity_id, character_a_id);
    assert_eq!(reputation_update.component_type, "Reputation");
    assert_eq!(reputation_update.new_value, 0.3);
    
    // Check trust update
    let trust_update = result.relationship_updates.iter()
        .find(|u| u.relationship_type == "trust")
        .expect("Should have trust update");
    assert_eq!(trust_update.to_entity_id, character_b_id);
    assert_eq!(trust_update.new_value, -0.3); // Started at 0.0, changed by -0.3
    
    // Check fear update
    let fear_update = result.relationship_updates.iter()
        .find(|u| u.relationship_type == "fear")
        .expect("Should have fear update");
    assert_eq!(fear_update.to_entity_id, character_b_id);
    assert_eq!(fear_update.new_value, 0.2); // Started at 0.0, changed by +0.2
    
    println!("✅ Successfully processed multiple valence changes of different types");
}

#[tokio::test]
async fn test_valence_clamping_configuration() {
    // Test that valence values are properly clamped when configured
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_test_user(&test_app).await.unwrap();
    let character_a_id = Uuid::new_v4();
    let character_b_id = Uuid::new_v4();
    
    // Create test entities
    create_test_entity(&test_app, user_id, character_a_id, "Health|Position|Relationships").await.unwrap();
    create_test_entity(&test_app, user_id, character_b_id, "Health|Position|Relationships").await.unwrap();
    
    // Create existing high trust relationship
    create_test_relationship(&test_app, user_id, character_a_id, character_b_id, "trust", json!({
        "trust": 0.9,
        "created_at": "2023-01-01T00:00:00Z"
    })).await.unwrap();
    
    // Create processor with clamping enabled
    let config = ValenceProcessingConfig {
        clamp_values: true,
        ..Default::default()
    };
    let processor = EventValenceProcessor::with_config(Arc::new(test_app.db_pool.clone()), config);
    
    // Create trust valence change that would exceed maximum (1.0)
    let valence_changes = vec![
        EventValence {
            target: character_b_id,
            valence_type: ValenceType::Trust,
            change: 0.5, // Would result in 1.4, but should be clamped to 1.0
            description: Some("Extraordinary act of loyalty".to_string()),
        }
    ];
    
    // Process the valence changes
    let result = processor
        .process_valence_changes(&valence_changes, Some(character_a_id), Some(Uuid::new_v4()), user_id)
        .await
        .expect("Valence processing should succeed");
    
    // Verify the result is clamped
    assert_eq!(result.relationship_updates.len(), 1);
    let relationship_update = &result.relationship_updates[0];
    assert_eq!(relationship_update.previous_value, 0.9);
    assert_eq!(relationship_update.new_value, 1.0); // Clamped to maximum
    assert_eq!(relationship_update.change_amount, 0.5); // Original change preserved
    
    println!("✅ Successfully clamped valence values to valid range");
}

#[tokio::test]
async fn test_minimum_change_threshold() {
    // Test that changes below the minimum threshold are ignored
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_test_user(&test_app).await.unwrap();
    let entity_id = Uuid::new_v4();
    
    // Create test entity
    create_test_entity(&test_app, user_id, entity_id, "Health|Position").await.unwrap();
    
    // Create processor with higher minimum threshold
    let config = ValenceProcessingConfig {
        min_change_threshold: 0.1,
        ..Default::default()
    };
    let processor = EventValenceProcessor::with_config(Arc::new(test_app.db_pool.clone()), config);
    
    // Create valence changes below and above threshold
    let valence_changes = vec![
        EventValence {
            target: entity_id,
            valence_type: ValenceType::Health,
            change: 0.05, // Below threshold, should be ignored
            description: Some("Minor healing".to_string()),
        },
        EventValence {
            target: entity_id,
            valence_type: ValenceType::Reputation,
            change: 0.15, // Above threshold, should be processed
            description: Some("Good deed recognized".to_string()),
        }
    ];
    
    // Process the valence changes
    let result = processor
        .process_valence_changes(&valence_changes, None, Some(Uuid::new_v4()), user_id)
        .await
        .expect("Valence processing should succeed");
    
    // Verify only the above-threshold change was processed
    assert_eq!(result.component_updates.len(), 1);
    assert_eq!(result.history_records.len(), 1);
    
    let component_update = &result.component_updates[0];
    assert_eq!(component_update.component_type, "Reputation");
    assert_eq!(component_update.change_amount, 0.15);
    
    println!("✅ Successfully filtered changes below minimum threshold");
}

#[tokio::test]
async fn test_self_referential_valence_handling() {
    // Test that self-referential valence changes are handled appropriately
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_test_user(&test_app).await.unwrap();
    let entity_id = Uuid::new_v4();
    
    // Create test entity
    create_test_entity(&test_app, user_id, entity_id, "Health|Position|Relationships").await.unwrap();
    
    // Create processor
    let processor = EventValenceProcessor::new(Arc::new(test_app.db_pool.clone()));
    
    // Create self-referential trust valence change (entity affecting its own trust)
    let valence_changes = vec![
        EventValence {
            target: entity_id,
            valence_type: ValenceType::Trust,
            change: 0.3,
            description: Some("Self-confidence boost".to_string()),
        }
    ];
    
    // Process the valence changes with same entity as source
    let result = processor
        .process_valence_changes(&valence_changes, Some(entity_id), Some(Uuid::new_v4()), user_id)
        .await
        .expect("Valence processing should succeed");
    
    // Verify the self-referential change was skipped
    assert_eq!(result.component_updates.len(), 0);
    assert_eq!(result.relationship_updates.len(), 0);
    assert_eq!(result.messages.len(), 1);
    assert!(result.messages[0].contains("self-referential"));
    
    println!("✅ Successfully handled self-referential valence change");
}

#[tokio::test]
async fn test_new_component_creation() {
    // Test that new components are created when they don't exist
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_test_user(&test_app).await.unwrap();
    let entity_id = Uuid::new_v4();
    
    // Create test entity (without any components initially)
    create_test_entity(&test_app, user_id, entity_id, "Health|Position").await.unwrap();
    
    // Create processor with custom config to allow larger health changes
    let config = ValenceProcessingConfig {
        max_change_per_event: 0.0, // Disable change clamping for this test
        ..Default::default()
    };
    let processor = EventValenceProcessor::with_config(Arc::new(test_app.db_pool.clone()), config);
    
    // Create health valence change for entity without existing health component
    let valence_changes = vec![
        EventValence {
            target: entity_id,
            valence_type: ValenceType::Health,
            change: 25.0,
            description: Some("Healing magic applied".to_string()),
        }
    ];
    
    // Process the valence changes
    let result = processor
        .process_valence_changes(&valence_changes, None, Some(Uuid::new_v4()), user_id)
        .await
        .expect("Valence processing should succeed");
    
    // Verify the component was created with the new value
    assert_eq!(result.component_updates.len(), 1);
    
    let component_update = &result.component_updates[0];
    assert_eq!(component_update.entity_id, entity_id);
    assert_eq!(component_update.component_type, "Health");
    assert_eq!(component_update.previous_value, 0.0); // Default value
    assert_eq!(component_update.new_value, 25.0);
    assert_eq!(component_update.change_amount, 25.0);
    
    // Verify the component was actually created in the database
    let conn = test_app.db_pool.get().await.unwrap();
    let component = conn.interact({
        let entity_id = entity_id;
        move |conn| {
            ecs_components::table
                .filter(ecs_components::entity_id.eq(entity_id))
                .filter(ecs_components::component_type.eq("Health"))
                .first::<EcsComponent>(conn)
        }
    })
    .await
    .expect("DB interaction should succeed")
    .expect("Health component should exist");
    
    assert_eq!(component.component_data["current"], 25.0);
    
    println!("✅ Successfully created new component from valence change");
}

#[tokio::test]
async fn test_new_relationship_creation() {
    // Test that new relationships are created when they don't exist
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_test_user(&test_app).await.unwrap();
    let character_a_id = Uuid::new_v4();
    let character_b_id = Uuid::new_v4();
    
    // Create test entities (without any relationships initially)
    create_test_entity(&test_app, user_id, character_a_id, "Health|Position|Relationships").await.unwrap();
    create_test_entity(&test_app, user_id, character_b_id, "Health|Position|Relationships").await.unwrap();
    
    // Create processor
    let processor = EventValenceProcessor::new(Arc::new(test_app.db_pool.clone()));
    
    // Create trust valence change for entities without existing relationship
    let valence_changes = vec![
        EventValence {
            target: character_b_id,
            valence_type: ValenceType::Trust,
            change: 0.6,
            description: Some("First positive interaction".to_string()),
        }
    ];
    
    // Process the valence changes
    let result = processor
        .process_valence_changes(&valence_changes, Some(character_a_id), Some(Uuid::new_v4()), user_id)
        .await
        .expect("Valence processing should succeed");
    
    // Verify the relationship was created with the new value
    assert_eq!(result.relationship_updates.len(), 1);
    
    let relationship_update = &result.relationship_updates[0];
    assert_eq!(relationship_update.from_entity_id, character_a_id);
    assert_eq!(relationship_update.to_entity_id, character_b_id);
    assert_eq!(relationship_update.relationship_type, "trust");
    assert_eq!(relationship_update.previous_value, 0.0); // Default value
    assert_eq!(relationship_update.new_value, 0.6);
    assert_eq!(relationship_update.change_amount, 0.6);
    
    // Verify the relationship was actually created in the database
    let conn = test_app.db_pool.get().await.unwrap();
    let relationship = conn.interact({
        let from_entity_id = character_a_id;
        let to_entity_id = character_b_id;
        move |conn| {
            ecs_entity_relationships::table
                .filter(ecs_entity_relationships::from_entity_id.eq(from_entity_id))
                .filter(ecs_entity_relationships::to_entity_id.eq(to_entity_id))
                .filter(ecs_entity_relationships::relationship_type.eq("trust"))
                .select(EcsEntityRelationship::as_select())
                .first::<EcsEntityRelationship>(conn)
        }
    })
    .await
    .expect("DB interaction should succeed")
    .expect("Trust relationship should exist");
    
    let trust_value = relationship.relationship_data["trust"].as_f64().unwrap() as f32;
    assert!((trust_value - 0.6).abs() < 0.001, "Expected 0.6, got {}", trust_value);
    
    println!("✅ Successfully created new relationship from valence change");
}