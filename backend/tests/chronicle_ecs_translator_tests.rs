#![cfg(test)]
// backend/tests/chronicle_ecs_translator_tests.rs
//
// Tests for the Chronicle-to-ECS translation service that maps chronicle events
// to ECS entity state changes

use std::sync::Arc;
use anyhow::Result as AnyhowResult;
use scribe_backend::{
    models::{
        chronicle_event::{ChronicleEvent, EventSource, CreateEventRequest},
        chronicle::{CreateChronicleRequest},
        users::{NewUser, UserRole, AccountStatus, UserDbQuery},
        narrative_ontology::{EventActor, ActorRole, EventValence, ValenceType, NarrativeAction},
        ecs_diesel::{EcsEntity, EcsComponent},
    },
    services::{
        chronicle_service::ChronicleService,
        chronicle_ecs_translator::ChronicleEcsTranslator,
    },
    schema::users,
    test_helpers::{TestDataGuard, TestApp, spawn_app_permissive_rate_limiting},
};
use uuid::Uuid;
use chrono::Utc;
use serde_json::json;
use secrecy::{SecretString, ExposeSecret};
use diesel::{RunQueryDsl, prelude::*};
use bcrypt;

/// Helper to create a test user in the database
async fn create_test_user(test_app: &TestApp) -> AnyhowResult<Uuid> {
    let conn = test_app.db_pool.get().await?;
    
    let hashed_password = bcrypt::hash("testpassword", bcrypt::DEFAULT_COST)?;
    let username = format!("translator_test_user_{}", Uuid::new_v4().simple());
    let email = format!("{}@test.com", username);
    
    // Generate proper crypto keys
    let kek_salt = scribe_backend::crypto::generate_salt()?;
    let dek = scribe_backend::crypto::generate_dek()?;
    
    let secret_password = secrecy::SecretString::new("testpassword".to_string().into());
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

/// Helper to create a test chronicle
async fn create_test_chronicle(user_id: Uuid, test_app: &TestApp) -> AnyhowResult<Uuid> {
    let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
    
    let create_request = CreateChronicleRequest {
        name: "ECS Translation Test Chronicle".to_string(),
        description: Some("Testing chronicle event to ECS entity translation".to_string()),
    };
    
    let chronicle = chronicle_service
        .create_chronicle(user_id, create_request)
        .await?;
    
    Ok(chronicle.id)
}

/// Helper to create a chronicle event with actors and action
async fn create_event_with_actors(
    user_id: Uuid,
    chronicle_id: Uuid, 
    event_type: &str,
    summary: &str,
    actors: Vec<EventActor>,
    action: Option<NarrativeAction>,
    valence: Option<Vec<EventValence>>,
    test_app: &TestApp,
) -> AnyhowResult<ChronicleEvent> {
    let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
    
    let create_request = CreateEventRequest {
        event_type: event_type.to_string(),
        summary: summary.to_string(),
        event_data: Some(json!({
            "location": "Test Location",
            "participants": actors.iter().map(|a| a.entity_id.to_string()).collect::<Vec<_>>()
        })),
        source: EventSource::AiExtracted,
    };
    
    let mut event = chronicle_service
        .create_event(user_id, chronicle_id, create_request, None)
        .await?;
    
    // Set the Ars Fabula ontology fields
    event.actors = Some(serde_json::to_value(&actors)?);
    if let Some(action) = action {
        event.action = Some(serde_json::to_value(&action)?.as_str().unwrap_or("UNKNOWN").to_string());
    }
    if let Some(valence) = valence {
        event.valence = Some(serde_json::to_value(&valence)?);
    }
    event.timestamp_iso8601 = Utc::now();
    
    Ok(event)
}

#[tokio::test]
async fn test_translate_simple_character_meeting_event() {
    // Test that a simple character meeting event creates ECS entities and relationships
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_test_user(&test_app).await.unwrap();
    let chronicle_id = create_test_chronicle(user_id, &test_app).await.unwrap();
    
    // Create two character entities
    let character_a_id = Uuid::new_v4();
    let character_b_id = Uuid::new_v4();
    
    // Create actors for the meeting event
    let actors = vec![
        EventActor {
            entity_id: character_a_id,
            role: ActorRole::Agent,
            context: Some("approached the tavern".to_string()),
        },
        EventActor {
            entity_id: character_b_id,
            role: ActorRole::Patient,
            context: Some("was sitting at the bar".to_string()),
        },
    ];
    
    // Create the meeting event
    let event = create_event_with_actors(
        user_id,
        chronicle_id,
        "CHARACTER.SOCIAL.MEETING",
        "Alice met Bob at the tavern",
        actors,
        Some(NarrativeAction::Met),
        None, // No valence changes yet
        &test_app,
    ).await.unwrap();
    
    // Create the translator service
    let translator = ChronicleEcsTranslator::new(Arc::new(test_app.db_pool.clone()));
    
    // Translate the event to ECS
    let translation_result = translator
        .translate_event(&event, user_id)
        .await
        .expect("Translation should succeed");
    
    // Verify entities were created
    assert_eq!(translation_result.entities_created.len(), 2);
    assert!(translation_result.entities_created.contains(&character_a_id));
    assert!(translation_result.entities_created.contains(&character_b_id));
    
    // Verify component updates - characters should have basic components
    assert!(!translation_result.component_updates.is_empty());
    
    // Verify relationship creation - characters should now know each other
    assert!(!translation_result.relationship_updates.is_empty());
    
    println!("✅ Successfully translated character meeting event to ECS");
}

#[tokio::test]
async fn test_translate_valence_change_event() {
    // Test that valence changes in events update relationship components
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_test_user(&test_app).await.unwrap();
    let chronicle_id = create_test_chronicle(user_id, &test_app).await.unwrap();
    
    let character_a_id = Uuid::new_v4();
    let character_b_id = Uuid::new_v4();
    
    // Create actors
    let actors = vec![
        EventActor {
            entity_id: character_a_id,
            role: ActorRole::Agent,
            context: Some("the betrayer".to_string()),
        },
        EventActor {
            entity_id: character_b_id,
            role: ActorRole::Patient,
            context: Some("the betrayed".to_string()),
        },
    ];
    
    // Create valence changes - A betrayed B, reducing trust
    let valence = vec![
        EventValence {
            target: character_b_id,
            valence_type: ValenceType::Trust,
            change: -0.8, // Major trust loss
            description: Some("Lost trust due to betrayal".to_string()),
        },
        EventValence {
            target: character_a_id,
            valence_type: ValenceType::Reputation,
            change: -0.3, // Some reputation loss
            description: Some("Reputation damaged by betraying a friend".to_string()),
        },
    ];
    
    // Create the betrayal event
    let event = create_event_with_actors(
        user_id,
        chronicle_id,
        "CHARACTER.SOCIAL.BETRAYAL",
        "Alice betrayed Bob by revealing his secret",
        actors,
        Some(NarrativeAction::Betrayed),
        Some(valence),
        &test_app,
    ).await.unwrap();
    
    // Create the translator service
    let translator = ChronicleEcsTranslator::new(Arc::new(test_app.db_pool.clone()));
    
    // Translate the event to ECS
    let translation_result = translator
        .translate_event(&event, user_id)
        .await
        .expect("Translation should succeed");
    
    // Verify relationship updates
    assert!(!translation_result.relationship_updates.is_empty());
    
    // Check that trust values were updated
    let trust_updates: Vec<_> = translation_result.relationship_updates
        .iter()
        .filter(|r| r.relationship_type == "trust")
        .collect();
    
    assert!(!trust_updates.is_empty(), "Should have trust relationship updates");
    
    println!("✅ Successfully translated valence changes to relationship components");
}

#[tokio::test]
async fn test_translate_item_acquisition_event() {
    // Test that item acquisition events update inventory components
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_test_user(&test_app).await.unwrap();
    let chronicle_id = create_test_chronicle(user_id, &test_app).await.unwrap();
    
    let character_id = Uuid::new_v4();
    let item_id = Uuid::new_v4();
    
    // Create actors - character acquires item
    let actors = vec![
        EventActor {
            entity_id: character_id,
            role: ActorRole::Agent,
            context: Some("the adventurer".to_string()),
        },
        EventActor {
            entity_id: item_id,
            role: ActorRole::Patient,
            context: Some("magical sword".to_string()),
        },
    ];
    
    // Create the acquisition event
    let event = create_event_with_actors(
        user_id,
        chronicle_id,
        "ITEM.ACQUISITION.FOUND",
        "The adventurer found a magical sword in the ancient temple",
        actors,
        Some(NarrativeAction::Acquired),
        None,
        &test_app,
    ).await.unwrap();
    
    // Create the translator service
    let translator = ChronicleEcsTranslator::new(Arc::new(test_app.db_pool.clone()));
    
    // Translate the event to ECS
    let translation_result = translator
        .translate_event(&event, user_id)
        .await
        .expect("Translation should succeed");
    
    // Verify both character and item entities were created
    assert!(translation_result.entities_created.contains(&character_id));
    assert!(translation_result.entities_created.contains(&item_id));
    
    // Verify inventory component update
    let inventory_updates: Vec<_> = translation_result.component_updates
        .iter()
        .filter(|c| c.component_type == "Inventory")
        .collect();
    
    assert!(!inventory_updates.is_empty(), "Should have inventory component updates");
    
    println!("✅ Successfully translated item acquisition to inventory component");
}

#[tokio::test]  
async fn test_translate_multiple_events_preserves_state() {
    // Test that processing multiple events in sequence maintains correct ECS state
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_test_user(&test_app).await.unwrap();
    let chronicle_id = create_test_chronicle(user_id, &test_app).await.unwrap();
    
    let character_a_id = Uuid::new_v4();
    let character_b_id = Uuid::new_v4();
    
    // Create the translator service
    let translator = ChronicleEcsTranslator::new(Arc::new(test_app.db_pool.clone()));
    
    // Event 1: Characters meet
    let meeting_actors = vec![
        EventActor {
            entity_id: character_a_id,
            role: ActorRole::Agent,
            context: Some("approached".to_string()),
        },
        EventActor {
            entity_id: character_b_id,
            role: ActorRole::Patient,
            context: Some("was waiting".to_string()),
        },
    ];
    
    let meeting_event = create_event_with_actors(
        user_id,
        chronicle_id,
        "CHARACTER.SOCIAL.MEETING",
        "Alice met Bob",
        meeting_actors,
        Some(NarrativeAction::Met),
        None,
        &test_app,
    ).await.unwrap();
    
    let result1 = translator.translate_event(&meeting_event, user_id).await.unwrap();
    assert_eq!(result1.entities_created.len(), 2);
    
    // Event 2: Trust increases
    let trust_valence = vec![
        EventValence {
            target: character_b_id,
            valence_type: ValenceType::Trust,
            change: 0.5,
            description: Some("Helpful interaction".to_string()),
        },
    ];
    
    let trust_event = create_event_with_actors(
        user_id,
        chronicle_id,
        "CHARACTER.SOCIAL.HELP",
        "Alice helped Bob",
        vec![
            EventActor {
                entity_id: character_a_id,
                role: ActorRole::Agent,
                context: Some("the helper".to_string()),
            },
            EventActor {
                entity_id: character_b_id,
                role: ActorRole::Beneficiary,
                context: Some("received help".to_string()),
            },
        ],
        Some(NarrativeAction::Gave), // Using 'Gave' as a proxy for helping
        Some(trust_valence),
        &test_app,
    ).await.unwrap();
    
    let result2 = translator.translate_event(&trust_event, user_id).await.unwrap();
    
    // Entities should not be recreated
    assert_eq!(result2.entities_created.len(), 0, "Entities should already exist");
    
    // Should have relationship updates
    assert!(!result2.relationship_updates.is_empty());
    
    println!("✅ Successfully processed multiple events maintaining state consistency");
}