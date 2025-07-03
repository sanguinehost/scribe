#![cfg(test)]
// backend/tests/chronicle_backfill_processor_tests.rs
//
// Tests for the Chronicle Backfill Processing service that handles
// idempotent processing of historical chronicle events into ECS state

use std::sync::Arc;
use anyhow::Result as AnyhowResult;
use scribe_backend::{
    models::{
        chronicle::{CreateChronicleRequest},
        chronicle_event::{CreateEventRequest, EventSource},
        users::{NewUser, UserRole, AccountStatus, UserDbQuery},
        narrative_ontology::{EventActor, ActorRole, EventValence, ValenceType, NarrativeAction},
        ecs_diesel::{EcsEntity, EcsComponent},
    },
    services::{
        chronicle_service::ChronicleService,
        chronicle_backfill_processor::{ChronicleBackfillProcessor, BackfillConfig},
    },
    schema::{users, ecs_entities, ecs_components},
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
    let username = format!("backfill_test_user_{}", Uuid::new_v4().simple());
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

/// Helper to create a test chronicle with events
async fn create_test_chronicle_with_events(
    user_id: Uuid, 
    test_app: &TestApp, 
    event_count: usize
) -> AnyhowResult<(Uuid, Vec<Uuid>)> {
    let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
    
    // Create chronicle
    let create_request = CreateChronicleRequest {
        name: format!("Backfill Test Chronicle {}", Uuid::new_v4().simple()),
        description: Some("Testing chronicle backfill processing".to_string()),
    };
    
    let chronicle = chronicle_service
        .create_chronicle(user_id, create_request)
        .await?;
    
    // Create test events with different types and actors
    let mut event_ids = Vec::new();
    
    for i in 0..event_count {
        // Add a small delay to ensure unique timestamps
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let character_a_id = Uuid::new_v4();
        let character_b_id = Uuid::new_v4();
        
        let actors = vec![
            EventActor {
                entity_id: character_a_id,
                role: ActorRole::Agent,
                context: Some(format!("character A in event {}", i)),
            },
            EventActor {
                entity_id: character_b_id,
                role: ActorRole::Patient,
                context: Some(format!("character B in event {}", i)),
            },
        ];
        
        let valence = if i % 2 == 0 {
            // Even events: health change
            Some(vec![EventValence {
                target: character_a_id,
                valence_type: ValenceType::Health,
                change: -10.0,
                description: Some("Combat damage".to_string()),
            }])
        } else {
            // Odd events: trust change
            Some(vec![EventValence {
                target: character_b_id,
                valence_type: ValenceType::Trust,
                change: 0.2,
                description: Some("Helpful interaction".to_string()),
            }])
        };
        
        let create_request = CreateEventRequest {
            event_type: format!("TEST.EVENT.{}", i),
            summary: format!("Test event {} for backfill processing", i),
            event_data: Some(json!({
                "test_event_number": i,
                "participants": [character_a_id.to_string(), character_b_id.to_string()]
            })),
            source: EventSource::AiExtracted,
        };
        
        let event = chronicle_service
            .create_event(user_id, chronicle.id, create_request, None)
            .await?;
        
        // Update the event with Ars Fabula ontology fields using direct database update
        let conn = test_app.db_pool.get().await?;
        let event_id = event.id;
        
        let actors_json = serde_json::to_value(&actors)?;
        let action_str = "Met";
        let valence_json = if let Some(valence) = valence {
            Some(serde_json::to_value(&valence)?)
        } else {
            None
        };
        
        conn.interact(move |conn| {
            use diesel::prelude::*;
            use scribe_backend::schema::chronicle_events::dsl::*;
            
            if let Some(valence_val) = valence_json {
                diesel::update(chronicle_events.filter(id.eq(event_id)))
                    .set((
                        actors.eq(Some(actors_json)),
                        action.eq(Some(action_str)),
                        valence.eq(Some(valence_val)),
                        timestamp_iso8601.eq(Utc::now()),
                    ))
                    .execute(conn)
            } else {
                diesel::update(chronicle_events.filter(id.eq(event_id)))
                    .set((
                        actors.eq(Some(actors_json)),
                        action.eq(Some(action_str)),
                        timestamp_iso8601.eq(Utc::now()),
                    ))
                    .execute(conn)
            }
        })
        .await
        .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))??;
        
        event_ids.push(event_id);
    }
    
    Ok((chronicle.id, event_ids))
}

/// Helper to count ECS entities in the database
async fn count_ecs_entities(test_app: &TestApp) -> AnyhowResult<i64> {
    let conn = test_app.db_pool.get().await?;
    
    let count = conn.interact(move |conn| {
        ecs_entities::table.count().get_result::<i64>(conn)
    })
    .await
    .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))??;
    
    Ok(count)
}

/// Helper to count ECS components in the database
async fn count_ecs_components(test_app: &TestApp) -> AnyhowResult<i64> {
    let conn = test_app.db_pool.get().await?;
    
    let count = conn.interact(move |conn| {
        ecs_components::table.count().get_result::<i64>(conn)
    })
    .await
    .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))??;
    
    Ok(count)
}

#[tokio::test]
async fn test_backfill_single_chronicle_with_events() {
    // Test basic backfill processing of a single chronicle
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_test_user(&test_app).await.unwrap();
    let (chronicle_id, event_ids) = create_test_chronicle_with_events(user_id, &test_app, 5).await.unwrap();
    
    // Verify initial state - no ECS entities should exist
    let initial_entity_count = count_ecs_entities(&test_app).await.unwrap();
    let initial_component_count = count_ecs_components(&test_app).await.unwrap();
    
    // Create backfill processor
    let processor = ChronicleBackfillProcessor::new(Arc::new(test_app.db_pool.clone()));
    
    // Process the chronicles
    let result = processor
        .backfill_user_chronicles(user_id)
        .await
        .expect("Backfill should succeed");
    
    // Verify results
    assert_eq!(result.chronicles_processed, 1);
    assert_eq!(result.events_processed, 5);
    assert_eq!(result.events_skipped, 0);
    assert_eq!(result.translation_errors, 0);
    assert_eq!(result.chronicle_stats.len(), 1);
    
    // Verify chronicle stats
    let chronicle_stats = result.chronicle_stats.get(&chronicle_id).unwrap();
    assert_eq!(chronicle_stats.events_processed, 5);
    assert_eq!(chronicle_stats.events_skipped, 0);
    assert!(chronicle_stats.entities_created > 0);
    
    // Verify ECS entities were created
    let final_entity_count = count_ecs_entities(&test_app).await.unwrap();
    let final_component_count = count_ecs_components(&test_app).await.unwrap();
    
    assert!(final_entity_count > initial_entity_count);
    assert!(final_component_count > initial_component_count);
    
    println!("✅ Successfully backfilled single chronicle with {} events", event_ids.len());
}

#[tokio::test]
async fn test_backfill_multiple_chronicles() {
    // Test backfill processing of multiple chronicles
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_test_user(&test_app).await.unwrap();
    
    // Create multiple chronicles with different event counts
    let (chronicle1_id, _) = create_test_chronicle_with_events(user_id, &test_app, 3).await.unwrap();
    let (chronicle2_id, _) = create_test_chronicle_with_events(user_id, &test_app, 2).await.unwrap();
    let (chronicle3_id, _) = create_test_chronicle_with_events(user_id, &test_app, 4).await.unwrap();
    
    // Create backfill processor
    let processor = ChronicleBackfillProcessor::new(Arc::new(test_app.db_pool.clone()));
    
    // Process all chronicles
    let result = processor
        .backfill_user_chronicles(user_id)
        .await
        .expect("Backfill should succeed");
    
    // Verify results
    assert_eq!(result.chronicles_processed, 3);
    assert_eq!(result.events_processed, 9); // 3 + 2 + 4
    assert_eq!(result.events_skipped, 0);
    assert_eq!(result.chronicle_stats.len(), 3);
    
    // Verify each chronicle was processed
    assert!(result.chronicle_stats.contains_key(&chronicle1_id));
    assert!(result.chronicle_stats.contains_key(&chronicle2_id));
    assert!(result.chronicle_stats.contains_key(&chronicle3_id));
    
    // Verify individual chronicle stats
    assert_eq!(result.chronicle_stats.get(&chronicle1_id).unwrap().events_processed, 3);
    assert_eq!(result.chronicle_stats.get(&chronicle2_id).unwrap().events_processed, 2);
    assert_eq!(result.chronicle_stats.get(&chronicle3_id).unwrap().events_processed, 4);
    
    println!("✅ Successfully backfilled multiple chronicles with total {} events", result.events_processed);
}

#[tokio::test]
async fn test_backfill_idempotency() {
    // Test that running backfill multiple times produces identical results
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_test_user(&test_app).await.unwrap();
    let (chronicle_id, _) = create_test_chronicle_with_events(user_id, &test_app, 3).await.unwrap();
    
    // Create backfill processor with checkpointing disabled for this test
    let config = BackfillConfig {
        enable_checkpointing: false,
        skip_processed_events: false, // Force reprocessing to test idempotency
        ..Default::default()
    };
    let processor = ChronicleBackfillProcessor::with_config(Arc::new(test_app.db_pool.clone()), config);
    
    // First backfill run
    let result1 = processor
        .backfill_user_chronicles(user_id)
        .await
        .expect("First backfill should succeed");
    
    // Get ECS state after first run
    let entities_after_first = count_ecs_entities(&test_app).await.unwrap();
    let components_after_first = count_ecs_components(&test_app).await.unwrap();
    
    // Second backfill run
    let result2 = processor
        .backfill_user_chronicles(user_id)
        .await
        .expect("Second backfill should succeed");
    
    // Get ECS state after second run
    let entities_after_second = count_ecs_entities(&test_app).await.unwrap();
    let components_after_second = count_ecs_components(&test_app).await.unwrap();
    
    // Verify results are identical
    assert_eq!(result1.chronicles_processed, result2.chronicles_processed);
    assert_eq!(result1.events_processed, result2.events_processed);
    
    // Verify ECS state is identical (idempotency)
    assert_eq!(entities_after_first, entities_after_second);
    assert_eq!(components_after_first, components_after_second);
    
    println!("✅ Successfully verified backfill idempotency - identical results on multiple runs");
}

#[tokio::test]
async fn test_backfill_with_checkpointing() {
    // Test backfill processing with checkpointing enabled
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_test_user(&test_app).await.unwrap();
    let (chronicle_id, _) = create_test_chronicle_with_events(user_id, &test_app, 5).await.unwrap();
    
    // Create backfill processor with small batch size to trigger checkpointing
    let config = BackfillConfig {
        batch_size: 2,
        enable_checkpointing: true,
        ..Default::default()
    };
    let processor = ChronicleBackfillProcessor::with_config(Arc::new(test_app.db_pool.clone()), config);
    
    // Process the chronicles
    let result = processor
        .backfill_user_chronicles(user_id)
        .await
        .expect("Backfill with checkpointing should succeed");
    
    // Verify processing completed
    assert_eq!(result.chronicles_processed, 1);
    assert_eq!(result.events_processed, 5);
    assert_eq!(result.translation_errors, 0);
    
    // Verify checkpoint was created
    let checkpoint = processor
        .get_checkpoint(user_id, Some(chronicle_id))
        .await
        .expect("Should get checkpoint")
        .expect("Checkpoint should exist");
    
    assert_eq!(checkpoint.user_id, user_id);
    assert_eq!(checkpoint.chronicle_id, Some(chronicle_id));
    assert_eq!(checkpoint.events_processed_count, 5);
    
    println!("✅ Successfully processed chronicle with checkpointing");
}

#[tokio::test]
async fn test_backfill_with_empty_chronicles() {
    // Test backfill processing when chronicles have no events
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_test_user(&test_app).await.unwrap();
    
    // Create chronicles with no events
    let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
    let _chronicle1 = chronicle_service
        .create_chronicle(user_id, CreateChronicleRequest {
            name: "Empty Chronicle 1".to_string(),
            description: Some("Chronicle with no events".to_string()),
        })
        .await
        .unwrap();
        
    let _chronicle2 = chronicle_service
        .create_chronicle(user_id, CreateChronicleRequest {
            name: "Empty Chronicle 2".to_string(),
            description: Some("Another chronicle with no events".to_string()),
        })
        .await
        .unwrap();
    
    // Create backfill processor
    let processor = ChronicleBackfillProcessor::new(Arc::new(test_app.db_pool.clone()));
    
    // Process the chronicles
    let result = processor
        .backfill_user_chronicles(user_id)
        .await
        .expect("Backfill should succeed even with empty chronicles");
    
    // Verify results
    assert_eq!(result.chronicles_processed, 2);
    assert_eq!(result.events_processed, 0);
    assert_eq!(result.events_skipped, 0);
    assert_eq!(result.translation_errors, 0);
    assert_eq!(result.chronicle_stats.len(), 2);
    
    println!("✅ Successfully handled backfill of empty chronicles");
}

#[tokio::test]
async fn test_backfill_reset_checkpoints() {
    // Test resetting checkpoints for a user
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_test_user(&test_app).await.unwrap();
    let (chronicle_id, _) = create_test_chronicle_with_events(user_id, &test_app, 3).await.unwrap();
    
    // Create backfill processor
    let processor = ChronicleBackfillProcessor::new(Arc::new(test_app.db_pool.clone()));
    
    // Process chronicles to create checkpoints
    let _result = processor
        .backfill_user_chronicles(user_id)
        .await
        .expect("Backfill should succeed");
    
    // Verify checkpoint exists
    let checkpoint_before = processor
        .get_checkpoint(user_id, Some(chronicle_id))
        .await
        .expect("Should get checkpoint");
    assert!(checkpoint_before.is_some());
    
    // Reset checkpoints
    processor
        .reset_checkpoints(user_id)
        .await
        .expect("Reset should succeed");
    
    // Verify checkpoint is gone
    let checkpoint_after = processor
        .get_checkpoint(user_id, Some(chronicle_id))
        .await
        .expect("Should get checkpoint");
    assert!(checkpoint_after.is_none());
    
    println!("✅ Successfully reset backfill checkpoints");
}

#[tokio::test]
async fn test_backfill_configuration_options() {
    // Test different configuration options
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user_id = create_test_user(&test_app).await.unwrap();
    let (chronicle_id, _) = create_test_chronicle_with_events(user_id, &test_app, 4).await.unwrap();
    
    // Test with custom configuration
    let config = BackfillConfig {
        batch_size: 1, // Very small batches
        max_parallel_chronicles: 1,
        skip_processed_events: true,
        validate_consistency: true,
        enable_checkpointing: false, // Disable checkpointing
    };
    
    let processor = ChronicleBackfillProcessor::with_config(Arc::new(test_app.db_pool.clone()), config);
    
    // Process chronicles
    let result = processor
        .backfill_user_chronicles(user_id)
        .await
        .expect("Backfill with custom config should succeed");
    
    // Verify processing completed
    assert_eq!(result.chronicles_processed, 1);
    assert_eq!(result.events_processed, 4);
    assert_eq!(result.translation_errors, 0);
    
    // Verify no checkpoint was created (disabled in config)
    let checkpoint = processor
        .get_checkpoint(user_id, Some(chronicle_id))
        .await
        .expect("Should get checkpoint");
    assert!(checkpoint.is_none());
    
    println!("✅ Successfully tested custom backfill configuration");
}