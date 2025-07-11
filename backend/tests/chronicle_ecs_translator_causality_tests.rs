// ChronicleEcsTranslator Causality Tests
//
// Tests for Phase 1: Enhanced Chronicle-to-ECS Translation with Causal Tracking
// - translate_event_with_causality method
// - Causal relationship creation
// - Chronicle event causality tracking
// - OWASP security compliance

use std::sync::Arc;
use uuid::Uuid;
use serde_json::json;
use chrono::Utc;

use scribe_backend::{
    test_helpers::{spawn_app, TestDataGuard, db::create_test_user},
    models::{
        chronicle_event::{ChronicleEvent, NewChronicleEvent, EventSource},
        ecs::{RelationshipCategory},
        ecs_diesel::{NewEcsEntity},
    },
    services::chronicle_ecs_translator::ChronicleEcsTranslator,
    schema::{chronicle_events, ecs_entities, ecs_entity_relationships},
};
use diesel::prelude::*;

// Helper to create a test chronicle
async fn create_test_chronicle(user_id: uuid::Uuid, test_app: &scribe_backend::test_helpers::TestApp) -> Result<uuid::Uuid, anyhow::Error> {
    use scribe_backend::services::ChronicleService;
    use scribe_backend::models::chronicle::CreateChronicleRequest;
    
    let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
    
    let create_request = CreateChronicleRequest {
        name: "Causality Test Chronicle".to_string(),
        description: Some("Testing chronicle-ecs translator causality features".to_string()),
    };
    
    let chronicle = chronicle_service
        .create_chronicle(user_id, create_request)
        .await?;
    
    Ok(chronicle.id)
}

#[tokio::test]
async fn test_translate_event_with_causality_basic() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let translator = ChronicleEcsTranslator::new(Arc::new(app.db_pool.clone()));
    let chronicle_id = create_test_chronicle(user.id, &app).await.unwrap();
    
    // Create previous event
    let previous_event_id = Uuid::new_v4();
    let current_event_id = Uuid::new_v4();
    
    let agent_entity = Uuid::new_v4();
    let patient_entity = Uuid::new_v4();
    
    let conn = app.db_pool.get().await.unwrap();
    
    // Insert entities first
    let entities = vec![
        NewEcsEntity { id: agent_entity, user_id: user.id, archetype_signature: "Character|Health".to_string() },
        NewEcsEntity { id: patient_entity, user_id: user.id, archetype_signature: "Character|Health".to_string() },
    ];
    
    conn.interact({
        let entities = entities.clone();
        move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&entities)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Create previous chronicle event
    let previous_event = NewChronicleEvent {
        chronicle_id,
        user_id: user.id,
        sequence_number: 1,
        event_type: "COMBAT_INITIATION".to_string(),
        summary: "Hero draws sword".to_string(),
        source: EventSource::AiExtracted.to_string(),
        event_data: Some(json!({"action": "draw_weapon"})),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: Utc::now(),
        actors: Some(json!([
            {"entity_id": agent_entity, "role": "AGENT", "context": "hero"}
        ])),
        action: Some("ACQUIRED".to_string()),
        context_data: None,
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: None,
        causes_event_ids: None,
    };

    let previous_event_result = conn.interact({
        let previous_event = previous_event.clone();
        move |conn| {
            diesel::insert_into(chronicle_events::table)
                .values(&previous_event)
                .get_result::<ChronicleEvent>(conn)
        }
    }).await.unwrap().unwrap();

    // Create current chronicle event
    let current_event = ChronicleEvent {
        id: current_event_id,
        chronicle_id,
        user_id: user.id,
        sequence_number: 2,
        event_type: "COMBAT_ACTION".to_string(),
        summary: "Hero attacks monster".to_string(),
        source: EventSource::AiExtracted.to_string(),
        event_data: Some(json!({"action": "attack", "weapon": "sword"})),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: Utc::now(),
        actors: Some(json!([
            {"entity_id": agent_entity, "role": "AGENT", "context": "hero"},
            {"entity_id": patient_entity, "role": "PATIENT", "context": "monster"}
        ])),
        action: Some("ATTACKED".to_string()),
        context_data: None,
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: None,
        causes_event_ids: None,
    };

    // Test enhanced translation with causality
    let result = translator.translate_event_with_causality(
        &current_event,
        user.id,
        Some(&previous_event_result)
    ).await;

    assert!(result.is_ok(), "Enhanced translation should succeed");
    
    let translation_result = result.unwrap();
    
    // Verify entities were created/updated
    assert!(!translation_result.entities_created.is_empty() || !translation_result.component_updates.is_empty(), 
           "Should create entities or update components");
    
    // Verify causal relationships were created
    assert!(!translation_result.relationship_updates.is_empty(), "Should create causal relationships");
    
    // Check that causal relationships include proper metadata
    let causal_relationships: Vec<_> = translation_result.relationship_updates.iter()
        .filter(|r| r.relationship_type == "causes_effect_on" || r.relationship_type == "affected_by")
        .collect();
    
    assert!(!causal_relationships.is_empty(), "Should create causal relationships");
    
    // Verify causal relationship has enhanced metadata
    for rel in &causal_relationships {
        let rel_data = &rel.relationship_data;
        assert!(rel_data.get("category").is_some(), "Should have category metadata");
        assert!(rel_data.get("causal_metadata").is_some(), "Should have causal metadata");
        assert!(rel_data.get("temporal_validity").is_some(), "Should have temporal validity");
    }
}

#[tokio::test]
async fn test_chronicle_event_causality_update() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let translator = ChronicleEcsTranslator::new(Arc::new(app.db_pool.clone()));
    let chronicle_id = create_test_chronicle(user.id, &app).await.unwrap();
    
    let previous_event_id = Uuid::new_v4();
    let current_event_id = Uuid::new_v4();
    
    let agent_entity = Uuid::new_v4();
    let patient_entity = Uuid::new_v4();
    
    let conn = app.db_pool.get().await.unwrap();
    
    // Insert entities
    let entities = vec![
        NewEcsEntity { id: agent_entity, user_id: user.id, archetype_signature: "Character".to_string() },
        NewEcsEntity { id: patient_entity, user_id: user.id, archetype_signature: "Character".to_string() },
    ];
    
    conn.interact({
        let entities = entities.clone();
        move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&entities)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Create and insert previous event
    let previous_event = NewChronicleEvent {
        chronicle_id,
        user_id: user.id,
        sequence_number: 1,
        event_type: "CAUSE".to_string(),
        summary: "Hero casts spell".to_string(),
        source: EventSource::AiExtracted.to_string(),
        event_data: Some(json!({"spell": "fireball"})),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: Utc::now(),
        actors: Some(json!([{"entity_id": agent_entity, "role": "AGENT"}])),
        action: Some("ACQUIRED".to_string()),
        context_data: None,
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: None,
        causes_event_ids: None,
    };

    let previous_event_record = conn.interact({
        let previous_event = previous_event.clone();
        move |conn| {
            diesel::insert_into(chronicle_events::table)
                .values(&previous_event)
                .get_result::<ChronicleEvent>(conn)
        }
    }).await.unwrap().unwrap();

    // Create current event (will be inserted by translation)
    let current_event = ChronicleEvent {
        id: current_event_id,
        chronicle_id,
        user_id: user.id,
        sequence_number: 2,
        event_type: "EFFECT".to_string(),
        summary: "Monster takes fire damage".to_string(),
        source: EventSource::AiExtracted.to_string(),
        event_data: Some(json!({"damage_type": "fire", "amount": 25})),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: Utc::now(),
        actors: Some(json!([
            {"entity_id": agent_entity, "role": "AGENT"},
            {"entity_id": patient_entity, "role": "PATIENT"}
        ])),
        action: Some("ATTACKED".to_string()),
        context_data: None,
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: None,
        causes_event_ids: None,
    };

    // Insert current event first (normally done by chronicle service)
    let current_event_record = conn.interact({
        let current_event_new = NewChronicleEvent {
            chronicle_id: current_event.chronicle_id,
            user_id: current_event.user_id,
            sequence_number: current_event.sequence_number,
            event_type: current_event.event_type.clone(),
            summary: current_event.summary.clone(),
            source: current_event.source.clone(),
            event_data: current_event.event_data.clone(),
            summary_encrypted: current_event.summary_encrypted.clone(),
            summary_nonce: current_event.summary_nonce.clone(),
            timestamp_iso8601: current_event.timestamp_iso8601,
            actors: current_event.actors.clone(),
            action: current_event.action.clone(),
            context_data: current_event.context_data.clone(),
            causality: current_event.causality.clone(),
            valence: current_event.valence.clone(),
            modality: current_event.modality.clone(),
            caused_by_event_id: current_event.caused_by_event_id,
            causes_event_ids: current_event.causes_event_ids.clone(),
        };
        move |conn| {
            diesel::insert_into(chronicle_events::table)
                .values(&current_event_new)
                .get_result::<ChronicleEvent>(conn)
        }
    }).await.unwrap().unwrap();

    // Perform enhanced translation using the actual inserted record
    let _translation_result = translator.translate_event_with_causality(
        &current_event_record,
        user.id,
        Some(&previous_event_record)
    ).await.unwrap();

    // Verify causality was updated in database
    let updated_previous_event = conn.interact({
        let previous_event_id = previous_event_record.id;
        move |conn| {
            chronicle_events::table
                .filter(chronicle_events::id.eq(previous_event_id))
                .select(ChronicleEvent::as_select())
                .first::<ChronicleEvent>(conn)
        }
    }).await.expect("DB interaction should succeed").expect("Previous event should exist in database");

    let updated_current_event = conn.interact({
        let current_event_id = current_event_record.id;
        move |conn| {
            chronicle_events::table
                .filter(chronicle_events::id.eq(current_event_id))
                .select(ChronicleEvent::as_select())
                .first::<ChronicleEvent>(conn)
        }
    }).await.expect("DB interaction should succeed").expect("Current event should exist in database");


    // Verify causal chain is properly established
    assert!(updated_current_event.caused_by_event_id.is_some(), "Current event should reference causing event");
    assert_eq!(updated_current_event.caused_by_event_id.unwrap(), previous_event_record.id, "Should reference correct causing event");
    
    assert!(updated_previous_event.causes_event_ids.is_some(), "Previous event should reference caused events");
    let causes_events = updated_previous_event.causes_event_ids.unwrap();
    assert!(causes_events.contains(&Some(current_event_record.id)), "Should reference correct caused event");
}

#[tokio::test]
async fn test_causal_relationship_creation() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let translator = ChronicleEcsTranslator::new(Arc::new(app.db_pool.clone()));
    let chronicle_id = create_test_chronicle(user.id, &app).await.unwrap();
    
    let agent_entity = Uuid::new_v4();
    let patient_entity = Uuid::new_v4();
    
    let conn = app.db_pool.get().await.unwrap();
    
    // Insert entities
    let entities = vec![
        NewEcsEntity { id: agent_entity, user_id: user.id, archetype_signature: "Character".to_string() },
        NewEcsEntity { id: patient_entity, user_id: user.id, archetype_signature: "Monster".to_string() },
    ];
    
    conn.interact({
        let entities = entities.clone();
        move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&entities)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Create event with clear agent-patient relationship
    let event = ChronicleEvent {
        id: Uuid::new_v4(),
        chronicle_id,
        user_id: user.id,
        sequence_number: 2,
        event_type: "ATTACK".to_string(),
        summary: "Hero strikes monster with sword".to_string(),
        source: EventSource::AiExtracted.to_string(),
        event_data: Some(json!({"weapon": "sword", "damage": 15})),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: Utc::now(),
        actors: Some(json!([
            {"entity_id": agent_entity, "role": "AGENT", "context": "hero"},
            {"entity_id": patient_entity, "role": "PATIENT", "context": "monster"}
        ])),
        action: Some("ATTACKED".to_string()),
        context_data: None,
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: None,
        causes_event_ids: None,
    };

    // Perform standard translation first to create base relationships
    let _base_result = translator.translate_event(&event, user.id).await.unwrap();

    // Now test enhanced translation with causality (using a dummy previous event)
    let dummy_previous = ChronicleEvent {
        id: Uuid::new_v4(),
        chronicle_id,
        user_id: user.id,
        sequence_number: 1,
        event_type: "PREPARATION".to_string(),
        summary: "Hero prepares for battle".to_string(),
        source: EventSource::AiExtracted.to_string(),
        event_data: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: Utc::now(),
        actors: Some(json!([{"entity_id": agent_entity, "role": "AGENT"}])),
        action: Some("PREPARE".to_string()),
        context_data: None,
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: None,
        causes_event_ids: None,
    };

    let causal_result = translator.translate_event_with_causality(
        &event,
        user.id,
        Some(&dummy_previous)
    ).await.unwrap();

    // Verify causal relationships were created
    let causal_rels: Vec<_> = causal_result.relationship_updates.iter()
        .filter(|r| r.relationship_type == "causes_effect_on" || r.relationship_type == "affected_by")
        .collect();

    assert!(!causal_rels.is_empty(), "Should create causal relationships");

    // Check database for persisted causal relationships
    let persisted_causal_rels = conn.interact({
        let user_id = user.id;
        move |conn| {
            use scribe_backend::models::ecs_diesel::EcsEntityRelationship;
            ecs_entity_relationships::table
                .filter(ecs_entity_relationships::user_id.eq(user_id))
                .filter(ecs_entity_relationships::relationship_category.eq(Some(RelationshipCategory::Causal.as_str().to_string())))
                .select(EcsEntityRelationship::as_select())
                .load::<EcsEntityRelationship>(conn)
        }
    }).await.unwrap().unwrap();

    assert!(!persisted_causal_rels.is_empty(), "Causal relationships should be persisted to database");

    // Verify causal relationship structure
    for rel in &persisted_causal_rels {
        assert_eq!(rel.relationship_category, Some(RelationshipCategory::Causal.as_str().to_string()));
        assert!(rel.strength.is_some(), "Causal relationships should have strength");
        assert!(rel.causal_metadata.is_some(), "Causal relationships should have metadata");
        assert!(rel.temporal_validity.is_some(), "Causal relationships should have temporal validity");
        
        // Verify causal metadata structure
        let causal_metadata = rel.causal_metadata.as_ref().unwrap();
        assert!(causal_metadata.get("caused_by_event").is_some(), "Should reference causing event");
        assert!(causal_metadata.get("confidence").is_some(), "Should have confidence score");
        assert!(causal_metadata.get("causality_type").is_some(), "Should specify causality type");
    }
}

// OWASP Security Tests for ChronicleEcsTranslator

#[tokio::test]
async fn test_translator_access_control() {
    // A01: Broken Access Control - Ensure translation only works with user's own data
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user1 = create_test_user(&app.db_pool, "user1".to_string(), "password123".to_string()).await.unwrap();
    let user2 = create_test_user(&app.db_pool, "user2".to_string(), "password123".to_string()).await.unwrap();

    let translator = ChronicleEcsTranslator::new(Arc::new(app.db_pool.clone()));
    let chronicle_id = create_test_chronicle(user1.id, &app).await.unwrap();
    
    let user1_entity = Uuid::new_v4();
    let user2_entity = Uuid::new_v4();
    
    let conn = app.db_pool.get().await.unwrap();
    
    // Create entities for different users
    let entities = vec![
        NewEcsEntity { id: user1_entity, user_id: user1.id, archetype_signature: "User1Entity".to_string() },
        NewEcsEntity { id: user2_entity, user_id: user2.id, archetype_signature: "User2Entity".to_string() },
    ];
    
    conn.interact({
        let entities = entities.clone();
        move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&entities)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Create event referencing User2's entity but attempted by User1
    let unauthorized_event = ChronicleEvent {
        id: Uuid::new_v4(),
        chronicle_id,
        user_id: user2.id, // Event belongs to user2
        sequence_number: 1,
        event_type: "UNAUTHORIZED_ACCESS".to_string(),
        summary: "Trying to access another user's entity".to_string(),
        source: EventSource::AiExtracted.to_string(),
        event_data: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: Utc::now(),
        actors: Some(json!([{"entity_id": user2_entity, "role": "AGENT"}])),
        action: Some("ACCESS".to_string()),
        context_data: None,
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: None,
        causes_event_ids: None,
    };

    // User1 should NOT be able to translate User2's event
    let translation_result = translator.translate_event(&unauthorized_event, user1.id).await;
    
    // This should either fail or create no entities/relationships for user1
    match translation_result {
        Ok(result) => {
            // If it succeeds, user1 should not gain access to user2's data
            // Verify no entities were created for user1
            let user1_entities_count = conn.interact({
                let user1_id = user1.id;
                move |conn| {
                    ecs_entities::table
                        .filter(ecs_entities::user_id.eq(user1_id))
                        .count()
                        .get_result::<i64>(conn)
                }
            }).await.unwrap().unwrap();
            
            // User1 should still only have their original entity
            assert_eq!(user1_entities_count, 1, "User1 should not gain access to additional entities");
        }
        Err(_) => {
            // Failure is also acceptable for access control
        }
    }
}

#[tokio::test]
async fn test_translator_injection_resistance() {
    // A03: Injection - Test SQL injection resistance in event translation
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let translator = ChronicleEcsTranslator::new(Arc::new(app.db_pool.clone()));
    let chronicle_id = create_test_chronicle(user.id, &app).await.unwrap();
    
    let entity_id = Uuid::new_v4();
    
    let conn = app.db_pool.get().await.unwrap();
    
    // Create entity
    let entity = NewEcsEntity { id: entity_id, user_id: user.id, archetype_signature: "TestEntity".to_string() };
    
    conn.interact({
        let entity = entity.clone();
        move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&entity)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Create event with malicious SQL injection attempts
    let malicious_event = ChronicleEvent {
        id: Uuid::new_v4(),
        chronicle_id,
        user_id: user.id,
        sequence_number: 1,
        event_type: "'; DROP TABLE ecs_entities; --".to_string(),
        summary: "'; DELETE FROM ecs_entity_relationships; --".to_string(),
        source: EventSource::AiExtracted.to_string(),
        event_data: Some(json!({
            "payload": "'; TRUNCATE chronicle_events; --",
            "script": "<script>alert('xss')</script>",
            "command": "; rm -rf /"
        })),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: Utc::now(),
        actors: Some(json!([{
            "entity_id": entity_id,
            "role": "'; UPDATE users SET password = 'hacked'; --",
            "context": "' UNION SELECT * FROM users --"
        }])),
        action: Some("'; DROP DATABASE; --".to_string()),
        context_data: Some(json!({
            "exploit": "' OR 1=1 --",
            "bypass": "admin' --"
        })),
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: None,
        causes_event_ids: None,
    };

    // Translation should handle malicious data safely
    let translation_result = translator.translate_event(&malicious_event, user.id).await;
    
    // Should either succeed safely or fail gracefully
    match translation_result {
        Ok(_) => {
            // If it succeeds, verify database integrity
            let entity_count = conn.interact(move |conn| {
                ecs_entities::table.count().get_result::<i64>(conn)
            }).await.unwrap().unwrap();
            
            let relationship_count = conn.interact(move |conn| {
                ecs_entity_relationships::table.count().get_result::<i64>(conn)
            }).await.unwrap().unwrap();
            
            assert!(entity_count > 0, "Entities table should still exist and have data");
            // Relationships might be 0 if none were created, that's fine
            assert!(relationship_count >= 0, "Relationships table should still exist");
        }
        Err(_) => {
            // Graceful failure is acceptable
        }
    }

    // Verify critical tables still exist and have expected data
    let final_entity_count = conn.interact(move |conn| {
        ecs_entities::table
            .filter(ecs_entities::user_id.eq(user.id))
            .count()
            .get_result::<i64>(conn)
    }).await.unwrap().unwrap();
    
    assert_eq!(final_entity_count, 1, "User's entity should still exist");
}

#[tokio::test]
async fn test_translator_data_integrity() {
    // A08: Software and Data Integrity Failures - Ensure translation maintains data consistency
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let translator = ChronicleEcsTranslator::new(Arc::new(app.db_pool.clone()));
    let chronicle_id = create_test_chronicle(user.id, &app).await.unwrap();
    
    let entity_id = Uuid::new_v4();
    
    let conn = app.db_pool.get().await.unwrap();
    
    // Create entity
    let entity = NewEcsEntity { 
        id: entity_id, 
        user_id: user.id, 
        archetype_signature: "Character|Health|Position".to_string() 
    };
    
    conn.interact({
        let entity = entity.clone();
        move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&entity)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Create event with data integrity requirements
    let integrity_event = ChronicleEvent {
        id: Uuid::new_v4(),
        chronicle_id,
        user_id: user.id,
        sequence_number: 1,
        event_type: "INTEGRITY_TEST".to_string(),
        summary: "Testing data integrity during translation".to_string(),
        source: EventSource::AiExtracted.to_string(),
        event_data: Some(json!({
            "checksum": "abcdef123456",
            "version": "1.0",
            "timestamp": Utc::now()
        })),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: Utc::now(),
        actors: Some(json!([{
            "entity_id": entity_id,
            "role": "AGENT",
            "context": "integrity_test"
        }])),
        action: Some("VERIFY_INTEGRITY".to_string()),
        context_data: None,
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: None,
        causes_event_ids: None,
    };

    // Perform translation multiple times - should be idempotent
    let result1 = translator.translate_event(&integrity_event, user.id).await.unwrap();
    let result2 = translator.translate_event(&integrity_event, user.id).await.unwrap();

    // Verify idempotency - multiple translations should not create duplicate data
    let final_entity_count = conn.interact({
        let user_id = user.id;
        move |conn| {
            ecs_entities::table
                .filter(ecs_entities::user_id.eq(user_id))
                .count()
                .get_result::<i64>(conn)
        }
    }).await.unwrap().unwrap();

    // Should still have exactly one entity (original)
    assert_eq!(final_entity_count, 1, "Translation should be idempotent - no duplicate entities");

    // Verify component data consistency
    let components = conn.interact({
        let entity_id = entity_id;
        let user_id = user.id;
        move |conn| {
            use scribe_backend::models::ecs_diesel::EcsComponent;
            use scribe_backend::schema::ecs_components;
            ecs_components::table
                .filter(ecs_components::entity_id.eq(entity_id))
                .filter(ecs_components::user_id.eq(user_id))
                .select(EcsComponent::as_select())
                .load::<EcsComponent>(conn)
        }
    }).await.unwrap().unwrap();

    // Verify component data integrity
    for component in &components {
        assert_eq!(component.user_id, user.id, "Component should belong to correct user");
        assert_eq!(component.entity_id, entity_id, "Component should belong to correct entity");
        assert!(!component.component_type.is_empty(), "Component type should not be empty");
        assert!(component.component_data.is_object() || component.component_data.is_null(), "Component data should be valid JSON");
        assert!(component.created_at <= Utc::now(), "Created timestamp should be valid");
        assert!(component.updated_at <= Utc::now(), "Updated timestamp should be valid");
        assert!(component.created_at <= component.updated_at, "Created should be <= updated");
    }
}

#[tokio::test]
async fn test_translator_performance_limits() {
    // Performance test to prevent DoS attacks through expensive translations
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let translator = ChronicleEcsTranslator::new(Arc::new(app.db_pool.clone()));
    let chronicle_id = create_test_chronicle(user.id, &app).await.unwrap();
    
    let entity_id = Uuid::new_v4();
    
    let conn = app.db_pool.get().await.unwrap();
    
    // Create entity
    let entity = NewEcsEntity { id: entity_id, user_id: user.id, archetype_signature: "Test".to_string() };
    
    conn.interact({
        let entity = entity.clone();
        move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&entity)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Create event with reasonable complexity
    let performance_event = ChronicleEvent {
        id: Uuid::new_v4(),
        chronicle_id,
        user_id: user.id,
        sequence_number: 1,
        event_type: "PERFORMANCE_TEST".to_string(),
        summary: "Testing translation performance".to_string(),
        source: EventSource::AiExtracted.to_string(),
        event_data: Some(json!({
            "complexity": "moderate",
            "actors_count": 1
        })),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: Utc::now(),
        actors: Some(json!([{
            "entity_id": entity_id,
            "role": "AGENT",
            "context": "performance_test"
        }])),
        action: Some("TEST_PERFORMANCE".to_string()),
        context_data: None,
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: None,
        causes_event_ids: None,
    };

    // Test translation performance
    let start_time = std::time::Instant::now();
    
    let translation_result = translator.translate_event(&performance_event, user.id).await;
    
    let translation_time = start_time.elapsed();
    
    assert!(translation_result.is_ok(), "Translation should succeed");
    assert!(translation_time.as_secs() < 10, "Translation should complete within 10 seconds");
    
    let result = translation_result.unwrap();
    
    // Verify reasonable limits on generated data
    assert!(result.entities_created.len() < 100, "Should not create excessive entities");
    assert!(result.component_updates.len() < 1000, "Should not create excessive components");
    assert!(result.relationship_updates.len() < 1000, "Should not create excessive relationships");
}