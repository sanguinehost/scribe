// CausalComponent Tests
//
// Tests for Phase 1: CausalComponent Dynamic Generation
// - Dynamic component assembly at query time
// - Causal relationship querying
// - Event chain building
// - OWASP security compliance

use std::sync::Arc;
use uuid::Uuid;
use serde_json::json;
use chrono::Utc;

use scribe_backend::{
    test_helpers::{spawn_app, TestDataGuard, db::create_test_user},
    models::{
        ecs::{CausalComponent, RelationshipCategory},
        ecs_diesel::{NewEcsEntityRelationship, NewEcsEntity},
        chronicle_event::{NewChronicleEvent, EventSource, ChronicleEvent},
    },
    errors::AppError,
    schema::{ecs_entity_relationships, ecs_entities, chronicle_events},
    PgPool,
};
use diesel::prelude::*;

// Helper to create a test chronicle
async fn create_test_chronicle(user_id: uuid::Uuid, test_app: &scribe_backend::test_helpers::TestApp) -> Result<uuid::Uuid, anyhow::Error> {
    use scribe_backend::services::ChronicleService;
    use scribe_backend::models::chronicle::CreateChronicleRequest;
    
    let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
    
    let create_request = CreateChronicleRequest {
        name: "Causal Component Test Chronicle".to_string(),
        description: Some("Testing causal component generation".to_string()),
    };
    
    let chronicle = chronicle_service
        .create_chronicle(user_id, create_request)
        .await?;
    
    Ok(chronicle.id)
}

#[tokio::test]
async fn test_causal_component_generation() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let entity_id = Uuid::new_v4();
    let causing_entity_id = Uuid::new_v4();
    let chronicle_id = create_test_chronicle(user.id, &app).await.unwrap();
    
    let conn = app.db_pool.get().await.unwrap();
    
    // Create entities
    let entities = vec![
        NewEcsEntity { id: entity_id, user_id: user.id, archetype_signature: "Character|Health".to_string() },
        NewEcsEntity { id: causing_entity_id, user_id: user.id, archetype_signature: "Character|Health".to_string() },
    ];
    
    conn.interact({
        let entities = entities.clone();
        move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&entities)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Create causal relationship
    let causal_relationship = NewEcsEntityRelationship {
        id: Uuid::new_v4(),
        from_entity_id: causing_entity_id,
        to_entity_id: entity_id,
        user_id: user.id,
        relationship_type: "causes_effect_on".to_string(),
        relationship_data: json!({
            "effect_type": "damage",
            "magnitude": 10.0
        }),
        relationship_category: Some(RelationshipCategory::Causal.as_str().to_string()),
        strength: Some(0.8),
        causal_metadata: Some(json!({
            "caused_by_event": Uuid::new_v4(),
            "confidence": 0.9,
            "causality_type": "direct"
        })),
        temporal_validity: Some(json!({
            "valid_from": Utc::now(),
            "valid_until": null,
            "confidence": 1.0
        })),
    };

    conn.interact({
        let causal_relationship = causal_relationship.clone();
        move |conn| {
            diesel::insert_into(ecs_entity_relationships::table)
                .values(&causal_relationship)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Create chronicle events for causal chain
    let causing_event_id = Uuid::new_v4();
    let caused_event_id = Uuid::new_v4();
    
    let causing_event = NewChronicleEvent {
        chronicle_id,
        user_id: user.id,
        event_type: "COMBAT".to_string(),
        summary: "Hero attacks monster".to_string(),
        source: EventSource::AiExtracted.to_string(),
        event_data: Some(json!({"action": "attack"})),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: Utc::now(),
        actors: Some(json!([
            {"entity_id": causing_entity_id, "role": "AGENT"},
            {"entity_id": entity_id, "role": "PATIENT"}
        ])),
        action: Some("ATTACK".to_string()),
        context_data: None,
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: None,
        causes_event_ids: None,
        sequence_number: 0,
    };

    let caused_event = NewChronicleEvent {
        chronicle_id,
        user_id: user.id,
        event_type: "COMBAT_RESULT".to_string(),
        summary: "Monster takes damage".to_string(),
        source: EventSource::AiExtracted.to_string(),
        event_data: Some(json!({"result": "damage_taken"})),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: Utc::now(),
        actors: Some(json!([
            {"entity_id": entity_id, "role": "PATIENT"}
        ])),
        action: Some("TAKE_DAMAGE".to_string()),
        context_data: None,
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: None,
        causes_event_ids: None,
        sequence_number: 0,
    };

    // Insert causing event first (no dependencies)
    let causing_event_result = conn.interact({
        let causing_event = causing_event.clone();
        move |conn| {
            diesel::insert_into(chronicle_events::table)
                .values(&causing_event)
                .get_result::<ChronicleEvent>(conn)
        }
    }).await.unwrap().unwrap();

    // Update caused event to reference causing event
    let mut caused_event_with_ref = caused_event.clone();
    caused_event_with_ref.caused_by_event_id = Some(causing_event_result.id);

    // Insert caused event (references causing event)
    conn.interact({
        let caused_event = caused_event_with_ref.clone();
        move |conn| {
            diesel::insert_into(chronicle_events::table)
                .values(&caused_event)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Test CausalComponent generation
    let causal_component = CausalComponent::generate_for_entity(
        entity_id,
        user.id,
        &app.db_pool
    ).await;

    assert!(causal_component.is_ok(), "CausalComponent generation should succeed");
    
    let component = causal_component.unwrap();
    
    // Verify component structure
    assert!(!component.caused_by_events.is_empty(), "Should have causing events");
    assert!(component.causal_confidence >= 0.0 && component.causal_confidence <= 1.0, "Confidence should be between 0 and 1");
    assert!(component.causal_chain_depth > 0, "Should have non-zero chain depth");
    assert!(!component.causal_metadata.is_empty(), "Should have causal metadata");
    
    // Verify specific causal relationships
    assert!(component.caused_by_events.contains(&causing_event_result.id), "Should include causing event");
}

#[tokio::test]
async fn test_causal_component_empty_case() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let entity_id = Uuid::new_v4();
    
    let conn = app.db_pool.get().await.unwrap();
    
    // Create entity with no causal relationships
    let entity = NewEcsEntity { 
        id: entity_id, 
        user_id: user.id, 
        archetype_signature: "Isolated".to_string() 
    };
    
    conn.interact({
        let entity = entity.clone();
        move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&entity)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Test CausalComponent generation for entity with no causal data
    let causal_component = CausalComponent::generate_for_entity(
        entity_id,
        user.id,
        &app.db_pool
    ).await;

    assert!(causal_component.is_ok(), "CausalComponent generation should succeed even with no data");
    
    let component = causal_component.unwrap();
    
    // Verify empty component structure
    assert!(component.caused_by_events.is_empty(), "Should have no causing events");
    assert!(component.causes_events.is_empty(), "Should have no caused events");
    assert_eq!(component.causal_confidence, 0.0, "Confidence should be 0.0 for empty component");
    assert_eq!(component.causal_chain_depth, 0, "Chain depth should be 0 for empty component");
    // Verify metadata contains zero counts for empty component
    assert_eq!(component.causal_metadata.get("relationship_count").unwrap().as_u64().unwrap(), 0);
    assert_eq!(component.causal_metadata.get("caused_by_count").unwrap().as_u64().unwrap(), 0);
    assert_eq!(component.causal_metadata.get("causes_count").unwrap().as_u64().unwrap(), 0);
}

#[tokio::test]
async fn test_causal_component_complex_chain() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let entity_id = Uuid::new_v4();
    let chronicle_id = create_test_chronicle(user.id, &app).await.unwrap();
    
    let conn = app.db_pool.get().await.unwrap();
    
    // Create entity
    let entity = NewEcsEntity { 
        id: entity_id, 
        user_id: user.id, 
        archetype_signature: "Character".to_string() 
    };
    
    conn.interact({
        let entity = entity.clone();
        move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&entity)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Create a complex causal chain: Event A -> Event B -> Event C
    // Insert Event A first (no dependencies)
    let event_a = NewChronicleEvent {
        chronicle_id,
        user_id: user.id,
        event_type: "INITIAL_ACTION".to_string(),
        summary: "Hero casts spell".to_string(),
        source: EventSource::AiExtracted.to_string(),
        event_data: Some(json!({"spell": "fireball"})),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: Utc::now(),
        actors: Some(json!([{"entity_id": entity_id, "role": "AGENT"}])),
        action: Some("CAST_SPELL".to_string()),
        context_data: None,
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: None,
        causes_event_ids: None,
        sequence_number: 0,
    };

    let event_a_result = conn.interact({
        let event_a = event_a.clone();
        move |conn| {
            diesel::insert_into(chronicle_events::table)
                .values(&event_a)
                .get_result::<ChronicleEvent>(conn)
        }
    }).await.unwrap().unwrap();

    // Insert Event B (depends on A)
    let event_b = NewChronicleEvent {
        chronicle_id,
        user_id: user.id,
        event_type: "INTERMEDIATE_EFFECT".to_string(),
        summary: "Spell creates explosion".to_string(),
        source: EventSource::AiExtracted.to_string(),
        event_data: Some(json!({"effect": "explosion"})),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: Utc::now(),
        actors: Some(json!([{"entity_id": entity_id, "role": "SUBJECT"}])),
        action: Some("EXPLODE".to_string()),
        context_data: None,
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: Some(event_a_result.id),
        causes_event_ids: None,
        sequence_number: 1,
    };

    let event_b_result = conn.interact({
        let event_b = event_b.clone();
        move |conn| {
            diesel::insert_into(chronicle_events::table)
                .values(&event_b)
                .get_result::<ChronicleEvent>(conn)
        }
    }).await.unwrap().unwrap();

    // Insert Event C (depends on B)
    let event_c = NewChronicleEvent {
        chronicle_id,
        user_id: user.id,
        event_type: "FINAL_RESULT".to_string(),
        summary: "Enemies are defeated".to_string(),
        source: EventSource::AiExtracted.to_string(),
        event_data: Some(json!({"result": "victory"})),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: Utc::now(),
        actors: Some(json!([{"entity_id": entity_id, "role": "BENEFICIARY"}])),
        action: Some("DEFEAT_ENEMIES".to_string()),
        context_data: None,
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: Some(event_b_result.id),
        causes_event_ids: None,
        sequence_number: 2,
    };

    conn.interact({
        let event_c = event_c.clone();
        move |conn| {
            diesel::insert_into(chronicle_events::table)
                .values(&event_c)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Test CausalComponent generation for complex chain
    let causal_component = CausalComponent::generate_for_entity(
        entity_id,
        user.id,
        &app.db_pool
    ).await;

    assert!(causal_component.is_ok(), "CausalComponent generation should succeed for complex chain");
    
    let component = causal_component.unwrap();
    
    // Verify complex chain properties
    println!("Causal chain depth: {}", component.causal_chain_depth);
    println!("Caused by events: {:?}", component.caused_by_events);
    println!("Causes events: {:?}", component.causes_events);
    assert!(component.causal_chain_depth >= 2, "Should detect multi-step causal chain");
    assert!(component.causal_confidence > 0.0, "Should have positive confidence");
    
    // Should include events where entity is involved in causality
    let all_entity_events = vec![event_a_result.id, event_b_result.id];
    let component_events: std::collections::HashSet<_> = component.caused_by_events.iter()
        .chain(component.causes_events.iter())
        .collect();
    
    // At least some events should be captured
    assert!(!component_events.is_empty(), "Should capture some causal events");
}

// OWASP Security Tests for CausalComponent

#[tokio::test]
async fn test_causal_component_access_control() {
    // A01: Broken Access Control - Ensure users can only generate causal components for their own entities
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user1 = create_test_user(&app.db_pool, "user1".to_string(), "password123".to_string()).await.unwrap();
    let user2 = create_test_user(&app.db_pool, "user2".to_string(), "password123".to_string()).await.unwrap();

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

    // User1 should be able to generate causal component for their own entity
    let user1_component = CausalComponent::generate_for_entity(
        user1_entity,
        user1.id,
        &app.db_pool
    ).await;
    assert!(user1_component.is_ok(), "User1 should access their own entity");

    // User1 should NOT be able to generate causal component for User2's entity
    let unauthorized_component = CausalComponent::generate_for_entity(
        user2_entity,
        user1.id,  // User1 trying to access User2's entity
        &app.db_pool
    ).await;
    
    // This should either fail or return empty data (implementation dependent)
    match unauthorized_component {
        Ok(component) => {
            // If it succeeds, it should return empty data (no access to user2's relationships/events)
            assert!(component.caused_by_events.is_empty(), "Should not see other user's causal data");
            assert!(component.causes_events.is_empty(), "Should not see other user's causal data");
        }
        Err(_) => {
            // If it fails, that's also acceptable for access control
        }
    }
}

#[tokio::test]
async fn test_causal_component_injection_resistance() {
    // A03: Injection - Test that malicious data in causal relationships doesn't affect component generation
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let entity_id = Uuid::new_v4();
    let malicious_entity_id = Uuid::new_v4();
    
    let conn = app.db_pool.get().await.unwrap();
    
    // Create entities
    let entities = vec![
        NewEcsEntity { id: entity_id, user_id: user.id, archetype_signature: "Target".to_string() },
        NewEcsEntity { id: malicious_entity_id, user_id: user.id, archetype_signature: "Malicious".to_string() },
    ];
    
    conn.interact({
        let entities = entities.clone();
        move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&entities)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Create relationship with malicious JSON content
    let malicious_relationship = NewEcsEntityRelationship {
        id: Uuid::new_v4(),
        from_entity_id: malicious_entity_id,
        to_entity_id: entity_id,
        user_id: user.id,
        relationship_type: "'; DROP TABLE ecs_entity_relationships; --".to_string(),
        relationship_data: json!({
            "payload": "'; DELETE FROM chronicle_events; --",
            "script": "<script>alert('xss')</script>",
            "command": "; rm -rf /"
        }),
        relationship_category: Some("causal".to_string()),
        strength: Some(0.5),
        causal_metadata: Some(json!({
            "malicious_field": "'; TRUNCATE ecs_entities; --",
            "xss_attempt": "<img src=x onerror=alert('xss')>"
        })),
        temporal_validity: Some(json!({
            "exploit": "' UNION SELECT password FROM users --"
        })),
    };

    conn.interact({
        let malicious_relationship = malicious_relationship.clone();
        move |conn| {
            diesel::insert_into(ecs_entity_relationships::table)
                .values(&malicious_relationship)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Generate causal component - should handle malicious data safely
    let causal_component = CausalComponent::generate_for_entity(
        entity_id,
        user.id,
        &app.db_pool
    ).await;

    assert!(causal_component.is_ok(), "CausalComponent generation should succeed despite malicious data");
    
    // Verify system integrity - tables should still exist
    let entity_count = conn.interact(move |conn| {
        ecs_entities::table.count().get_result::<i64>(conn)
    }).await.unwrap().unwrap();
    
    let relationship_count = conn.interact(move |conn| {
        ecs_entity_relationships::table.count().get_result::<i64>(conn)
    }).await.unwrap().unwrap();
    
    assert!(entity_count > 0, "Entities table should still exist");
    assert!(relationship_count > 0, "Relationships table should still exist");
}

#[tokio::test]
async fn test_causal_component_data_integrity() {
    // A08: Software and Data Integrity Failures - Ensure causal component data is consistent and validated
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let entity_id = Uuid::new_v4();
    let chronicle_id = create_test_chronicle(user.id, &app).await.unwrap();
    
    let conn = app.db_pool.get().await.unwrap();
    
    // Create entity
    let entity = NewEcsEntity { 
        id: entity_id, 
        user_id: user.id, 
        archetype_signature: "TestEntity".to_string() 
    };
    
    conn.interact({
        let entity = entity.clone();
        move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&entity)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Create chronicle event with integrity constraints
    let event_id = Uuid::new_v4();
    let event = NewChronicleEvent {
        chronicle_id,
        user_id: user.id,
        event_type: "INTEGRITY_TEST".to_string(),
        summary: "Test event for data integrity".to_string(),
        source: EventSource::AiExtracted.to_string(),
        event_data: Some(json!({
            "checksum": "sha256_hash_here",
            "version": "1.0",
            "verified": true
        })),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: Utc::now(),
        actors: Some(json!([{"entity_id": entity_id, "role": "SUBJECT"}])),
        action: Some("VERIFY".to_string()),
        context_data: None,
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: None,
        causes_event_ids: None,
        sequence_number: 0,
    };

    conn.interact({
        let event = event.clone();
        move |conn| {
            diesel::insert_into(chronicle_events::table)
                .values(&event)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Generate causal component multiple times - should be consistent
    let component1 = CausalComponent::generate_for_entity(
        entity_id,
        user.id,
        &app.db_pool
    ).await.unwrap();
    
    let component2 = CausalComponent::generate_for_entity(
        entity_id,
        user.id,
        &app.db_pool
    ).await.unwrap();

    // Verify consistency between multiple generations
    assert_eq!(component1.caused_by_events, component2.caused_by_events, "Caused by events should be consistent");
    assert_eq!(component1.causes_events, component2.causes_events, "Causes events should be consistent");
    assert_eq!(component1.causal_chain_depth, component2.causal_chain_depth, "Chain depth should be consistent");
    assert_eq!(component1.causal_confidence, component2.causal_confidence, "Confidence should be consistent");
    
    // Verify data integrity constraints
    assert!(component1.causal_confidence >= 0.0 && component1.causal_confidence <= 1.0, "Confidence should be in valid range");
    assert!(component1.causal_chain_depth >= 0, "Chain depth should be non-negative");
    
    // Verify no data corruption in metadata
    for (key, value) in &component1.causal_metadata {
        assert!(!key.is_empty(), "Metadata keys should not be empty");
        assert!(value.is_string() || value.is_number() || value.is_boolean() || value.is_object() || value.is_array(), "Metadata values should be valid JSON types");
    }
}

#[tokio::test]
async fn test_causal_component_performance_limits() {
    // Performance and DoS protection test - ensure component generation doesn't consume excessive resources
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let entity_id = Uuid::new_v4();
    
    let conn = app.db_pool.get().await.unwrap();
    
    // Create entity
    let entity = NewEcsEntity { 
        id: entity_id, 
        user_id: user.id, 
        archetype_signature: "PerformanceTest".to_string() 
    };
    
    conn.interact({
        let entity = entity.clone();
        move |conn| {
            diesel::insert_into(ecs_entities::table)
                .values(&entity)
                .execute(conn)
        }
    }).await.unwrap().unwrap();

    // Test component generation with timeout
    let start_time = std::time::Instant::now();
    
    let causal_component = CausalComponent::generate_for_entity(
        entity_id,
        user.id,
        &app.db_pool
    ).await;

    let generation_time = start_time.elapsed();
    
    assert!(causal_component.is_ok(), "Component generation should succeed");
    assert!(generation_time.as_secs() < 5, "Component generation should complete within 5 seconds");
    
    let component = causal_component.unwrap();
    
    // Verify reasonable limits on generated data
    assert!(component.caused_by_events.len() < 10000, "Should not generate excessive caused_by events");
    assert!(component.causes_events.len() < 10000, "Should not generate excessive causes events");
    assert!(component.causal_metadata.len() < 1000, "Should not generate excessive metadata entries");
    assert!(component.causal_chain_depth < 1000, "Should not calculate excessive chain depth");
}