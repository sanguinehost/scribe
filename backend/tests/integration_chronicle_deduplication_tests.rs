//! Comprehensive End-to-End Chronicle Event Deduplication Integration Tests
//! 
//! These tests are CRITICAL for maintaining chronicle integrity. They validate that
//! the Ars Fabula-based deduplication system correctly identifies and prevents
//! duplicate events from being created, specifically addressing the Mount Everest
//! scenario and other edge cases.
//!
//! Test Coverage:
//! - Mount Everest scenario (3 identical cleansing events)
//! - Temporal boundary testing (5-minute window)
//! - Actor overlap variations (different similarity thresholds)
//! - Action similarity (semantic grouping)
//! - Mixed modality scenarios
//! - Cross-chronicle isolation
//! - Performance under load

use chrono::{DateTime, Utc, Duration};
use serde_json::json;
use uuid::Uuid;

use scribe_backend::{
    auth::user_store::{create_user_in_db, Backend as AuthBackend},
    config::Config,
    models::{
        chronicle::{CreateChronicleRequest},
        chronicle_event::{CreateEventRequest, EventSource, EventFilter},
        narrative_ontology::{
            NarrativeEvent, NarrativeAction, ActorRole, EventModality,
            ValenceType,
        },
    },
    services::{
        ChronicleService, ChronicleDeduplicationService, DeduplicationConfig,
    },
    test_helpers::*,
};
use scribe_backend::test_helpers::db::setup_test_database;
use std::sync::Arc;

/// Test fixture for Mount Everest scenario
struct MountEverestTestFixture {
    user_id: Uuid,
    chronicle_id: Uuid,
    lucas_persona_id: Uuid,
    mount_everest_location_id: Uuid,
    chronicle_service: ChronicleService,
    dedup_service: ChronicleDeduplicationService,
    auth_backend: Arc<AuthBackend>,
    _db_pool: scribe_backend::PgPool, // Keep reference to prevent cleanup
}

impl MountEverestTestFixture {
    async fn new() -> Self {
        let db_pool = setup_test_database(Some("mount_everest")).await;
        let config = Arc::new(Config::load().expect("Failed to load config"));
        
        // Create mock services for testing
        let ai_client = Arc::new(MockAiClient::new());
        let embedding_client = Arc::new(MockEmbeddingClient::new());
        let qdrant_service = Arc::new(MockQdrantClientService::new());
        let auth_backend = Arc::new(AuthBackend::new(db_pool.clone()));
        
        let app_state = TestAppStateBuilder::new(
            db_pool.clone(),
            config.clone(),
            ai_client,
            embedding_client,
            qdrant_service,
            auth_backend.clone(),
        )
        .build()
        .await
        .expect("Failed to build test app state");

        let lucas_persona_id = Uuid::new_v4();
        let mount_everest_location_id = Uuid::new_v4();

        // Create a user for the chronicle
        let user = create_user_in_db(
            &db_pool,
            &format!("test-user-{}", Uuid::new_v4()),
            "password123",
            &format!("test-user-{}@example.com", Uuid::new_v4()),
            None,
        )
        .await
        .expect("Failed to create test user");
        let user_id = user.id;

        // Create test chronicle
        let chronicle_service = ChronicleService::new(db_pool.clone());
        let chronicle_request = CreateChronicleRequest {
            name: "Lucas's Adventure Chronicle".to_string(),
            description: Some("Chronicle of Lucas's spiritual journey".to_string()),
        };
        let chronicle = chronicle_service
            .create_chronicle(user_id, chronicle_request)
            .await
            .expect("Failed to create test chronicle");

        let dedup_service = ChronicleDeduplicationService::new(
            db_pool.clone(),
            Some(DeduplicationConfig {
                time_window_minutes: 5,
                actor_overlap_threshold: 0.6,
                enable_action_similarity: true,
                max_events_to_check: 50,
                duplicate_confidence_threshold: 0.7,
            }),
        );

        Self {
            user_id,
            chronicle_id: chronicle.id,
            lucas_persona_id,
            mount_everest_location_id,
            chronicle_service,
            dedup_service,
            auth_backend,
            _db_pool: db_pool,
        }
    }

    /// Create the canonical Mount Everest cleansing event
    fn create_mount_everest_event(&self, timestamp: DateTime<Utc>) -> NarrativeEvent {
        let mut event = NarrativeEvent::new(
            "SPIRITUAL.CLEANSING.LOCATION".to_string(),
            NarrativeAction::Custom("CLEANSED".to_string()),
            "Lucas performed a spiritual cleansing ritual at Mount Everest".to_string(),
        );
        event.timestamp = timestamp;
        event
            .add_actor(self.lucas_persona_id, ActorRole::Agent)
            .add_actor(self.mount_everest_location_id, ActorRole::Patient)
            .with_modality(EventModality::Actual)
            .add_valence(self.lucas_persona_id, ValenceType::Health, 0.3)
            .add_valence(self.lucas_persona_id, ValenceType::Knowledge, 0.2)
    }

    /// Create a slight variation of the Mount Everest event (should still be detected as duplicate)
    fn create_mount_everest_variant(&self, timestamp: DateTime<Utc>, summary_variant: &str) -> NarrativeEvent {
        let mut event = NarrativeEvent::new(
            "SPIRITUAL.CLEANSING.LOCATION".to_string(),
            NarrativeAction::Custom("CLEANSED".to_string()),
            summary_variant.to_string(),
        );
        event.timestamp = timestamp;
        event
            .add_actor(self.lucas_persona_id, ActorRole::Agent)
            .add_actor(self.mount_everest_location_id, ActorRole::Patient)
            .with_modality(EventModality::Actual)
            .add_valence(self.lucas_persona_id, ValenceType::Health, 0.25) // Slightly different valence
    }

    /// Create a different but related event (should NOT be detected as duplicate)
    fn create_different_event(&self, timestamp: DateTime<Utc>) -> NarrativeEvent {
        let mut event = NarrativeEvent::new(
            "SPIRITUAL.MEDITATION.LOCATION".to_string(),
            NarrativeAction::Custom("MEDITATED".to_string()),
            "Lucas meditated at Mount Everest, finding inner peace".to_string(),
        );
        event.timestamp = timestamp;
        event
            .add_actor(self.lucas_persona_id, ActorRole::Agent)
            .add_actor(self.mount_everest_location_id, ActorRole::Patient)
            .with_modality(EventModality::Actual)
    }

    /// Convert NarrativeEvent to CreateEventRequest for API testing
    fn narrative_to_create_request(&self, narrative_event: &NarrativeEvent) -> CreateEventRequest {
        CreateEventRequest {
            event_type: narrative_event.event_type.clone(),
            summary: narrative_event.summary.clone(),
            source: EventSource::AiExtracted,
            event_data: Some(json!({
                "actors": narrative_event.actors,
                "action": narrative_event.action,
                "causality": narrative_event.causality,
                "valence": narrative_event.valence,
                "modality": narrative_event.modality,
                "timestamp_iso8601": narrative_event.timestamp,
            })),
            timestamp_iso8601: narrative_event.timestamp.clone(),
        }
    }
}

/// Test the exact Mount Everest scenario that was failing
#[tokio::test]
async fn test_mount_everest_deduplication_scenario() {
    let fixture = MountEverestTestFixture::new().await;
    let base_time = Utc::now();

    // Create the first Mount Everest event - this should succeed
    let event1 = fixture.create_mount_everest_event(base_time);
    let request1 = fixture.narrative_to_create_request(&event1);
    
    let created_event1 = fixture
        .chronicle_service
        .create_event(
            fixture.user_id,
            fixture.chronicle_id,
            request1,
            None, // No encryption for test
        )
        .await
        .expect("First event creation should succeed");

    println!("✓ First Mount Everest event created successfully: {}", created_event1.id);

    // Create the second Mount Everest event 2 minutes later - this should be detected as duplicate
    let event2 = fixture.create_mount_everest_event(base_time + Duration::minutes(2));
    let request2 = fixture.narrative_to_create_request(&event2);
    
    let created_event2 = fixture
        .chronicle_service
        .create_event(
            fixture.user_id,
            fixture.chronicle_id,
            request2,
            None,
        )
        .await
        .expect("Second event creation should return existing event");

    // The second event should return the same ID as the first (deduplication occurred)
    assert_eq!(
        created_event1.id, created_event2.id,
        "Second event should be deduplicated and return the first event's ID"
    );
    println!("✓ Second Mount Everest event correctly deduplicated to: {}", created_event2.id);

    // Create the third Mount Everest event 3 minutes later with slight variation - should still be duplicate
    let event3 = fixture.create_mount_everest_variant(
        base_time + Duration::minutes(3),
        "Lucas conducted a purification ceremony at Mount Everest's peak",
    );
    let request3 = fixture.narrative_to_create_request(&event3);
    
    let created_event3 = fixture
        .chronicle_service
        .create_event(
            fixture.user_id,
            fixture.chronicle_id,
            request3,
            None,
        )
        .await
        .expect("Third event creation should return existing event");

    // The third event should also return the same ID as the first
    assert_eq!(
        created_event1.id, created_event3.id,
        "Third event should be deduplicated and return the first event's ID"
    );
    println!("✓ Third Mount Everest event correctly deduplicated to: {}", created_event3.id);

    // Verify only one event exists in the database
    let events = fixture
        .chronicle_service
        .get_chronicle_events(
            fixture.user_id,
            fixture.chronicle_id,
            EventFilter::default(),
        )
        .await
        .expect("Failed to retrieve events");

    assert_eq!(
        events.len(), 1,
        "Should have exactly 1 event in chronicle, found: {}",
        events.len()
    );
    println!("✓ Database contains exactly 1 event as expected");

    // Verify the event has the correct action
    let event = &events[0];
    assert_eq!(
        event.action.as_deref(), Some("CLEANSED"),
        "Event should have CLEANSED action"
    );
    println!("✓ Event has correct action: {:?}", event.action);

    // Verify the event has the correct actors
    let actors = event.get_actors().expect("Failed to parse actors");
    assert_eq!(actors.len(), 2, "Event should have 2 actors");
    
    let actor_ids: Vec<Uuid> = actors.iter().map(|a| a.entity_id).collect();
    assert!(actor_ids.contains(&fixture.lucas_persona_id), "Should contain Lucas persona");
    assert!(actor_ids.contains(&fixture.mount_everest_location_id), "Should contain Mount Everest location");
    println!("✓ Event has correct actors: Lucas and Mount Everest");
}

/// Test temporal boundary conditions
#[tokio::test]
async fn test_temporal_boundary_deduplication() {
    let fixture = MountEverestTestFixture::new().await;
    let base_time = Utc::now();

    // Create first event
    let event1 = fixture.create_mount_everest_event(base_time);
    let request1 = fixture.narrative_to_create_request(&event1);
    let created_event1 = fixture
        .chronicle_service
        .create_event(fixture.user_id, fixture.chronicle_id, request1, None)
        .await
        .expect("First event should succeed");

    // Create event just within the 5-minute window (4 minutes 59 seconds later)
    let event2 = fixture.create_mount_everest_event(base_time + Duration::seconds(299));
    let request2 = fixture.narrative_to_create_request(&event2);
    let created_event2 = fixture
        .chronicle_service
        .create_event(fixture.user_id, fixture.chronicle_id, request2, None)
        .await
        .expect("Second event should be deduplicated");

    assert_eq!(
        created_event1.id, created_event2.id,
        "Event within time window should be deduplicated"
    );

    // Create event just outside the 5-minute window (6 minutes after Event 1's actual timestamp)
    let event3 = fixture.create_mount_everest_event(created_event1.timestamp_iso8601 + Duration::seconds(360));
    let request3 = fixture.narrative_to_create_request(&event3);
    
    println!("Event 1 timestamp: {}", created_event1.timestamp_iso8601);
    println!("Event 3 timestamp: {}", event3.timestamp);
    println!("Time diff in minutes: {}", (event3.timestamp - created_event1.timestamp_iso8601).num_minutes());
    println!("Time diff in seconds: {}", (event3.timestamp - created_event1.timestamp_iso8601).num_seconds());
    
    let created_event3 = fixture
        .chronicle_service
        .create_event(fixture.user_id, fixture.chronicle_id, request3, None)
        .await
        .expect("Third event should succeed");

    println!("Event 1 ID: {}, Event 3 ID: {}", created_event1.id, created_event3.id);

    assert_ne!(
        created_event1.id, created_event3.id,
        "Event outside time window should NOT be deduplicated"
    );

    // Verify we have exactly 2 events
    let events = fixture
        .chronicle_service
        .get_chronicle_events(fixture.user_id, fixture.chronicle_id, EventFilter::default())
        .await
        .expect("Failed to retrieve events");

    assert_eq!(events.len(), 2, "Should have exactly 2 events");
    println!("✓ Temporal boundary deduplication working correctly");
}

/// Test actor overlap threshold variations
#[tokio::test]
async fn test_actor_overlap_threshold() {
    let fixture = MountEverestTestFixture::new().await;
    let base_time = Utc::now();

    // Create first event with Lucas and Mount Everest
    let event1 = fixture.create_mount_everest_event(base_time);
    let request1 = fixture.narrative_to_create_request(&event1);
    let created_event1 = fixture
        .chronicle_service
        .create_event(fixture.user_id, fixture.chronicle_id, request1, None)
        .await
        .expect("First event should succeed");

    // Create event with Lucas, Mount Everest, and additional witness (should still be duplicate)
    let witness_id = Uuid::new_v4();
    let mut event2 = fixture.create_mount_everest_event(base_time + Duration::minutes(2));
    event2 = event2.add_actor(witness_id, ActorRole::Witness);
    let request2 = fixture.narrative_to_create_request(&event2);
    let created_event2 = fixture
        .chronicle_service
        .create_event(fixture.user_id, fixture.chronicle_id, request2, None)
        .await
        .expect("Second event should be deduplicated");

    // With 2/3 actors matching (66.7% overlap), this should still be deduplicated
    // because our threshold is 60%
    assert_eq!(
        created_event1.id, created_event2.id,
        "Event with 66.7% actor overlap should be deduplicated (threshold: 60%)"
    );

    // Create event with only Lucas (should NOT be duplicate due to low overlap)
    let mut event3 = NarrativeEvent::new(
        "SPIRITUAL.CLEANSING.LOCATION".to_string(),
        NarrativeAction::Custom("CLEANSED".to_string()),
        "Lucas performed solo cleansing".to_string(),
    );
    event3 = event3.add_actor(fixture.lucas_persona_id, ActorRole::Agent);
    let request3 = fixture.narrative_to_create_request(&event3);
    let created_event3 = fixture
        .chronicle_service
        .create_event(fixture.user_id, fixture.chronicle_id, request3, None)
        .await
        .expect("Third event should succeed");

    // With 1/2 actors matching (50% overlap), this should NOT be deduplicated
    assert_ne!(
        created_event1.id, created_event3.id,
        "Event with 50% actor overlap should NOT be deduplicated (threshold: 60%)"
    );

    println!("✓ Actor overlap threshold working correctly");
}

/// Test semantic action similarity
#[tokio::test]
async fn test_semantic_action_similarity() {
    let fixture = MountEverestTestFixture::new().await;
    let base_time = Utc::now();

    // Create first event with DISCOVERED action
    let mut event1 = NarrativeEvent::new(
        "EXPLORATION.DISCOVERY.LOCATION".to_string(),
        NarrativeAction::Discovered,
        "Lucas discovered a hidden cave at Mount Everest".to_string(),
    );
    event1 = event1
        .add_actor(fixture.lucas_persona_id, ActorRole::Agent)
        .add_actor(fixture.mount_everest_location_id, ActorRole::Patient);
    let request1 = fixture.narrative_to_create_request(&event1);
    let created_event1 = fixture
        .chronicle_service
        .create_event(fixture.user_id, fixture.chronicle_id, request1, None)
        .await
        .expect("First event should succeed");

    // Create second event with FOUND action (semantically similar to DISCOVERED)
    let mut event2 = NarrativeEvent::new(
        "EXPLORATION.DISCOVERY.LOCATION".to_string(),
        NarrativeAction::Found,
        "Lucas found a secret passage near Mount Everest".to_string(),
    );
    event2 = event2
        .add_actor(fixture.lucas_persona_id, ActorRole::Agent)
        .add_actor(fixture.mount_everest_location_id, ActorRole::Patient);
    let request2 = fixture.narrative_to_create_request(&event2);
    let created_event2 = fixture
        .chronicle_service
        .create_event(fixture.user_id, fixture.chronicle_id, request2, None)
        .await
        .expect("Second event should be deduplicated");

    // DISCOVERED and FOUND are in the same semantic group, so this should be deduplicated
    assert_eq!(
        created_event1.id, created_event2.id,
        "Semantically similar actions (DISCOVERED/FOUND) should be deduplicated"
    );

    // Create third event with ATTACKED action (different semantic group)
    let mut event3 = NarrativeEvent::new(
        "COMBAT.ATTACK.TARGET".to_string(),
        NarrativeAction::Attacked,
        "Lucas attacked the mountain spirits".to_string(),
    );
    event3 = event3
        .add_actor(fixture.lucas_persona_id, ActorRole::Agent)
        .add_actor(fixture.mount_everest_location_id, ActorRole::Patient);
    let request3 = fixture.narrative_to_create_request(&event3);
    let created_event3 = fixture
        .chronicle_service
        .create_event(fixture.user_id, fixture.chronicle_id, request3, None)
        .await
        .expect("Third event should succeed");

    // DISCOVERED and ATTACKED are in different semantic groups, so this should NOT be deduplicated
    assert_ne!(
        created_event1.id, created_event3.id,
        "Semantically different actions (DISCOVERED/ATTACKED) should NOT be deduplicated"
    );

    println!("✓ Semantic action similarity working correctly");
}

/// Test cross-chronicle isolation
#[tokio::test]
async fn test_cross_chronicle_isolation() {
    let fixture = MountEverestTestFixture::new().await;
    let base_time = Utc::now();

    // Create second chronicle
    let chronicle2_request = CreateChronicleRequest {
        name: "Lucas's Second Chronicle".to_string(),
        description: Some("Separate chronicle for isolation testing".to_string()),
    };
    let chronicle2 = fixture
        .chronicle_service
        .create_chronicle(fixture.user_id, chronicle2_request)
        .await
        .expect("Failed to create second chronicle");

    // Create identical events in both chronicles
    let event1 = fixture.create_mount_everest_event(base_time);
    let request1 = fixture.narrative_to_create_request(&event1);
    
    // Create in first chronicle
    let created_event1 = fixture
        .chronicle_service
        .create_event(fixture.user_id, fixture.chronicle_id, request1.clone(), None)
        .await
        .expect("First chronicle event should succeed");

    // Create identical event in second chronicle
    let created_event2 = fixture
        .chronicle_service
        .create_event(fixture.user_id, chronicle2.id, request1, None)
        .await
        .expect("Second chronicle event should succeed");

    // Events in different chronicles should NOT be deduplicated
    assert_ne!(
        created_event1.id, created_event2.id,
        "Identical events in different chronicles should NOT be deduplicated"
    );

    println!("✓ Cross-chronicle isolation working correctly");
}

/// Test performance under load with many potential duplicates
#[tokio::test]
async fn test_deduplication_performance_under_load() {
    let fixture = MountEverestTestFixture::new().await;
    let base_time = Utc::now();

    // Create initial event
    let event1 = fixture.create_mount_everest_event(base_time);
    let request1 = fixture.narrative_to_create_request(&event1);
    let created_event1 = fixture
        .chronicle_service
        .create_event(fixture.user_id, fixture.chronicle_id, request1, None)
        .await
        .expect("Initial event should succeed");

    // Create 20 slightly different events rapidly (all should be deduplicated)
    let start_time = std::time::Instant::now();
    for i in 1..=20 {
        let variant_event = fixture.create_mount_everest_variant(
            base_time + Duration::seconds(i * 10), // 10 seconds apart
            &format!("Lucas performed cleansing ritual #{} at Mount Everest", i),
        );
        let variant_request = fixture.narrative_to_create_request(&variant_event);
        
        let created_event = fixture
            .chronicle_service
            .create_event(fixture.user_id, fixture.chronicle_id, variant_request, None)
            .await
            .expect(&format!("Event {} should be deduplicated", i));

        assert_eq!(
            created_event1.id, created_event.id,
            "Event {} should be deduplicated to original event", i
        );
    }
    let duration = start_time.elapsed();

    println!("✓ Processed 20 duplicate events in {:?} (avg: {:?} per event)", 
             duration, duration / 20);

    // Verify still only one event in database
    let events = fixture
        .chronicle_service
        .get_chronicle_events(fixture.user_id, fixture.chronicle_id, EventFilter::default())
        .await
        .expect("Failed to retrieve events");

    assert_eq!(events.len(), 1, "Should still have exactly 1 event after load test");

    // Performance should be reasonable (less than 1 second total for 20 events)
    assert!(duration.as_secs() < 1, "Deduplication should complete in under 1 second");
}

/// Test mixed modality scenarios
#[tokio::test]
async fn test_mixed_modality_deduplication() {
    let fixture = MountEverestTestFixture::new().await;
    let base_time = Utc::now();

    // Create ACTUAL event
    let event1 = fixture.create_mount_everest_event(base_time);
    let request1 = fixture.narrative_to_create_request(&event1);
    let created_event1 = fixture
        .chronicle_service
        .create_event(fixture.user_id, fixture.chronicle_id, request1, None)
        .await
        .expect("ACTUAL event should succeed");

    // Create HYPOTHETICAL event with same action and actors
    let mut event2 = fixture.create_mount_everest_event(base_time + Duration::minutes(2));
    event2 = event2.with_modality(EventModality::Hypothetical);
    let request2 = fixture.narrative_to_create_request(&event2);
    let created_event2 = fixture
        .chronicle_service
        .create_event(fixture.user_id, fixture.chronicle_id, request2, None)
        .await
        .expect("HYPOTHETICAL event should be deduplicated");

    // Hypothetical events should still be deduplicated if they have same action/actors
    assert_eq!(
        created_event1.id, created_event2.id,
        "HYPOTHETICAL event should be deduplicated with ACTUAL event"
    );

    // Create BELIEVED_BY event
    let mut event3 = fixture.create_mount_everest_event(base_time + Duration::minutes(3));
    event3 = event3.with_modality(EventModality::BelievedBy(Uuid::new_v4()));
    let request3 = fixture.narrative_to_create_request(&event3);
    let created_event3 = fixture
        .chronicle_service
        .create_event(fixture.user_id, fixture.chronicle_id, request3, None)
        .await
        .expect("BELIEVED_BY event should be deduplicated");

    assert_eq!(
        created_event1.id, created_event3.id,
        "BELIEVED_BY event should be deduplicated with ACTUAL event"
    );

    println!("✓ Mixed modality deduplication working correctly");
}

/// Test that genuinely different events are NOT deduplicated
#[tokio::test]
async fn test_different_events_not_deduplicated() {
    let fixture = MountEverestTestFixture::new().await;
    let base_time = Utc::now();

    // Create Mount Everest cleansing event
    let event1 = fixture.create_mount_everest_event(base_time);
    let request1 = fixture.narrative_to_create_request(&event1);
    let created_event1 = fixture
        .chronicle_service
        .create_event(fixture.user_id, fixture.chronicle_id, request1, None)
        .await
        .expect("Cleansing event should succeed");

    // Create different meditation event at same location
    let event2 = fixture.create_different_event(base_time + Duration::minutes(2));
    let request2 = fixture.narrative_to_create_request(&event2);
    let created_event2 = fixture
        .chronicle_service
        .create_event(fixture.user_id, fixture.chronicle_id, request2, None)
        .await
        .expect("Meditation event should succeed");

    // Different actions should NOT be deduplicated
    assert_ne!(
        created_event1.id, created_event2.id,
        "Different events (CLEANSED vs MEDITATED) should NOT be deduplicated"
    );

    // Verify we have 2 events
    let events = fixture
        .chronicle_service
        .get_chronicle_events(fixture.user_id, fixture.chronicle_id, EventFilter::default())
        .await
        .expect("Failed to retrieve events");

    assert_eq!(events.len(), 2, "Should have exactly 2 different events");
    println!("✓ Different events correctly NOT deduplicated");
}

/// Test direct deduplication service functionality
#[tokio::test]
async fn test_deduplication_service_direct() {
    let fixture = MountEverestTestFixture::new().await;
    let base_time = Utc::now();

    // Create first event manually in database
    let event1 = fixture.create_mount_everest_event(base_time);
    let request1 = fixture.narrative_to_create_request(&event1);
    let created_event1 = fixture
        .chronicle_service
        .create_event(fixture.user_id, fixture.chronicle_id, request1, None)
        .await
        .expect("First event should succeed");

    // Test deduplication service directly
    let mut temp_event = created_event1.clone();
    temp_event.id = Uuid::new_v4(); // Different ID
    temp_event.timestamp_iso8601 = base_time + Duration::minutes(2); // 2 minutes later

    let duplicate_result = fixture
        .dedup_service
        .check_for_duplicates(&temp_event)
        .await
        .expect("Deduplication check should succeed");

    assert!(duplicate_result.is_duplicate, "Should detect as duplicate");
    assert_eq!(
        duplicate_result.duplicate_event_id,
        Some(created_event1.id),
        "Should identify correct duplicate event"
    );
    assert!(
        duplicate_result.confidence >= 0.7,
        "Confidence should be high: {}",
        duplicate_result.confidence
    );

    println!("✓ Direct deduplication service working correctly");
    println!("  Confidence: {:.3}", duplicate_result.confidence);
    println!("  Reasoning: {}", duplicate_result.reasoning);
}

/// Comprehensive end-to-end stress test
#[tokio::test]
async fn test_comprehensive_deduplication_stress_test() {
    let fixture = MountEverestTestFixture::new().await;
    let base_time = Utc::now();

    println!("🔥 Starting comprehensive deduplication stress test...");

    // Test scenario: Multiple users, multiple chronicles, various event types
    let user2 = create_user_in_db(
        &fixture._db_pool,
        &format!("test-user-{}", Uuid::new_v4()),
        "password123",
        &format!("test-user-{}@example.com", Uuid::new_v4()),
        None,
    )
    .await
    .expect("Failed to create test user 2");
    let user2_id = user2.id;

    let chronicle2_request = CreateChronicleRequest {
        name: "User2's Chronicle".to_string(),
        description: Some("Second user's chronicle".to_string()),
    };
    let chronicle2 = fixture
        .chronicle_service
        .create_chronicle(user2_id, chronicle2_request)
        .await
        .expect("Failed to create second user's chronicle");

    // Test 1: Same user, same chronicle - should deduplicate
    let event1 = fixture.create_mount_everest_event(base_time);
    let request1 = fixture.narrative_to_create_request(&event1);
    let created1a = fixture
        .chronicle_service
        .create_event(fixture.user_id, fixture.chronicle_id, request1.clone(), None)
        .await
        .expect("Event 1a should succeed");

    let created1b = fixture
        .chronicle_service
        .create_event(fixture.user_id, fixture.chronicle_id, request1, None)
        .await
        .expect("Event 1b should be deduplicated");

    assert_eq!(created1a.id, created1b.id, "Same user/chronicle should deduplicate");

    // Test 2: Different user, same event - should NOT deduplicate
    let event2 = fixture.create_mount_everest_event(base_time);
    let request2 = fixture.narrative_to_create_request(&event2);
    let created2 = fixture
        .chronicle_service
        .create_event(user2_id, chronicle2.id, request2, None)
        .await
        .expect("Event 2 should succeed");

    assert_ne!(created1a.id, created2.id, "Different users should NOT deduplicate");

    // Test 3: Rapid-fire identical events (should all deduplicate to first)
    let mut duplicate_ids = Vec::new();
    for i in 0..10 {
        let event = fixture.create_mount_everest_variant(
            base_time + Duration::seconds(i * 5),
            &format!("Rapid event variant {}", i),
        );
        let request = fixture.narrative_to_create_request(&event);
        let created = fixture
            .chronicle_service
            .create_event(fixture.user_id, fixture.chronicle_id, request, None)
            .await
            .expect(&format!("Rapid event {} should be processed", i));
        
        duplicate_ids.push(created.id);
    }

    // All rapid events should have the same ID as the first event
    for (i, &id) in duplicate_ids.iter().enumerate() {
        assert_eq!(
            id, created1a.id,
            "Rapid event {} should be deduplicated to original", i
        );
    }

    // Final verification: Count total events
    let events1 = fixture
        .chronicle_service
        .get_chronicle_events(fixture.user_id, fixture.chronicle_id, EventFilter::default())
        .await
        .expect("Failed to get user1 events");

    let events2 = fixture
        .chronicle_service
        .get_chronicle_events(user2_id, chronicle2.id, EventFilter::default())
        .await
        .expect("Failed to get user2 events");

    assert_eq!(events1.len(), 1, "User1 should have exactly 1 event");
    assert_eq!(events2.len(), 1, "User2 should have exactly 1 event");

    println!("✅ Comprehensive stress test PASSED");
    println!("  User1 events: {}", events1.len());
    println!("  User2 events: {}", events2.len());
    println!("  Total duplicate detections: {}", duplicate_ids.len());
}