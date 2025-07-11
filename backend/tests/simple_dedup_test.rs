//! Simple Chronicle Event Deduplication Test

use uuid::Uuid;
use serde_json;

use scribe_backend::{
    models::{
        chronicle::{CreateChronicleRequest},
        chronicle_event::{CreateEventRequest, EventSource},
    },
    services::ChronicleService,
    test_helpers,
};

#[tokio::test]
async fn test_simple_deduplication() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
    
    // Create a test user first
    let user = test_helpers::db::create_test_user(&test_app.db_pool, "dedup_test_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    
    // Create a chronicle
    let chronicle_request = CreateChronicleRequest {
        name: "Test Chronicle".to_string(),
        description: Some("Test chronicle for deduplication".to_string()),
    };
    
    let chronicle = chronicle_service
        .create_chronicle(user_id, chronicle_request)
        .await
        .expect("Failed to create chronicle");
    
    // Create first event with proper Ars Fabula data
    let lucas_id = Uuid::new_v4();
    let location_id = Uuid::new_v4();
    
    let event_data = serde_json::json!({
        "actors": [
            {"entity_id": lucas_id, "role": "AGENT"},
            {"entity_id": location_id, "role": "PATIENT"}
        ],
        "action": "CLEANSED",
        "modality": "ACTUAL"
    });
    
    let event_request = CreateEventRequest {
        event_type: "SPIRITUAL.CLEANSING.LOCATION".to_string(),
        summary: "Lucas performed a cleansing ritual".to_string(),
        source: EventSource::AiExtracted,
        event_data: Some(event_data),
        timestamp_iso8601: Some(chrono::Utc::now()),
    };
    
    let first_event = chronicle_service
        .create_event(user_id, chronicle.id, event_request.clone(), None)
        .await
        .expect("Failed to create first event");
    
    println!("✓ Created first event: {}", first_event.id);
    
    // Try to create the same event again
    let second_event = chronicle_service
        .create_event(user_id, chronicle.id, event_request, None)
        .await
        .expect("Failed to create second event");
    
    println!("✓ Created second event: {}", second_event.id);
    
    // Check if deduplication occurred by comparing IDs
    if first_event.id == second_event.id {
        println!("✅ DEDUPLICATION WORKING: Both events have same ID");
    } else {
        println!("❌ DEDUPLICATION FAILED: Events have different IDs");
        println!("   First event ID:  {}", first_event.id);
        println!("   Second event ID: {}", second_event.id);
    }
    
    assert_eq!(first_event.id, second_event.id, "Events should be deduplicated");
}