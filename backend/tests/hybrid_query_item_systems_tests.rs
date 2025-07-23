use anyhow::Result;
use std::sync::Arc;
use uuid::Uuid;
use serde_json::json;
use chrono::Utc;
use scribe_backend::test_helpers::{spawn_app, TestDataGuard, db::create_test_user};
use scribe_backend::services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryService};
use scribe_backend::models::chronicle_event::{NewChronicleEvent, EventSource};
use scribe_backend::models::chronicle::CreateChronicleRequest;
use scribe_backend::services::chronicle_service::ChronicleService;
use diesel::prelude::*;
use scribe_backend::schema::chronicle_events;

// Helper function to create test NewChronicleEvent objects
fn create_test_chronicle_event(
    chronicle_id: Uuid,
    user_id: Uuid,
    event_type: &str,
    event_data: serde_json::Value,
) -> NewChronicleEvent {
    let now = Utc::now();
    NewChronicleEvent {
        chronicle_id,
        user_id,
        event_type: event_type.to_string(),
        summary: "Test event".to_string(),
        source: EventSource::UserAdded.to_string(),
        event_data: Some(event_data),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: now,
        actors: None,
        action: None,
        context_data: None,
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: None,
        causes_event_ids: None,
        sequence_number: 1,
    }
}

#[tokio::test]
async fn test_item_ownership_timeline_tracking() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&app.db_pool, "test@example.com".to_string(), "testuser".to_string()).await?;
    let user_id = user.id;
    
    // Create chronicle
    let chronicle_service = ChronicleService::new(app.db_pool.clone());
    let chronicle = chronicle_service.create_chronicle(
        user_id,
        CreateChronicleRequest {
            name: "Test Chronicle".to_string(),
            description: Some("Test chronicle for item systems".to_string()),
        },
    ).await?;
    let chronicle_id = chronicle.id;
    
    let sword_id = Uuid::new_v4();
    let alice_id = Uuid::new_v4();
    let bob_id = Uuid::new_v4();
    
    // Event 1: Alice finds the sword
    let event1 = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Item Discovery",
        json!({
            "content": "Alice discovered an ancient sword in the ruins",
            "actors": [{
                "entity_id": alice_id.to_string(),
                "context": "Alice"
            }],
            "items": [{
                "item_id": sword_id.to_string(),
                "name": "Ancient Sword",
                "action": "discovered",
                "owner": alice_id.to_string()
            }]
        })
    );
    
    // Event 2: Alice gives sword to Bob
    let event2 = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Item Transfer",
        json!({
            "content": "Alice gave the ancient sword to Bob for his quest",
            "actors": [
                {
                    "entity_id": alice_id.to_string(),
                    "context": "Alice"
                },
                {
                    "entity_id": bob_id.to_string(),
                    "context": "Bob"
                }
            ],
            "items": [{
                "item_id": sword_id.to_string(),
                "name": "Ancient Sword",
                "action": "transferred",
                "from_owner": alice_id.to_string(),
                "to_owner": bob_id.to_string()
            }]
        })
    );
    
    // Insert events into database
    let conn = app.db_pool.get().await?;
    conn.interact(move |conn| -> Result<(), diesel::result::Error> {
        diesel::insert_into(chronicle_events::table)
            .values(&vec![event1, event2])
            .execute(conn)?;
        Ok(())
    }).await??;
    
    let service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(),
        app.app_state.feature_flags.clone(),
        app.ai_client.clone(),
        app.config.advanced_model.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.ecs_enhanced_rag_service.clone(),
        app.app_state.ecs_graceful_degradation.clone(),
    );
    
    // Query for item ownership timeline
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemTimeline,
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: Default::default(),
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // TODO: Verify ownership timeline once implemented
    // assert_eq!(result.item_timelines.len(), 1);
    // let sword_timeline = &result.item_timelines[0];
    // assert_eq!(sword_timeline.item_id, sword_id);
    // assert_eq!(sword_timeline.ownership_history.len(), 2);
    // assert_eq!(sword_timeline.current_owner, Some(bob_id));
    
    Ok(())
}

#[tokio::test]
async fn test_item_usage_pattern_tracking() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&app.db_pool, "test2@example.com".to_string(), "testuser2".to_string()).await?;
    let user_id = user.id;
    
    // Create chronicle
    let chronicle_service = ChronicleService::new(app.db_pool.clone());
    let chronicle = chronicle_service.create_chronicle(
        user_id,
        CreateChronicleRequest {
            name: "Test Chronicle 2".to_string(),
            description: Some("Test chronicle for item usage".to_string()),
        },
    ).await?;
    let chronicle_id = chronicle.id;
    
    let potion_id = Uuid::new_v4();
    let character_id = Uuid::new_v4();
    
    // Multiple events showing item usage
    let event1 = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Item Usage",
        json!({
            "content": "Elena sipped the healing potion, feeling its warmth",
            "actors": [{
                "entity_id": character_id.to_string(),
                "context": "Elena"
            }],
            "items": [{
                "item_id": potion_id.to_string(),
                "name": "Healing Potion",
                "action": "used",
                "usage_type": "partial",
                "remaining": "75%"
            }]
        })
    );
    
    let event2 = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Item Usage",
        json!({
            "content": "Elena drank more of the healing potion during battle",
            "actors": [{
                "entity_id": character_id.to_string(),
                "context": "Elena"
            }],
            "items": [{
                "item_id": potion_id.to_string(),
                "name": "Healing Potion",
                "action": "used",
                "usage_type": "partial",
                "remaining": "25%",
                "context": "during_combat"
            }]
        })
    );
    
    let event3 = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Item Depletion",
        json!({
            "content": "Elena finished the last of the healing potion",
            "actors": [{
                "entity_id": character_id.to_string(),
                "context": "Elena"
            }],
            "items": [{
                "item_id": potion_id.to_string(),
                "name": "Healing Potion",
                "action": "depleted",
                "usage_type": "complete",
                "remaining": "0%"
            }]
        })
    );
    
    // Insert events into database
    let conn = app.db_pool.get().await?;
    conn.interact(move |conn| -> Result<(), diesel::result::Error> {
        diesel::insert_into(chronicle_events::table)
            .values(&vec![event1, event2, event3])
            .execute(conn)?;
        Ok(())
    }).await??;
    
    let service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(),
        app.app_state.feature_flags.clone(),
        app.ai_client.clone(),
        app.config.advanced_model.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.ecs_enhanced_rag_service.clone(),
        app.app_state.ecs_graceful_degradation.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemUsage,
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: Default::default(),
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // TODO: Verify usage patterns once implemented
    // assert!(result.item_usage_patterns.contains_key(&potion_id));
    // let usage_pattern = &result.item_usage_patterns[&potion_id];
    // assert_eq!(usage_pattern.total_uses, 3);
    // assert_eq!(usage_pattern.depletion_rate, Some("25% per use"));
    
    Ok(())
}

#[tokio::test]
async fn test_item_location_tracking() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&app.db_pool, "test3@example.com".to_string(), "testuser3".to_string()).await?;
    let user_id = user.id;
    
    // Create chronicle
    let chronicle_service = ChronicleService::new(app.db_pool.clone());
    let chronicle = chronicle_service.create_chronicle(
        user_id,
        CreateChronicleRequest {
            name: "Test Chronicle 3".to_string(),
            description: Some("Test chronicle for item location".to_string()),
        },
    ).await?;
    let chronicle_id = chronicle.id;
    
    let artifact_id = Uuid::new_v4();
    let location1_id = Uuid::new_v4();
    let location2_id = Uuid::new_v4();
    
    // Track item movement through locations
    let event1 = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Item Placement",
        json!({
            "content": "The Crystal of Power was placed in the Temple vault",
            "actors": [],
            "items": [{
                "item_id": artifact_id.to_string(),
                "name": "Crystal of Power",
                "action": "placed",
                "location": {
                    "location_id": location1_id.to_string(),
                    "name": "Temple Vault"
                }
            }]
        })
    );
    
    let event2 = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Item Movement",
        json!({
            "content": "The Crystal of Power was moved to the Royal Treasury",
            "actors": [],
            "items": [{
                "item_id": artifact_id.to_string(),
                "name": "Crystal of Power",
                "action": "moved",
                "from_location": {
                    "location_id": location1_id.to_string(),
                    "name": "Temple Vault"
                },
                "to_location": {
                    "location_id": location2_id.to_string(),
                    "name": "Royal Treasury"
                }
            }]
        })
    );
    
    // Insert events into database
    let conn = app.db_pool.get().await?;
    conn.interact(move |conn| -> Result<(), diesel::result::Error> {
        diesel::insert_into(chronicle_events::table)
            .values(&vec![event1, event2])
            .execute(conn)?;
        Ok(())
    }).await??;
    
    let service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(),
        app.app_state.feature_flags.clone(),
        app.ai_client.clone(),
        app.config.advanced_model.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.ecs_enhanced_rag_service.clone(),
        app.app_state.ecs_graceful_degradation.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemLocation,
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: Default::default(),
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // TODO: Verify location tracking once implemented
    // assert!(result.item_locations.contains_key(&artifact_id));
    // let location_history = &result.item_locations[&artifact_id];
    // assert_eq!(location_history.len(), 2);
    
    Ok(())
}

#[tokio::test]
async fn test_item_creation_and_destruction() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&app.db_pool, "test4@example.com".to_string(), "testuser4".to_string()).await?;
    let user_id = user.id;
    
    // Create chronicle
    let chronicle_service = ChronicleService::new(app.db_pool.clone());
    let chronicle = chronicle_service.create_chronicle(
        user_id,
        CreateChronicleRequest {
            name: "Test Chronicle 4".to_string(),
            description: Some("Test chronicle for item creation/destruction".to_string()),
        },
    ).await?;
    let chronicle_id = chronicle.id;
    
    let item_id = Uuid::new_v4();
    let creator_id = Uuid::new_v4();
    
    // Item creation event
    let event1 = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Item Creation",
        json!({
            "content": "The blacksmith forged a new blade from star metal",
            "actors": [{
                "entity_id": creator_id.to_string(),
                "context": "Master Blacksmith"
            }],
            "items": [{
                "item_id": item_id.to_string(),
                "name": "Star Metal Blade",
                "action": "created",
                "creator": creator_id.to_string(),
                "materials": ["star metal", "dragon bone"],
                "properties": {
                    "quality": "legendary",
                    "durability": "unbreaking"
                }
            }]
        })
    );
    
    // Item destruction event
    let event2 = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Item Destruction",
        json!({
            "content": "The Star Metal Blade shattered against the demon's hide",
            "actors": [],
            "items": [{
                "item_id": item_id.to_string(),
                "name": "Star Metal Blade",
                "action": "destroyed",
                "destruction_cause": "combat",
                "fragments": ["star metal shards", "broken hilt"]
            }]
        })
    );
    
    // Insert events into database
    let conn = app.db_pool.get().await?;
    conn.interact(move |conn| -> Result<(), diesel::result::Error> {
        diesel::insert_into(chronicle_events::table)
            .values(&vec![event1, event2])
            .execute(conn)?;
        Ok(())
    }).await??;
    
    let service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(),
        app.app_state.feature_flags.clone(),
        app.ai_client.clone(),
        app.config.advanced_model.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.ecs_enhanced_rag_service.clone(),
        app.app_state.ecs_graceful_degradation.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemLifecycle,
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: Default::default(),
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // TODO: Verify lifecycle tracking once implemented
    // assert!(result.item_lifecycles.contains_key(&item_id));
    // let lifecycle = &result.item_lifecycles[&item_id];
    // assert_eq!(lifecycle.status, "destroyed");
    
    Ok(())
}

#[tokio::test]
async fn test_item_interaction_with_entities() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&app.db_pool, "test5@example.com".to_string(), "testuser5".to_string()).await?;
    let user_id = user.id;
    
    // Create chronicle
    let chronicle_service = ChronicleService::new(app.db_pool.clone());
    let chronicle = chronicle_service.create_chronicle(
        user_id,
        CreateChronicleRequest {
            name: "Test Chronicle 5".to_string(),
            description: Some("Test chronicle for item interactions".to_string()),
        },
    ).await?;
    let chronicle_id = chronicle.id;
    
    let book_id = Uuid::new_v4();
    let reader1_id = Uuid::new_v4();
    let reader2_id = Uuid::new_v4();
    
    // Multiple entities interact with same item
    let event1 = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Item Interaction",
        json!({
            "content": "Sarah studied the ancient tome, learning its secrets",
            "actors": [{
                "entity_id": reader1_id.to_string(),
                "context": "Sarah"
            }],
            "items": [{
                "item_id": book_id.to_string(),
                "name": "Ancient Tome",
                "action": "read",
                "interaction_type": "study",
                "effect": "gained_knowledge"
            }]
        })
    );
    
    let event2 = create_test_chronicle_event(
        chronicle_id,
        user_id,
        "Item Interaction",
        json!({
            "content": "Marcus borrowed the ancient tome from Sarah",
            "actors": [
                {
                    "entity_id": reader2_id.to_string(),
                    "context": "Marcus"
                },
                {
                    "entity_id": reader1_id.to_string(),
                    "context": "Sarah"
                }
            ],
            "items": [{
                "item_id": book_id.to_string(),
                "name": "Ancient Tome",
                "action": "borrowed",
                "from": reader1_id.to_string(),
                "to": reader2_id.to_string()
            }]
        })
    );
    
    // Insert events into database
    let conn = app.db_pool.get().await?;
    conn.interact(move |conn| -> Result<(), diesel::result::Error> {
        diesel::insert_into(chronicle_events::table)
            .values(&vec![event1, event2])
            .execute(conn)?;
        Ok(())
    }).await??;
    
    let service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(),
        app.app_state.feature_flags.clone(),
        app.ai_client.clone(),
        app.config.advanced_model.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.ecs_enhanced_rag_service.clone(),
        app.app_state.ecs_graceful_degradation.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemInteractions,
        max_results: 10,
        include_current_state: true,
        include_relationships: true,
        options: Default::default(),
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // TODO: Verify entity interactions once implemented
    // assert!(result.item_interactions.contains_key(&book_id));
    // let interactions = &result.item_interactions[&book_id];
    // assert_eq!(interactions.interacting_entities.len(), 2);
    
    Ok(())
}

#[tokio::test]
async fn test_complex_item_query_with_filters() -> Result<()> {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&app.db_pool, "test6@example.com".to_string(), "testuser6".to_string()).await?;
    let user_id = user.id;
    
    // Create chronicle
    let chronicle_service = ChronicleService::new(app.db_pool.clone());
    let chronicle = chronicle_service.create_chronicle(
        user_id,
        CreateChronicleRequest {
            name: "Test Chronicle 6".to_string(),
            description: Some("Test chronicle for complex queries".to_string()),
        },
    ).await?;
    let chronicle_id = chronicle.id;
    
    // Create multiple items with different properties
    let mut events = Vec::new();
    for i in 0..5 {
        let item_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        
        let rarity = match i % 3 {
            0 => "common",
            1 => "rare",
            _ => "legendary",
        };
        
        let event = create_test_chronicle_event(
            chronicle_id,
            user_id,
            "Item Discovery",
            json!({
                "content": format!("A {} item was found", rarity),
                "actors": [{
                    "entity_id": owner_id.to_string(),
                    "context": format!("Adventurer {}", i)
                }],
                "items": [{
                    "item_id": item_id.to_string(),
                    "name": format!("Item {}", i),
                    "action": "discovered",
                    "owner": owner_id.to_string(),
                    "properties": {
                        "rarity": rarity,
                        "value": i * 100,
                        "type": if i % 2 == 0 { "weapon" } else { "armor" }
                    }
                }]
            })
        );
        events.push(event);
    }
    
    // Insert events into database
    let conn = app.db_pool.get().await?;
    conn.interact(move |conn| -> Result<(), diesel::result::Error> {
        diesel::insert_into(chronicle_events::table)
            .values(&events)
            .execute(conn)?;
        Ok(())
    }).await??;
    
    let service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(),
        app.app_state.feature_flags.clone(),
        app.ai_client.clone(),
        app.config.advanced_model.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.ecs_enhanced_rag_service.clone(),
        app.app_state.ecs_graceful_degradation.clone(),
    );
    
    // Query for specific item properties
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemSearch,
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: Default::default(),
    };
    
    let result = service.execute_hybrid_query(query).await?;
    
    // TODO: Verify filtered results once implemented
    // assert!(result.items.len() > 0);
    // for item in &result.items {
    //     assert_eq!(item.properties["rarity"], "legendary");
    //     assert_eq!(item.properties["type"], "weapon");
    // }
    
    Ok(())
}