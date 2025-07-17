use anyhow::Result;
use uuid::Uuid;
use serde_json::json;
use scribe_backend::test_helpers::{spawn_app, TestDataGuard, create_test_chronicle_event};
use scribe_backend::services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryService};
use chrono::{DateTime, Utc, Duration};

#[tokio::test]
async fn test_item_ownership_timeline_tracking() -> Result<()> {
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
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
    ).await;
    
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
    ).await;
    
    let service = HybridQueryService::new(
        app.chronicle_service.clone(),
        app.ecs_manager.clone(),
        app.nlp_service.clone(),
        app.token_counter.clone(),
        app.enhanced_rag_service.clone(),
        app.llm_clients.clone(),
        app.lorebook_service.clone(),
    );
    
    // Query for item ownership timeline
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemTimeline,
        query_text: "Ancient Sword ownership history".to_string(),
        entity_names: vec![], // Item query
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
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
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
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
    ).await;
    
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
    ).await;
    
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
    ).await;
    
    let service = HybridQueryService::new(
        app.chronicle_service.clone(),
        app.ecs_manager.clone(),
        app.nlp_service.clone(),
        app.token_counter.clone(),
        app.enhanced_rag_service.clone(),
        app.llm_clients.clone(),
        app.lorebook_service.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemUsage,
        query_text: "Healing Potion usage pattern".to_string(),
        entity_names: vec![],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
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
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
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
    ).await;
    
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
    ).await;
    
    let service = HybridQueryService::new(
        app.chronicle_service.clone(),
        app.ecs_manager.clone(),
        app.nlp_service.clone(),
        app.token_counter.clone(),
        app.enhanced_rag_service.clone(),
        app.llm_clients.clone(),
        app.lorebook_service.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemLocation,
        query_text: "Where has the Crystal of Power been?".to_string(),
        entity_names: vec![],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
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
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
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
    ).await;
    
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
    ).await;
    
    let service = HybridQueryService::new(
        app.chronicle_service.clone(),
        app.ecs_manager.clone(),
        app.nlp_service.clone(),
        app.token_counter.clone(),
        app.enhanced_rag_service.clone(),
        app.llm_clients.clone(),
        app.lorebook_service.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemLifecycle,
        query_text: "Star Metal Blade lifecycle".to_string(),
        entity_names: vec![],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
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
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
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
    ).await;
    
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
    ).await;
    
    let service = HybridQueryService::new(
        app.chronicle_service.clone(),
        app.ecs_manager.clone(),
        app.nlp_service.clone(),
        app.token_counter.clone(),
        app.enhanced_rag_service.clone(),
        app.llm_clients.clone(),
        app.lorebook_service.clone(),
    );
    
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemInteractions,
        query_text: "Who has interacted with the Ancient Tome?".to_string(),
        entity_names: vec![],
        time_range: None,
        include_relationships: true,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
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
    let app = spawn_app().await;
    let _guard = TestDataGuard::new(&app.db_pool);
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    
    // Create multiple items with different properties
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
        ).await;
    }
    
    let service = HybridQueryService::new(
        app.chronicle_service.clone(),
        app.ecs_manager.clone(),
        app.nlp_service.clone(),
        app.token_counter.clone(),
        app.enhanced_rag_service.clone(),
        app.llm_clients.clone(),
        app.lorebook_service.clone(),
    );
    
    // Query for specific item properties
    let query = HybridQuery {
        user_id,
        chronicle_id: Some(chronicle_id),
        query_type: HybridQueryType::ItemSearch,
        query_text: "Find all legendary weapons".to_string(),
        entity_names: vec![],
        time_range: None,
        include_relationships: false,
        include_current_state: true,
        min_relevance_score: 0.5,
        max_results: 10,
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