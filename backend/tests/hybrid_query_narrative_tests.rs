mod helpers;

use helpers::hybrid_query_test_helpers::{HybridQueryTestContext, create_test_scenario};
use scribe_backend::services::hybrid_query_service::{
    HybridQuery, HybridQueryType, HybridQueryOptions,
};
use serde_json::json;

#[tokio::test]
async fn test_query_summary_includes_narrative_answer() {
    let (ctx, scenario) = create_test_scenario().await.unwrap();
    
    // Test Entity Timeline Query with chronicle
    let timeline_query = HybridQuery {
        query_type: HybridQueryType::EntityTimeline {
            entity_name: "Alice".to_string(),
            entity_id: Some(scenario.alice.entity.id),
            include_current_state: true,
        },
        user_id: ctx.user_id,
        chronicle_id: ctx.chronicle.as_ref().map(|c| c.id),
        max_results: 20,
        include_current_state: true,
        include_relationships: true,
        options: HybridQueryOptions::default(),
    };
    
    let result = ctx.service.execute_hybrid_query(timeline_query).await.unwrap();
    
    // Verify narrative answer is present in the summary
    assert!(result.summary.narrative_answer.is_some(), "Narrative answer should be generated");
    let narrative = result.summary.narrative_answer.unwrap();
    assert!(narrative.contains("Alice"), "Narrative should mention Alice");
    
    // Test Relationship History Query
    let relationship_query = HybridQuery {
        query_type: HybridQueryType::RelationshipHistory {
            entity_a: "Alice".to_string(),
            entity_b: "Bob".to_string(),
            entity_a_id: Some(scenario.alice.entity.id),
            entity_b_id: Some(scenario.bob.entity.id),
        },
        user_id: ctx.user_id,
        chronicle_id: ctx.chronicle.as_ref().map(|c| c.id),
        max_results: 20,
        include_current_state: true,
        include_relationships: true,
        options: HybridQueryOptions::default(),
    };
    
    let result = ctx.service.execute_hybrid_query(relationship_query).await.unwrap();
    
    assert!(result.summary.narrative_answer.is_some(), "Narrative answer should be generated for relationship query");
    let narrative = result.summary.narrative_answer.unwrap();
    assert!(narrative.contains("Alice") || narrative.contains("Bob"), "Narrative should mention entities");
}

#[tokio::test]
async fn test_narrative_for_empty_results() {
    let ctx = HybridQueryTestContext::new(false).await.unwrap();
    
    // Query for non-existent entity (no chronicle, so no events)
    let query = HybridQuery {
        query_type: HybridQueryType::NarrativeQuery {
            query_text: "Find all dragons in the kingdom".to_string(),
            focus_entities: None,
            time_range: None,
        },
        user_id: ctx.user_id,
        chronicle_id: None,
        max_results: 20,
        include_current_state: true,
        include_relationships: true,
        options: HybridQueryOptions::default(),
    };
    
    let result = ctx.service.execute_hybrid_query(query).await.unwrap();
    
    assert!(result.summary.narrative_answer.is_some(), "Should have narrative even for empty results");
    let narrative = result.summary.narrative_answer.unwrap();
    assert!(
        narrative.contains("No relevant information found") || 
        narrative.contains("no") || 
        narrative.contains("found"),
        "Narrative should indicate no results found"
    );
}

#[tokio::test]
async fn test_narrative_for_location_query() {
    let (ctx, scenario) = create_test_scenario().await.unwrap();
    
    // Create location query
    let query = HybridQuery {
        query_type: HybridQueryType::LocationQuery {
            location_name: "The Rusty Anchor Tavern".to_string(),
            location_data: Some(json!({
                "location_type": "tavern"
            })),
            include_recent_activity: true,
        },
        user_id: ctx.user_id,
        chronicle_id: ctx.chronicle.as_ref().map(|c| c.id),
        max_results: 20,
        include_current_state: true,
        include_relationships: true,
        options: HybridQueryOptions::default(),
    };
    
    let result = ctx.service.execute_hybrid_query(query).await.unwrap();
    
    assert!(result.summary.narrative_answer.is_some(), "Should have narrative for location query");
    let narrative = result.summary.narrative_answer.unwrap();
    assert!(
        narrative.contains("Rusty Anchor") || narrative.contains("Activity") || narrative.contains("location"), 
        "Narrative should mention the location"
    );
}

#[tokio::test]
async fn test_narrative_for_world_model_snapshot() {
    let (ctx, scenario) = create_test_scenario().await.unwrap();
    
    // Create world snapshot query
    let query = HybridQuery {
        query_type: HybridQueryType::WorldModelSnapshot {
            timestamp: None,
            focus_entities: None,
            spatial_scope: None,
            include_predictions: false,
        },
        user_id: ctx.user_id,
        chronicle_id: ctx.chronicle.as_ref().map(|c| c.id),
        max_results: 50,
        include_current_state: true,
        include_relationships: true,
        options: HybridQueryOptions::default(),
    };
    
    let result = ctx.service.execute_hybrid_query(query).await.unwrap();
    
    assert!(result.summary.narrative_answer.is_some(), "Should have narrative for world snapshot");
    let narrative = result.summary.narrative_answer.unwrap();
    assert!(
        narrative.contains("World Model") || narrative.contains("Snapshot") || narrative.contains("entities"), 
        "Narrative should describe world state"
    );
}

#[tokio::test]
async fn test_narrative_includes_key_insights() {
    let (ctx, scenario) = create_test_scenario().await.unwrap();
    
    let query = HybridQuery {
        query_type: HybridQueryType::EntityTimeline {
            entity_name: "Merchant".to_string(),
            entity_id: Some(scenario.merchant.entity.id),
            include_current_state: true,
        },
        user_id: ctx.user_id,
        chronicle_id: ctx.chronicle.as_ref().map(|c| c.id),
        max_results: 20,
        include_current_state: true,
        include_relationships: true,
        options: HybridQueryOptions::default(),
    };
    
    let result = ctx.service.execute_hybrid_query(query).await.unwrap();
    
    // Should have both key insights and narrative
    assert!(!result.summary.key_insights.is_empty(), "Should generate key insights");
    assert!(result.summary.narrative_answer.is_some(), "Should generate narrative answer");
}

#[tokio::test]
async fn test_narrative_with_chronicle_events() {
    let (ctx, scenario) = create_test_scenario().await.unwrap();
    
    // Query for events involving Alice - should find the social interaction and trade events
    let query = HybridQuery {
        query_type: HybridQueryType::EntityTimeline {
            entity_name: "Alice".to_string(),
            entity_id: Some(scenario.alice.entity.id),
            include_current_state: true,
        },
        user_id: ctx.user_id,
        chronicle_id: ctx.chronicle.as_ref().map(|c| c.id),
        max_results: 20,
        include_current_state: true,
        include_relationships: true,
        options: HybridQueryOptions::default(),
    };
    
    let result = ctx.service.execute_hybrid_query(query).await.unwrap();
    
    // Should have found chronicle events
    assert!(!result.chronicle_events.is_empty(), "Should find chronicle events for Alice");
    assert!(result.summary.events_analyzed > 0, "Should have analyzed some events");
    
    // Narrative should mention the events
    assert!(result.summary.narrative_answer.is_some(), "Should have narrative answer");
    let narrative = result.summary.narrative_answer.unwrap();
    println!("Generated narrative: {}", narrative);
    assert!(
        narrative.contains("Alice") || narrative.contains("Timeline"),
        "Narrative should mention Alice: {}", narrative
    );
}

#[tokio::test]
async fn test_narrative_for_causal_chain() {
    let (ctx, scenario) = create_test_scenario().await.unwrap();
    
    // Create a causal chain query
    let query = HybridQuery {
        query_type: HybridQueryType::CausalChain {
            from_event: None, // Would need actual event ID
            to_state: Some("friendship established".to_string()),
            to_entity: Some(scenario.alice.entity.id),
            max_depth: 5,
            min_confidence: 0.6,
        },
        user_id: ctx.user_id,
        chronicle_id: ctx.chronicle.as_ref().map(|c| c.id),
        max_results: 20,
        include_current_state: true,
        include_relationships: true,
        options: HybridQueryOptions::default(),
    };
    
    let result = ctx.service.execute_hybrid_query(query).await.unwrap();
    
    assert!(result.summary.narrative_answer.is_some(), "Should have narrative for causal chain");
    let narrative = result.summary.narrative_answer.unwrap();
    assert!(
        narrative.contains("causal") || narrative.contains("chain") || narrative.contains("connection"),
        "Narrative should describe causal relationships"
    );
}