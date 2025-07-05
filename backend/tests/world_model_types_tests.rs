// World Model Types Tests
//
// Tests for Phase 2: World Model Types and Data Structures
// - WorldModelSnapshot creation and manipulation
// - EntitySnapshot state management
// - RelationshipSnapshot handling
// - CausalEventSnapshot processing
// - LLMWorldContext generation
// - OWASP security compliance

use std::collections::HashMap;
use uuid::Uuid;
use serde_json::json;
use chrono::{Utc, Duration};

use scribe_backend::{
    test_helpers::{spawn_app, TestDataGuard, db::create_test_user},
    models::world_model::*,
    errors::AppError,
};

#[tokio::test]
async fn test_world_model_snapshot_creation() {
    let user_id = Uuid::new_v4();
    let chronicle_id = Some(Uuid::new_v4());
    
    let snapshot = WorldModelSnapshot::new(user_id, chronicle_id);
    
    // Verify basic structure
    assert_eq!(snapshot.user_id, user_id);
    assert_eq!(snapshot.chronicle_id, chronicle_id);
    assert_eq!(snapshot.entity_count(), 0);
    assert_eq!(snapshot.relationship_count(), 0);
    assert_eq!(snapshot.event_count(), 0);
    assert!(!snapshot.has_entity(&Uuid::new_v4()));
}

#[tokio::test]
async fn test_world_model_snapshot_entity_management() {
    let user_id = Uuid::new_v4();
    let mut snapshot = WorldModelSnapshot::new(user_id, None);
    
    let entity_id = Uuid::new_v4();
    let entity = EntitySnapshot::new(
        entity_id,
        "Character|Health".to_string(),
        Some("Test Hero".to_string()),
    );
    
    // Add entity
    snapshot.add_entity(entity);
    
    assert_eq!(snapshot.entity_count(), 1);
    assert!(snapshot.has_entity(&entity_id));
    
    let retrieved = snapshot.get_entity(&entity_id);
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().name, Some("Test Hero".to_string()));
}

#[tokio::test]
async fn test_entity_snapshot_component_management() {
    let entity_id = Uuid::new_v4();
    let mut entity = EntitySnapshot::new(
        entity_id,
        "Character|Health|Position".to_string(),
        Some("Test Character".to_string()),
    );
    
    // Add health component
    entity.add_component("Health".to_string(), json!({
        "current": 85,
        "max": 100,
        "regeneration_rate": 1.5
    }));
    
    // Add position component
    entity.add_component("Position".to_string(), json!({
        "x": 10.5,
        "y": 20.3,
        "z": 0.0,
        "zone": "forest_clearing"
    }));
    
    // Verify components
    assert!(entity.has_component("Health"));
    assert!(entity.has_component("Position"));
    assert!(!entity.has_component("Inventory"));
    
    let health = entity.get_component("Health").unwrap();
    assert_eq!(health["current"], 85);
    assert_eq!(health["max"], 100);
    
    let position = entity.get_component("Position").unwrap();
    assert_eq!(position["zone"], "forest_clearing");
}

#[tokio::test]
async fn test_entity_snapshot_causal_influences() {
    let entity_id = Uuid::new_v4();
    let mut entity = EntitySnapshot::new(
        entity_id,
        "Character".to_string(),
        Some("Influenced Character".to_string()),
    );
    
    let event1 = Uuid::new_v4();
    let event2 = Uuid::new_v4();
    
    // Add causal influences
    entity.add_causal_influence(event1);
    entity.add_causal_influence(event2);
    entity.add_causal_influence(event1); // Duplicate should be ignored
    
    assert_eq!(entity.causal_influences.len(), 2);
    assert!(entity.causal_influences.contains(&event1));
    assert!(entity.causal_influences.contains(&event2));
}

#[tokio::test]
async fn test_relationship_snapshot_functionality() {
    let entity_a = Uuid::new_v4();
    let entity_b = Uuid::new_v4();
    
    let relationship = RelationshipSnapshot::new(
        entity_a,
        entity_b,
        "friendship".to_string(),
        "social".to_string(),
        0.8,
        json!({
            "trust": 0.9,
            "affection": 0.7,
            "duration_days": 30
        }),
    );
    
    // Test basic properties
    assert_eq!(relationship.from_entity, entity_a);
    assert_eq!(relationship.to_entity, entity_b);
    assert_eq!(relationship.relationship_type, "friendship");
    assert_eq!(relationship.category, "social");
    assert_eq!(relationship.strength, 0.8);
    
    // Test causal relationship detection
    assert!(!relationship.is_causal());
    
    let causal_rel = RelationshipSnapshot::new(
        entity_a,
        entity_b,
        "causes_effect_on".to_string(),
        "causal".to_string(),
        0.9,
        json!({}),
    );
    assert!(causal_rel.is_causal());
    
    // Test entity involvement
    assert!(relationship.involves_entity(&entity_a));
    assert!(relationship.involves_entity(&entity_b));
    assert!(!relationship.involves_entity(&Uuid::new_v4()));
    
    // Test get other entity
    assert_eq!(relationship.get_other_entity(&entity_a), Some(entity_b));
    assert_eq!(relationship.get_other_entity(&entity_b), Some(entity_a));
    assert_eq!(relationship.get_other_entity(&Uuid::new_v4()), None);
}

#[tokio::test]
async fn test_causal_event_snapshot_functionality() {
    let event_id = Uuid::new_v4();
    let timestamp = Utc::now();
    let mut event = CausalEventSnapshot::new(
        event_id,
        "COMBAT".to_string(),
        timestamp,
        "Hero attacks monster".to_string(),
    );
    
    let entity1 = Uuid::new_v4();
    let entity2 = Uuid::new_v4();
    let causing_event = Uuid::new_v4();
    let caused_event = Uuid::new_v4();
    
    // Add affected entities
    event.add_affected_entity(entity1);
    event.add_affected_entity(entity2);
    event.add_affected_entity(entity1); // Duplicate should be ignored
    
    // Set causality
    event.set_caused_by(causing_event);
    event.add_caused_event(caused_event);
    
    // Verify structure
    assert_eq!(event.event_id, event_id);
    assert_eq!(event.event_type, "COMBAT");
    assert_eq!(event.summary, "Hero attacks monster");
    assert_eq!(event.affected_entities.len(), 2);
    assert_eq!(event.caused_by, Some(causing_event));
    assert_eq!(event.causes.len(), 1);
    assert_eq!(event.causes[0], caused_event);
    
    // Test causal detection
    assert!(event.is_causal());
    
    // Test entity affection
    assert!(event.affects_entity(&entity1));
    assert!(event.affects_entity(&entity2));
    assert!(!event.affects_entity(&Uuid::new_v4()));
}

#[tokio::test]
async fn test_spatial_hierarchy_functionality() {
    let mut hierarchy = SpatialHierarchy::default();
    
    let root_location = Uuid::new_v4();
    let child_location = Uuid::new_v4();
    let entity_id = Uuid::new_v4();
    
    // Add root location
    hierarchy.add_root_location(root_location);
    hierarchy.add_root_location(root_location); // Duplicate should be ignored
    
    // Add containment
    hierarchy.add_containment(root_location, child_location);
    
    // Set entity location
    hierarchy.set_entity_location(entity_id, child_location);
    
    // Verify structure
    assert_eq!(hierarchy.root_locations.len(), 1);
    assert!(hierarchy.root_locations.contains(&root_location));
    
    let children = hierarchy.get_children(&root_location);
    assert!(children.is_some());
    assert_eq!(children.unwrap().len(), 1);
    assert!(children.unwrap().contains(&child_location));
    
    assert_eq!(hierarchy.get_entity_location(&entity_id), Some(&child_location));
    
    let entities_at_location = hierarchy.get_entities_at_location(&child_location);
    assert_eq!(entities_at_location.len(), 1);
    assert!(entities_at_location.contains(&entity_id));
}

#[tokio::test]
async fn test_temporal_context_functionality() {
    let time_window = Duration::hours(2);
    let mut context = TemporalContext::new(time_window);
    
    let significant_moment = Utc::now() - Duration::minutes(30);
    context.add_significant_moment(significant_moment);
    context.add_significant_moment(significant_moment); // Duplicate should be ignored
    
    // Verify structure
    assert_eq!(context.time_window, time_window);
    assert_eq!(context.significant_moments.len(), 1);
    assert!(context.significant_moments.contains(&significant_moment));
    
    // Test time window checking
    let recent_time = Utc::now() - Duration::minutes(30);
    let old_time = Utc::now() - Duration::hours(3);
    
    assert!(context.is_within_window(&recent_time));
    assert!(!context.is_within_window(&old_time));
    
    // Test window start calculation
    let expected_start = context.current_time - time_window;
    assert_eq!(context.window_start(), expected_start);
}

#[tokio::test]
async fn test_llm_world_context_building() {
    let mut context = LLMWorldContext::new();
    
    let entity_id = Uuid::new_v4();
    let entity_summary = EntitySummary::new(
        entity_id,
        "Test Hero".to_string(),
        "Character".to_string(),
        "healthy, in forest".to_string(),
    );
    
    let causal_chain = CausalChain::new(
        "Hero casts spell".to_string(),
        "Monster is defeated".to_string(),
        0.9,
    );
    
    let recent_change = RecentChange::new(
        "entity_state_change".to_string(),
        Some(entity_id),
        "Hero gained experience".to_string(),
        "low".to_string(),
    );
    
    // Build context
    context.add_entity_summary(entity_summary);
    context.add_causal_chain(causal_chain);
    context.add_recent_change(recent_change);
    context.add_reasoning_hint("Consider the character's motivation".to_string());
    
    // Verify structure
    assert_eq!(context.entity_summaries.len(), 1);
    assert_eq!(context.causal_chains.len(), 1);
    assert_eq!(context.recent_changes.len(), 1);
    assert_eq!(context.reasoning_hints.len(), 1);
    
    assert_eq!(context.entity_summaries[0].name, "Test Hero");
    assert_eq!(context.causal_chains[0].root_cause, "Hero casts spell");
    assert_eq!(context.recent_changes[0].change_type, "entity_state_change");
}

#[tokio::test]
async fn test_entity_summary_functionality() {
    let entity_id = Uuid::new_v4();
    let mut summary = EntitySummary::new(
        entity_id,
        "Test Character".to_string(),
        "Warrior".to_string(),
        "battle-ready".to_string(),
    );
    
    // Add attributes
    summary.add_attribute("level".to_string(), "5".to_string());
    summary.add_attribute("class".to_string(), "Fighter".to_string());
    
    // Add actions
    summary.add_recent_action("Attacked goblin".to_string());
    summary.add_recent_action("Looted treasure".to_string());
    
    // Verify structure
    assert_eq!(summary.entity_id, entity_id);
    assert_eq!(summary.name, "Test Character");
    assert_eq!(summary.entity_type, "Warrior");
    assert_eq!(summary.current_state, "battle-ready");
    assert_eq!(summary.key_attributes.len(), 2);
    assert_eq!(summary.recent_actions.len(), 2);
    
    assert_eq!(summary.key_attributes.get("level"), Some(&"5".to_string()));
    assert!(summary.recent_actions.contains(&"Attacked goblin".to_string()));
}

#[tokio::test]
async fn test_relationship_graph_functionality() {
    let mut graph = RelationshipGraph::new();
    
    let entity1 = Uuid::new_v4();
    let entity2 = Uuid::new_v4();
    
    // Add nodes
    let node1 = GraphNode::new(entity1, "Hero".to_string(), "character".to_string());
    let mut node2 = GraphNode::new(entity2, "Merchant".to_string(), "npc".to_string());
    node2.add_attribute("location".to_string(), "market".to_string());
    
    graph.add_node(node1);
    graph.add_node(node2);
    
    // Add edge
    let mut edge = GraphEdge::new(
        entity1,
        entity2,
        "knows".to_string(),
        0.6,
        "acquaintance".to_string(),
    );
    edge.add_attribute("trust".to_string(), "medium".to_string());
    graph.add_edge(edge);
    
    // Add cluster
    let cluster = RelationshipCluster::new(
        "allies".to_string(),
        vec![entity1, entity2],
        "Friendly characters in the market".to_string(),
        0.7,
    );
    graph.add_cluster(cluster);
    
    // Verify structure
    assert_eq!(graph.nodes.len(), 2);
    assert_eq!(graph.edges.len(), 1);
    assert_eq!(graph.clusters.len(), 1);
    
    // Test node finding
    let found_node = graph.find_node(&entity1);
    assert!(found_node.is_some());
    assert_eq!(found_node.unwrap().label, "Hero");
    
    // Test edge finding
    let entity_edges = graph.get_entity_edges(&entity1);
    assert_eq!(entity_edges.len(), 1);
    assert_eq!(entity_edges[0].relationship_type, "knows");
    
    // Test cluster functionality
    assert!(graph.clusters[0].contains_entity(&entity1));
    assert!(graph.clusters[0].contains_entity(&entity2));
    assert!(!graph.clusters[0].contains_entity(&Uuid::new_v4()));
}

#[tokio::test]
async fn test_causal_chain_functionality() {
    let mut chain = CausalChain::new(
        "Hero enters dungeon".to_string(),
        "Treasure is found".to_string(),
        0.8,
    );
    
    let step1 = CausalStep::new(
        "Hero defeats guardian".to_string(),
        vec!["Hero".to_string(), "Guardian".to_string()],
        Utc::now(),
        0.9,
    );
    
    let step2 = CausalStep::new(
        "Door unlocks".to_string(),
        vec!["Door".to_string()],
        Utc::now(),
        0.7,
    );
    
    chain.add_step(step1);
    chain.add_step(step2);
    
    // Verify structure
    assert_eq!(chain.root_cause, "Hero enters dungeon");
    assert_eq!(chain.final_effect, "Treasure is found");
    assert_eq!(chain.confidence, 0.8);
    assert_eq!(chain.length(), 2);
    assert_eq!(chain.steps[0].event, "Hero defeats guardian");
    assert_eq!(chain.steps[1].event, "Door unlocks");
}

#[tokio::test]
async fn test_spatial_context_functionality() {
    let mut spatial = SpatialContext::new();
    
    let location_id = Uuid::new_v4();
    let entity_id = Uuid::new_v4();
    
    // Add location
    let mut location = LocationSummary::new(
        location_id,
        "Market Square".to_string(),
        "town_center".to_string(),
        "A bustling marketplace".to_string(),
    );
    location.add_entity("Merchant".to_string());
    location.add_entity("Guard".to_string());
    spatial.add_location(location);
    
    // Add containment
    let containment = ContainmentRelation::new(
        "Town".to_string(),
        "Market Square".to_string(),
        "contains".to_string(),
    );
    spatial.add_containment(containment);
    
    // Set entity position
    spatial.set_entity_position(entity_id, "Market Square".to_string());
    
    // Verify structure
    assert_eq!(spatial.locations.len(), 1);
    assert_eq!(spatial.containment_relationships.len(), 1);
    assert_eq!(spatial.entity_positions.len(), 1);
    
    assert_eq!(spatial.locations[0].name, "Market Square");
    assert_eq!(spatial.locations[0].entities_present.len(), 2);
    assert_eq!(spatial.containment_relationships[0].parent, "Town");
    assert_eq!(spatial.entity_positions.get(&entity_id), Some(&"Market Square".to_string()));
}

// OWASP Security Tests for World Model Types

#[tokio::test]
async fn test_world_model_data_validation() {
    // A08: Software and Data Integrity Failures - Ensure world model data is properly validated
    let user_id = Uuid::new_v4();
    let mut snapshot = WorldModelSnapshot::new(user_id, None);
    
    // Test with potentially malicious data
    let malicious_entity_id = Uuid::new_v4();
    let mut malicious_entity = EntitySnapshot::new(
        malicious_entity_id,
        "'; DROP TABLE entities; --".to_string(),
        Some("<script>alert('xss')</script>".to_string()),
    );
    
    // Add malicious component data
    malicious_entity.add_component("MaliciousComponent".to_string(), json!({
        "script": "<img src=x onerror=alert('xss')>",
        "sql_injection": "'; DELETE FROM components; --",
        "command_injection": "; rm -rf /",
        "path_traversal": "../../../etc/passwd",
        "oversized_data": "A".repeat(10000)
    }));
    
    // System should handle malicious data safely
    snapshot.add_entity(malicious_entity);
    
    // Verify data is stored but not executed
    assert_eq!(snapshot.entity_count(), 1);
    let stored_entity = snapshot.get_entity(&malicious_entity_id).unwrap();
    assert!(stored_entity.name.is_some());
    assert!(stored_entity.has_component("MaliciousComponent"));
    
    // Verify that malicious data is contained and not interpreted
    let component = stored_entity.get_component("MaliciousComponent").unwrap();
    assert!(component.is_object());
    assert!(component.get("script").unwrap().is_string());
}

#[tokio::test]
async fn test_world_model_memory_safety() {
    // Performance and DoS protection test - prevent excessive memory usage
    let user_id = Uuid::new_v4();
    let mut snapshot = WorldModelSnapshot::new(user_id, None);
    
    // Test with large numbers of entities (reasonable limit)
    for i in 0..1000 {
        let entity = EntitySnapshot::new(
            Uuid::new_v4(),
            format!("Type{}", i),
            Some(format!("Entity{}", i)),
        );
        snapshot.add_entity(entity);
    }
    
    // Should handle reasonable numbers without issues
    assert_eq!(snapshot.entity_count(), 1000);
    
    // Test with large component data (should be contained)
    let large_entity_id = Uuid::new_v4();
    let mut large_entity = EntitySnapshot::new(
        large_entity_id,
        "LargeEntity".to_string(),
        Some("Large Data Entity".to_string()),
    );
    
    // Add component with large but reasonable data
    large_entity.add_component("LargeComponent".to_string(), json!({
        "data": "x".repeat(1000), // 1KB of data
        "array": (0..100).collect::<Vec<i32>>(),
        "nested": {
            "level1": {
                "level2": {
                    "level3": "deep nesting test"
                }
            }
        }
    }));
    
    snapshot.add_entity(large_entity);
    
    // Verify large data is handled properly
    assert_eq!(snapshot.entity_count(), 1001);
    let stored_large = snapshot.get_entity(&large_entity_id).unwrap();
    assert!(stored_large.has_component("LargeComponent"));
}

#[tokio::test]
async fn test_world_model_serialization_safety() {
    // Test that serialization/deserialization is safe from injection
    let user_id = Uuid::new_v4();
    let mut snapshot = WorldModelSnapshot::new(user_id, None);
    
    // Create entity with various data types
    let entity_id = Uuid::new_v4();
    let mut entity = EntitySnapshot::new(
        entity_id,
        "TestEntity".to_string(),
        Some("Serialization Test".to_string()),
    );
    
    // Add various JSON data types
    entity.add_component("StringData".to_string(), json!("normal string"));
    entity.add_component("NumberData".to_string(), json!(42));
    entity.add_component("BooleanData".to_string(), json!(true));
    entity.add_component("ArrayData".to_string(), json!([1, 2, 3]));
    entity.add_component("ObjectData".to_string(), json!({
        "nested": "value",
        "number": 123
    }));
    
    snapshot.add_entity(entity);
    
    // Test serialization
    let serialized = serde_json::to_string(&snapshot);
    assert!(serialized.is_ok(), "Serialization should succeed");
    
    // Test deserialization
    let deserialized: Result<WorldModelSnapshot, _> = serde_json::from_str(&serialized.unwrap());
    assert!(deserialized.is_ok(), "Deserialization should succeed");
    
    let restored_snapshot = deserialized.unwrap();
    assert_eq!(restored_snapshot.entity_count(), 1);
    assert_eq!(restored_snapshot.user_id, user_id);
    
    let restored_entity = restored_snapshot.get_entity(&entity_id).unwrap();
    assert_eq!(restored_entity.name, Some("Serialization Test".to_string()));
    assert!(restored_entity.has_component("StringData"));
    assert!(restored_entity.has_component("NumberData"));
}

#[tokio::test]
async fn test_world_model_access_control() {
    // A01: Broken Access Control - Ensure proper user isolation
    let user1_id = Uuid::new_v4();
    let user2_id = Uuid::new_v4();
    
    let user1_snapshot = WorldModelSnapshot::new(user1_id, None);
    let user2_snapshot = WorldModelSnapshot::new(user2_id, None);
    
    // Verify user isolation at the data structure level
    assert_ne!(user1_snapshot.user_id, user2_snapshot.user_id);
    assert_ne!(user1_snapshot.snapshot_id, user2_snapshot.snapshot_id);
    
    // Verify that snapshots are independent
    let entity_id = Uuid::new_v4();
    let entity = EntitySnapshot::new(
        entity_id,
        "UserSpecificEntity".to_string(),
        Some("User 1 Entity".to_string()),
    );
    
    let mut user1_modified = user1_snapshot.clone();
    user1_modified.add_entity(entity);
    
    // User1's snapshot should have the entity, User2's should not
    assert_eq!(user1_modified.entity_count(), 1);
    assert_eq!(user2_snapshot.entity_count(), 0);
    assert!(user1_modified.has_entity(&entity_id));
    assert!(!user2_snapshot.has_entity(&entity_id));
}