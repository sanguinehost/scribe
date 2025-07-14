use scribe_backend::services::planning::types::*;
use serde_json::json;
use uuid::Uuid;

#[test]
fn test_action_name_serialization() {
    // Test that action names serialize to snake_case as expected
    assert_eq!(
        serde_json::to_string(&ActionName::FindEntity).unwrap(),
        "\"find_entity\""
    );
    assert_eq!(
        serde_json::to_string(&ActionName::MoveEntity).unwrap(),
        "\"move_entity\""
    );
    assert_eq!(
        serde_json::to_string(&ActionName::AddItemToInventory).unwrap(),
        "\"add_item_to_inventory\""
    );
}

#[test]
fn test_action_name_deserialization() {
    // Test that we can deserialize from snake_case strings
    let find_entity: ActionName = serde_json::from_str("\"find_entity\"").unwrap();
    assert_eq!(find_entity, ActionName::FindEntity);
    
    let move_entity: ActionName = serde_json::from_str("\"move_entity\"").unwrap();
    assert_eq!(move_entity, ActionName::MoveEntity);
}

#[test]
fn test_complete_plan_serialization() {
    let plan = AiGeneratedPlan {
        plan: Plan {
            goal: "Sol needs to get the datapad from Borga".to_string(),
            actions: vec![
                PlannedAction {
                    id: "step1".to_string(),
                    name: ActionName::FindEntity,
                    parameters: json!({
                        "criteria": {
                            "type": "ByName",
                            "name": "Sol"
                        }
                    }),
                    preconditions: Preconditions {
                        entity_exists: Some(vec![EntityExistenceCheck {
                            entity_id: None,
                            entity_name: Some("Sol".to_string()),
                        }]),
                        ..Default::default()
                    },
                    effects: Effects::default(),
                    dependencies: vec![],
                },
            ],
            metadata: PlanMetadata {
                estimated_duration: Some(300),
                confidence: 0.85,
                alternative_considered: Some("Sol could try to steal the datapad".to_string()),
            },
        },
    };

    // Should serialize without errors
    let serialized = serde_json::to_string(&plan).unwrap();
    assert!(serialized.contains("\"goal\":\"Sol needs to get the datapad from Borga\""));
    assert!(serialized.contains("\"find_entity\""));
    assert!(serialized.contains("\"confidence\":0.85"));
}

#[test]
fn test_plan_deserialization_from_schema_example() {
    // Use the example from our schema file
    let json_str = r#"{
        "plan": {
            "goal": "Sol needs to get the datapad from Borga",
            "actions": [
                {
                    "id": "step1",
                    "name": "find_entity",
                    "parameters": {
                        "criteria": {
                            "type": "ByName",
                            "name": "Sol"
                        }
                    },
                    "preconditions": {
                        "entity_exists": [{"entity_name": "Sol"}]
                    },
                    "effects": {},
                    "dependencies": []
                }
            ],
            "metadata": {
                "estimated_duration": 300,
                "confidence": 0.85,
                "alternative_considered": "Sol could try to steal the datapad without Borga's consent"
            }
        }
    }"#;

    let plan: AiGeneratedPlan = serde_json::from_str(json_str).unwrap();
    assert_eq!(plan.plan.goal, "Sol needs to get the datapad from Borga");
    assert_eq!(plan.plan.actions.len(), 1);
    assert_eq!(plan.plan.actions[0].name, ActionName::FindEntity);
    assert_eq!(plan.plan.metadata.confidence, 0.85);
}

#[test]
fn test_preconditions_validation() {
    let preconditions = Preconditions {
        entity_exists: Some(vec![
            EntityExistenceCheck {
                entity_id: Some("sol-uuid".to_string()),
                entity_name: Some("Sol".to_string()),
            },
        ]),
        entity_at_location: Some(vec![
            EntityLocationCheck {
                entity_id: "sol-uuid".to_string(),
                location_id: "cantina-uuid".to_string(),
            },
        ]),
        inventory_has_space: Some(InventorySpaceCheck {
            entity_id: "sol-uuid".to_string(),
            required_slots: 1,
        }),
        ..Default::default()
    };

    // Verify all fields are present
    assert!(preconditions.entity_exists.is_some());
    assert!(preconditions.entity_at_location.is_some());
    assert!(preconditions.inventory_has_space.is_some());
    assert!(preconditions.relationship_exists.is_none());
}

#[test]
fn test_effects_serialization() {
    let effects = Effects {
        entity_moved: Some(EntityMovedEffect {
            entity_id: "sol-uuid".to_string(),
            new_location: "cantina-uuid".to_string(),
        }),
        inventory_changed: Some(InventoryChangeEffect {
            entity_id: "sol-uuid".to_string(),
            item_id: "datapad-uuid".to_string(),
            quantity_change: 1,
        }),
        ..Default::default()
    };

    let serialized = serde_json::to_string(&effects).unwrap();
    assert!(serialized.contains("\"entity_moved\""));
    assert!(serialized.contains("\"inventory_changed\""));
    assert!(!serialized.contains("\"entity_created\"")); // Should skip None fields
}

#[test]
fn test_validation_result_types() {
    let valid_plan = ValidatedPlan {
        plan_id: Uuid::new_v4(),
        original_plan: Plan {
            goal: "Test goal".to_string(),
            actions: vec![],
            metadata: PlanMetadata {
                estimated_duration: None,
                confidence: 0.9,
                alternative_considered: None,
            },
        },
        validation_timestamp: chrono::Utc::now(),
        cache_key: "test-cache-key".to_string(),
    };

    let result = PlanValidationResult::Valid(valid_plan.clone());
    match result {
        PlanValidationResult::Valid(p) => {
            assert_eq!(p.original_plan.goal, "Test goal");
            assert_eq!(p.cache_key, "test-cache-key");
        }
        _ => panic!("Expected Valid result"),
    }
}

#[test]
fn test_invalid_plan_with_failures() {
    let invalid_plan = InvalidPlan {
        plan: Plan {
            goal: "Invalid test".to_string(),
            actions: vec![],
            metadata: PlanMetadata {
                estimated_duration: None,
                confidence: 0.5,
                alternative_considered: None,
            },
        },
        failures: vec![
            ValidationFailure {
                action_id: "step1".to_string(),
                failure_type: ValidationFailureType::EntityNotFound,
                message: "Entity 'Sol' not found in world state".to_string(),
            },
            ValidationFailure {
                action_id: "step2".to_string(),
                failure_type: ValidationFailureType::PreconditionNotMet,
                message: "Sol is not at the required location".to_string(),
            },
        ],
    };

    assert_eq!(invalid_plan.failures.len(), 2);
    assert_eq!(invalid_plan.failures[0].failure_type, ValidationFailureType::EntityNotFound);
    assert_eq!(invalid_plan.failures[1].failure_type, ValidationFailureType::PreconditionNotMet);
}

#[test]
fn test_context_cache_structure() {
    use std::collections::HashMap;
    use chrono::Utc;

    let mut cache = ContextCache {
        recent_entities: HashMap::new(),
        recent_plans: vec![],
        cache_timestamp: Utc::now(),
    };

    // Add a cached entity
    let entity_id = Uuid::new_v4();
    cache.recent_entities.insert(
        entity_id,
        CachedEntityState {
            entity_id,
            name: "Sol".to_string(),
            components: HashMap::from([
                ("Position".to_string(), json!({"x": 10, "y": 20})),
                ("Health".to_string(), json!({"current": 100, "max": 100})),
            ]),
            last_accessed: Utc::now(),
            access_count: 3,
        },
    );

    // Add a cached plan
    let plan = Plan {
        goal: "Move to cantina".to_string(),
        actions: vec![],
        metadata: PlanMetadata {
            estimated_duration: Some(60),
            confidence: 0.95,
            alternative_considered: None,
        },
    };

    let validated_plan = ValidatedPlan {
        plan_id: Uuid::new_v4(),
        original_plan: plan,
        validation_timestamp: Utc::now(),
        cache_key: "cache-key-1".to_string(),
    };

    cache.recent_plans.push(("Move to cantina".to_string(), validated_plan));

    // Verify cache contents
    assert_eq!(cache.recent_entities.len(), 1);
    assert_eq!(cache.recent_plans.len(), 1);
    assert_eq!(cache.recent_plans[0].0, "Move to cantina");
}

#[test]
fn test_complex_plan_with_dependencies() {
    let plan = Plan {
        goal: "Complete a trade transaction".to_string(),
        actions: vec![
            PlannedAction {
                id: "find_trader".to_string(),
                name: ActionName::FindEntity,
                parameters: json!({"criteria": {"type": "ByName", "name": "Trader"}}),
                preconditions: Preconditions::default(),
                effects: Effects::default(),
                dependencies: vec![],
            },
            PlannedAction {
                id: "move_to_trader".to_string(),
                name: ActionName::MoveEntity,
                parameters: json!({
                    "entity_to_move": "player",
                    "new_parent": "trader_location"
                }),
                preconditions: Preconditions {
                    entity_exists: Some(vec![
                        EntityExistenceCheck {
                            entity_id: Some("player".to_string()),
                            entity_name: None,
                        },
                        EntityExistenceCheck {
                            entity_id: Some("trader_location".to_string()),
                            entity_name: None,
                        },
                    ]),
                    ..Default::default()
                },
                effects: Effects {
                    entity_moved: Some(EntityMovedEffect {
                        entity_id: "player".to_string(),
                        new_location: "trader_location".to_string(),
                    }),
                    ..Default::default()
                },
                dependencies: vec!["find_trader".to_string()],
            },
            PlannedAction {
                id: "execute_trade".to_string(),
                name: ActionName::UpdateRelationship,
                parameters: json!({
                    "source_entity": "player",
                    "target_entity": "trader",
                    "trust_delta": 0.1
                }),
                preconditions: Preconditions {
                    entity_at_location: Some(vec![
                        EntityLocationCheck {
                            entity_id: "player".to_string(),
                            location_id: "trader_location".to_string(),
                        },
                    ]),
                    relationship_exists: Some(vec![
                        RelationshipCheck {
                            source_entity: "player".to_string(),
                            target_entity: "trader".to_string(),
                            min_trust: Some(0.3),
                        },
                    ]),
                    ..Default::default()
                },
                effects: Effects {
                    relationship_changed: Some(RelationshipChangeEffect {
                        source_entity: "player".to_string(),
                        target_entity: "trader".to_string(),
                        trust_change: Some(0.1),
                        affection_change: None,
                    }),
                    ..Default::default()
                },
                dependencies: vec!["move_to_trader".to_string()],
            },
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(180),
            confidence: 0.75,
            alternative_considered: Some("Could use persuasion instead of trade".to_string()),
        },
    };

    // Verify dependency chain
    assert_eq!(plan.actions[0].dependencies.len(), 0);
    assert_eq!(plan.actions[1].dependencies, vec!["find_trader"]);
    assert_eq!(plan.actions[2].dependencies, vec!["move_to_trader"]);

    // Verify action sequence makes sense
    assert_eq!(plan.actions[0].name, ActionName::FindEntity);
    assert_eq!(plan.actions[1].name, ActionName::MoveEntity);
    assert_eq!(plan.actions[2].name, ActionName::UpdateRelationship);
}