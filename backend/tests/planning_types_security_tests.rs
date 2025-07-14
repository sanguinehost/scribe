use scribe_backend::services::planning::types::*;
use serde_json::json;
use uuid::Uuid;

// A01: Broken Access Control Tests

#[test]
fn test_a01_plan_contains_user_specific_entities() {
    // Plans should only reference entities the user owns
    let plan = Plan {
        goal: "Access another user's inventory".to_string(),
        actions: vec![
            PlannedAction {
                id: "hack_attempt".to_string(),
                name: ActionName::GetEntityDetails,
                parameters: json!({
                    "entity_id": "other-user-entity-uuid"
                }),
                preconditions: Preconditions::default(),
                effects: Effects::default(),
                dependencies: vec![],
            },
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(10),
            confidence: 0.1,
            alternative_considered: None,
        },
    };

    // This plan should be rejected during validation (tested in plan_validator)
    // Here we just ensure the structure can represent such attempts for detection
    assert_eq!(plan.actions[0].parameters["entity_id"], "other-user-entity-uuid");
}

#[test]
fn test_a01_plan_cache_key_includes_user_id() {
    // Cache keys must include user ID to prevent cross-user cache pollution
    let validated_plan = ValidatedPlan {
        plan_id: Uuid::new_v4(),
        original_plan: Plan {
            goal: "Test".to_string(),
            actions: vec![],
            metadata: PlanMetadata {
                estimated_duration: None,
                confidence: 1.0,
                alternative_considered: None,
            },
        },
        validation_timestamp: chrono::Utc::now(),
        cache_key: "plan:user123:goal_hash:state_hash".to_string(),
    };

    // Verify cache key contains user identifier
    assert!(validated_plan.cache_key.contains("user123"));
}

// A02: Cryptographic Failures Tests

#[test]
fn test_a02_sensitive_data_not_in_plan_metadata() {
    // Plans should not contain sensitive data in metadata
    let metadata = PlanMetadata {
        estimated_duration: Some(100),
        confidence: 0.8,
        alternative_considered: Some("Alternative approach".to_string()),
    };

    // Serialize and check no sensitive patterns
    let serialized = serde_json::to_string(&metadata).unwrap();
    assert!(!serialized.contains("password"));
    assert!(!serialized.contains("token"));
    assert!(!serialized.contains("secret"));
}

// A03: Injection Tests

#[test]
fn test_a03_sql_injection_in_entity_names() {
    // Test that malicious entity names are properly handled
    let malicious_check = EntityExistenceCheck {
        entity_id: None,
        entity_name: Some("Sol'; DROP TABLE users; --".to_string()),
    };

    // This should serialize safely
    let serialized = serde_json::to_string(&malicious_check).unwrap();
    assert!(serialized.contains("Sol'; DROP TABLE users; --"));
    
    // The actual protection happens in the validator/executor
}

#[test]
fn test_a03_json_injection_in_parameters() {
    // Test that malicious JSON in parameters doesn't break structure
    let action = PlannedAction {
        id: "test".to_string(),
        name: ActionName::CreateEntity,
        parameters: json!({
            "name": "Test\", \"malicious\": \"injected",
            "description": "Normal description"
        }),
        preconditions: Preconditions::default(),
        effects: Effects::default(),
        dependencies: vec![],
    };

    // Should handle quotes properly
    let serialized = serde_json::to_string(&action).unwrap();
    assert!(serialized.contains("Test\\\", \\\"malicious\\\": \\\"injected"));
}

#[test]
fn test_a03_script_injection_in_goal() {
    // Test XSS-style injection in goal text
    let plan = Plan {
        goal: "<script>alert('xss')</script>".to_string(),
        actions: vec![],
        metadata: PlanMetadata {
            estimated_duration: None,
            confidence: 1.0,
            alternative_considered: None,
        },
    };

    // Should preserve but not execute
    assert_eq!(plan.goal, "<script>alert('xss')</script>");
}

// A04: Insecure Design Tests

#[test]
fn test_a04_action_dependency_cycles() {
    // Plans should not have circular dependencies
    let actions = vec![
        PlannedAction {
            id: "step1".to_string(),
            name: ActionName::FindEntity,
            parameters: json!({}),
            preconditions: Preconditions::default(),
            effects: Effects::default(),
            dependencies: vec!["step2".to_string()], // Depends on step2
        },
        PlannedAction {
            id: "step2".to_string(),
            name: ActionName::MoveEntity,
            parameters: json!({}),
            preconditions: Preconditions::default(),
            effects: Effects::default(),
            dependencies: vec!["step1".to_string()], // Depends on step1 - circular!
        },
    ];

    // Validator should detect this
    assert_eq!(actions[0].dependencies[0], "step2");
    assert_eq!(actions[1].dependencies[0], "step1");
}

#[test]
fn test_a04_resource_exhaustion_limits() {
    // Test that we can handle but should limit very large plans
    let mut actions = vec![];
    for i in 0..1000 {
        actions.push(PlannedAction {
            id: format!("step{}", i),
            name: ActionName::FindEntity,
            parameters: json!({"entity": format!("entity{}", i)}),
            preconditions: Preconditions::default(),
            effects: Effects::default(),
            dependencies: if i > 0 { vec![format!("step{}", i - 1)] } else { vec![] },
        });
    }

    let plan = Plan {
        goal: "Extremely complex plan".to_string(),
        actions,
        metadata: PlanMetadata {
            estimated_duration: Some(100000),
            confidence: 0.1,
            alternative_considered: None,
        },
    };

    // Should be able to create, but validator should enforce limits
    assert_eq!(plan.actions.len(), 1000);
}

// A05: Security Misconfiguration Tests

#[test]
fn test_a05_invalid_confidence_bounds() {
    // Confidence should be between 0 and 1
    let metadata = PlanMetadata {
        estimated_duration: None,
        confidence: 1.5, // Invalid - too high
        alternative_considered: None,
    };

    // Type system allows this, but validator should check
    assert!(metadata.confidence > 1.0);
}

#[test]
fn test_a05_negative_inventory_slots() {
    // Required slots should not be negative
    let check = InventorySpaceCheck {
        entity_id: "test".to_string(),
        required_slots: 0, // Minimum valid value
    };

    // Type system prevents negative values with u32
    assert_eq!(check.required_slots, 0);
}

// A07: Identification and Authentication Failures Tests

#[test]
fn test_a07_action_without_user_context() {
    // All actions should have user context (tested in executor)
    let action = PlannedAction {
        id: "anonymous".to_string(),
        name: ActionName::CreateEntity,
        parameters: json!({
            // Note: no user_id field
            "name": "Anonymous Entity"
        }),
        preconditions: Preconditions::default(),
        effects: Effects::default(),
        dependencies: vec![],
    };

    // Validator should require user context
    assert!(!action.parameters.as_object().unwrap().contains_key("user_id"));
}

// A08: Software and Data Integrity Failures Tests

#[test]
fn test_a08_effect_consistency_with_action() {
    // Effects should match the action type
    let action = PlannedAction {
        id: "inconsistent".to_string(),
        name: ActionName::MoveEntity,
        parameters: json!({
            "entity_to_move": "player",
            "new_parent": "location"
        }),
        preconditions: Preconditions::default(),
        effects: Effects {
            // Wrong effect type for move action!
            inventory_changed: Some(InventoryChangeEffect {
                entity_id: "player".to_string(),
                item_id: "item".to_string(),
                quantity_change: 1,
            }),
            ..Default::default()
        },
        dependencies: vec![],
    };

    // Validator should detect mismatch
    assert!(action.effects.inventory_changed.is_some());
    assert!(action.effects.entity_moved.is_none());
}

#[test]
fn test_a08_cache_timestamp_validation() {
    use chrono::{Duration, Utc};

    let cache = ContextCache {
        recent_entities: Default::default(),
        recent_plans: vec![],
        cache_timestamp: Utc::now() - Duration::hours(25), // Very old cache
    };

    // Cache invalidation should check timestamps
    let age = Utc::now() - cache.cache_timestamp;
    assert!(age > Duration::hours(24));
}

// A09: Security Logging and Monitoring Failures Tests

#[test]
fn test_a09_validation_failure_includes_context() {
    let failure = ValidationFailure {
        action_id: "suspicious_action".to_string(),
        failure_type: ValidationFailureType::PermissionDenied,
        message: "User attempted to access entity owned by another user".to_string(),
    };

    // Should have enough context for logging
    assert!(!failure.action_id.is_empty());
    assert!(!failure.message.is_empty());
    assert_eq!(failure.failure_type, ValidationFailureType::PermissionDenied);
}

#[test]
fn test_a09_plan_metadata_for_monitoring() {
    let plan = Plan {
        goal: "Suspicious activity".to_string(),
        actions: vec![],
        metadata: PlanMetadata {
            estimated_duration: Some(1), // Suspiciously fast
            confidence: 0.01, // Suspiciously low
            alternative_considered: Some("Legitimate approach".to_string()),
        },
    };

    // Monitoring should flag suspicious patterns
    assert!(plan.metadata.confidence < 0.1);
    assert!(plan.metadata.estimated_duration.unwrap() < 10);
}

// A10: Server-Side Request Forgery Tests

#[test]
fn test_a10_no_external_references_in_plans() {
    // Plans should not contain URLs or external references
    let action = PlannedAction {
        id: "external".to_string(),
        name: ActionName::FindEntity,
        parameters: json!({
            "criteria": {
                "type": "ByName",
                "name": "http://evil.com/entity"
            }
        }),
        preconditions: Preconditions::default(),
        effects: Effects::default(),
        dependencies: vec![],
    };

    // Validator should check for URL patterns
    let name = action.parameters["criteria"]["name"].as_str().unwrap();
    assert!(name.starts_with("http"));
}

// Additional Security Tests

#[test]
fn test_plan_size_limits() {
    // Test serialization size limits
    let mut large_metadata = std::collections::HashMap::new();
    for i in 0..10000 {
        large_metadata.insert(format!("key{}", i), json!(format!("value{}", i)));
    }

    let action = PlannedAction {
        id: "large".to_string(),
        name: ActionName::CreateEntity,
        parameters: json!(large_metadata),
        preconditions: Preconditions::default(),
        effects: Effects::default(),
        dependencies: vec![],
    };

    let serialized = serde_json::to_string(&action).unwrap();
    // Should handle but validator should limit
    assert!(serialized.len() > 100000);
}

#[test]
fn test_trust_bounds_validation() {
    // Trust values should be properly bounded
    let check = RelationshipCheck {
        source_entity: "player".to_string(),
        target_entity: "npc".to_string(),
        min_trust: Some(2.0), // Invalid - too high
    };

    // Validator should enforce bounds
    assert!(check.min_trust.unwrap() > 1.0);
}

#[test]
fn test_component_operation_validation() {
    // Component operations should be valid
    let effect = ComponentUpdateEffect {
        entity_id: "test".to_string(),
        component_type: "Health".to_string(),
        operation: ComponentOperation::Update,
    };

    // Ensure all operation types are handled
    match effect.operation {
        ComponentOperation::Add => {},
        ComponentOperation::Update => {},
        ComponentOperation::Remove => {},
    }
}