// NOTE: These tests validate Task 6.1.2 - ECS State Reconciliation & Intelligent Plan Repair
// 
// This test suite focuses specifically on the ECS State Reconciliation system's ability to:
// 1. Detect when ECS state has fallen behind narrative (rather than plan being invalid)
// 2. Generate appropriate repair actions to fix ECS inconsistencies
// 3. Combine repair plans with original plans safely
// 4. Validate that repair chains don't create infinite loops
// 5. Handle low confidence repair scenarios appropriately
// 6. Test the complete repair workflow integration

use scribe_backend::{
    services::{
        planning::{
            PlanValidatorService, PlanRepairService,
            types::*,
        },
        EcsEntityManager,
    },
    models::{
        ecs::*,
        chats::{ChatMessage, MessageRole},
        users::User as DbUser,
    },
    test_helpers::{spawn_app_permissive_rate_limiting, TestDataGuard, MockAiClient, db::create_test_user, ai_tool_testing::create_test_user_id},
    PgPool,
};
use std::sync::Arc;
use uuid::Uuid;
use chrono::Utc;
use serde_json::json;

/// Helper to create test entity manager
async fn create_test_entity_manager(db_pool: PgPool) -> Arc<EcsEntityManager> {
    let redis_client = Arc::new(
        redis::Client::open("redis://127.0.0.1:6379/")
            .expect("Failed to create Redis client for tests")
    );
    
    Arc::new(EcsEntityManager::new(
        db_pool.into(),
        redis_client,
        None,
    ))
}

/// Helper to create test entities for reconciliation scenarios  
async fn create_test_entities_for_reconciliation(
    entity_manager: &Arc<EcsEntityManager>,
    db_pool: &PgPool,
) -> (Uuid, Uuid, Uuid, Uuid, Uuid) {
    // Create a test user and use the actual returned user ID
    let test_user = create_test_user(
        db_pool,
        "testuser".to_string(),
        "testpassword".to_string()
    ).await.expect("Failed to create test user");
    let user_id = test_user.id;

    // Create Sol character in the Chamber
    let sol_result = entity_manager.create_entity(
        user_id,
        Some(Uuid::new_v4()),
        "Name|Inventory|Salience|ParentLink".to_string(),
        vec![
            ("Name".to_string(), serde_json::json!({"name": "Sol"})),
            ("Inventory".to_string(), serde_json::json!({"items": [], "capacity": 10})),
            ("Salience".to_string(), serde_json::json!({"tier": "Core", "scale_context": "character", "expiry": null})),
        ],
    ).await.unwrap();
    let sol_id = sol_result.entity.id;

    // Create Chamber location  
    let chamber_result = entity_manager.create_entity(
        user_id,
        Some(Uuid::new_v4()),
        "Name|Salience".to_string(),
        vec![
            ("Name".to_string(), serde_json::json!({"name": "Chamber"})),
            ("Salience".to_string(), serde_json::json!({"tier": "Secondary", "scale_context": "location", "expiry": null})),
        ],
    ).await.unwrap();
    let chamber_id = chamber_result.entity.id;

    // Create Cantina location
    let cantina_result = entity_manager.create_entity(
        user_id,
        Some(Uuid::new_v4()),
        "Name|Salience".to_string(),
        vec![
            ("Name".to_string(), serde_json::json!({"name": "Cantina"})),
            ("Salience".to_string(), serde_json::json!({"tier": "Secondary", "scale_context": "location", "expiry": null})),
        ],
    ).await.unwrap();
    let cantina_id = cantina_result.entity.id;

    // Create Borga character (no relationship with Sol initially)
    let borga_result = entity_manager.create_entity(
        user_id,
        Some(Uuid::new_v4()),
        "Name|Salience".to_string(),
        vec![
            ("Name".to_string(), serde_json::json!({"name": "Borga"})),
            ("Salience".to_string(), serde_json::json!({"tier": "Secondary", "scale_context": "character", "expiry": null})),
        ],
    ).await.unwrap();
    let borga_id = borga_result.entity.id;

    // Set Sol's initial location to Chamber
    entity_manager.move_entity(user_id, sol_id, chamber_id, None).await.unwrap();

    (sol_id, chamber_id, cantina_id, borga_id, user_id)
}

/// Helper to create mock chat messages for context analysis
fn create_mock_chat_messages(scenario: &str) -> Vec<ChatMessage> {
    let base_time = Utc::now() - chrono::Duration::minutes(5);
    
    match scenario {
        "missing_movement" => vec![
            ChatMessage {
                id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                user_id: Uuid::new_v4(),
                message_type: MessageRole::User,
                content: "Sol walks into the cantina and looks around.".as_bytes().to_vec(),
                content_nonce: None,
                created_at: base_time,
                prompt_tokens: None,
                completion_tokens: None,
                raw_prompt_ciphertext: None,
                raw_prompt_nonce: None,
                model_name: "test-model".to_string(),
            },
            ChatMessage {
                id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                user_id: Uuid::new_v4(),
                message_type: MessageRole::Assistant,
                content: "Sol enters the bustling cantina, the smell of exotic drinks filling the air.".as_bytes().to_vec(),
                content_nonce: None,
                created_at: base_time + chrono::Duration::minutes(1),
                prompt_tokens: None,
                completion_tokens: None,
                raw_prompt_ciphertext: None,
                raw_prompt_nonce: None,
                model_name: "test-model".to_string(),
            },
        ],
        "missing_relationship" => vec![
            ChatMessage {
                id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                user_id: Uuid::new_v4(),
                message_type: MessageRole::User,
                content: "Sol greets his old friend Borga warmly.".as_bytes().to_vec(),
                content_nonce: None,
                created_at: base_time,
                prompt_tokens: None,
                completion_tokens: None,
                raw_prompt_ciphertext: None,
                raw_prompt_nonce: None,
                model_name: "test-model".to_string(),
            },
            ChatMessage {
                id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                user_id: Uuid::new_v4(),
                message_type: MessageRole::Assistant,
                content: "Borga's face lights up as he sees Sol approach, clearly happy to see his trusted companion.".as_bytes().to_vec(),
                content_nonce: None,
                created_at: base_time + chrono::Duration::minutes(1),
                prompt_tokens: None,
                completion_tokens: None,
                raw_prompt_ciphertext: None,
                raw_prompt_nonce: None,
                model_name: "test-model".to_string(),
            },
        ],
        "missing_component" => vec![
            ChatMessage {
                id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                user_id: Uuid::new_v4(),
                message_type: MessageRole::User,
                content: "Sol's reputation as a skilled pilot spreads after the successful mission.".as_bytes().to_vec(),
                content_nonce: None,
                created_at: base_time,
                prompt_tokens: None,
                completion_tokens: None,
                raw_prompt_ciphertext: None,
                raw_prompt_nonce: None,
                model_name: "test-model".to_string(),
            },
            ChatMessage {
                id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                user_id: Uuid::new_v4(),
                message_type: MessageRole::Assistant,
                content: "Word of Sol's exceptional piloting skills spreads through the starport, earning respect among fellow pilots.".as_bytes().to_vec(),
                content_nonce: None,
                created_at: base_time + chrono::Duration::minutes(1),
                prompt_tokens: None,
                completion_tokens: None,
                raw_prompt_ciphertext: None,
                raw_prompt_nonce: None,
                model_name: "test-model".to_string(),
            },
        ],
        _ => vec![],
    }
}

#[tokio::test]
async fn test_ecs_consistency_analyzer_missing_movement_detection() {
    // Test that the analyzer correctly identifies missing movement as an ECS inconsistency
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let (sol_id, _chamber_id, cantina_id, _borga_id, user_id) = 
        create_test_entities_for_reconciliation(&entity_manager, &test_app.db_pool).await;

    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);

    // Create a plan that assumes Sol is in the cantina (but ECS shows he's in chamber)
    let plan = Plan {
        goal: "Sol orders a drink at the cantina".to_string(),
        actions: vec![
            PlannedAction {
                id: "step1".to_string(),
                name: ActionName::AddItemToInventory,
                parameters: serde_json::json!({
                    "owner_entity_id": sol_id.to_string(),
                    "item_entity_id": Uuid::new_v4().to_string(),
                    "quantity": 1,
                }),
                preconditions: Preconditions {
                    entity_at_location: Some(vec![
                        EntityLocationCheck {
                            entity_id: sol_id.to_string(),
                            location_id: cantina_id.to_string(),
                        }
                    ]),
                    inventory_has_space: Some(InventorySpaceCheck {
                        entity_id: sol_id.to_string(),
                        required_slots: 1,
                    }),
                    ..Default::default()
                },
                effects: Effects::default(),
                dependencies: vec![],
            }
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(30),
            confidence: 0.9,
            alternative_considered: None,
        },
    };

    let chat_context = create_mock_chat_messages("missing_movement");
    
    // Standard validation should fail (Sol not in cantina)
    let result = validator.validate_plan(&plan, user_id).await.unwrap();
    
    match result {
        PlanValidationResult::Invalid(invalid) => {
            // Should detect that entity is not at expected location
            assert!(invalid.failures.iter().any(|f| 
                f.failure_type == ValidationFailureType::PreconditionNotMet &&
                f.message.contains("location")
            ));
        }
        _ => panic!("Expected invalid plan due to location mismatch"),
    }

    // TODO: Once implemented, test enhanced validation with repair capability
    // let enhanced_result = validator.validate_plan_with_repair(&plan, user_id, &chat_context).await.unwrap();
    // match enhanced_result {
    //     PlanValidationResult::RepairableInvalid(repairable) => {
    //         assert_eq!(repairable.inconsistency_analysis.inconsistency_type, InconsistencyType::MissingMovement);
    //         assert!(repairable.confidence_score > 0.7);
    //         assert!(!repairable.repair_actions.is_empty());
    //     }
    //     _ => panic!("Expected repairable invalid plan for missing movement"),
    // }
}

#[tokio::test]
async fn test_ecs_consistency_analyzer_missing_relationship_detection() {
    // Test detection of missing relationships implied by narrative context
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let (sol_id, _chamber_id, _cantina_id, borga_id, user_id) = 
        create_test_entities_for_reconciliation(&entity_manager, &test_app.db_pool).await;

    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);

    // Plan to update relationship trust, but no relationship exists
    let plan = Plan {
        goal: "Sol expresses trust in Borga".to_string(),
        actions: vec![
            PlannedAction {
                id: "step1".to_string(),
                name: ActionName::UpdateRelationship,
                parameters: serde_json::json!({
                    "source_entity_id": sol_id.to_string(),
                    "target_entity_id": borga_id.to_string(),
                    "trust": 0.8,
                }),
                preconditions: Preconditions {
                    relationship_exists: Some(vec![
                        RelationshipCheck {
                            source_entity: sol_id.to_string(),
                            target_entity: borga_id.to_string(),
                            min_trust: Some(0.0),
                        }
                    ]),
                    ..Default::default()
                },
                effects: Effects::default(),
                dependencies: vec![],
            }
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(15),
            confidence: 0.85,
            alternative_considered: None,
        },
    };

    let _chat_context = create_mock_chat_messages("missing_relationship");
    
    // Should fail because no relationship exists between Sol and Borga
    let result = validator.validate_plan(&plan, user_id).await.unwrap();
    
    match result {
        PlanValidationResult::Invalid(invalid) => {
            assert!(invalid.failures.iter().any(|f| 
                f.failure_type == ValidationFailureType::PreconditionNotMet &&
                f.message.contains("relationship does not exist")
            ));
        }
        _ => panic!("Expected invalid plan due to missing relationship"),
    }
}

#[tokio::test]
async fn test_ecs_consistency_analyzer_missing_component_detection() {
    // Test detection of missing components that should exist based on narrative
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let (sol_id, _chamber_id, _cantina_id, _borga_id, user_id) = 
        create_test_entities_for_reconciliation(&entity_manager, &test_app.db_pool).await;

    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let validator = PlanValidatorService::new(entity_manager, redis_client);

    // Plan to update Reputation component that doesn't exist on Sol
    let plan = Plan {
        goal: "Sol's piloting reputation improves".to_string(),
        actions: vec![
            PlannedAction {
                id: "step1".to_string(),
                name: ActionName::UpdateEntity,
                parameters: serde_json::json!({
                    "entity_id": sol_id.to_string(),
                    "component_operations": [{
                        "operation": "update",
                        "component_type": "Reputation",
                        "component_data": {"pilot_skill": 0.9}
                    }]
                }),
                preconditions: Preconditions {
                    entity_has_component: Some(vec![
                        EntityComponentCheck {
                            entity_id: sol_id.to_string(),
                            component_type: "Reputation".to_string(),
                        }
                    ]),
                    ..Default::default()
                },
                effects: Effects::default(),
                dependencies: vec![],
            }
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(10),
            confidence: 0.8,
            alternative_considered: None,
        },
    };

    let _chat_context = create_mock_chat_messages("missing_component");
    
    // Should fail because Sol doesn't have a Reputation component
    let result = validator.validate_plan(&plan, user_id).await.unwrap();
    
    match result {
        PlanValidationResult::Invalid(invalid) => {
            assert!(invalid.failures.iter().any(|f| 
                f.failure_type == ValidationFailureType::PreconditionNotMet &&
                f.message.contains("missing component")
            ));
        }
        _ => panic!("Expected invalid plan due to missing component"),
    }
}

#[tokio::test]
async fn test_plan_repair_service_movement_repair() {
    // Test that repair service can generate movement repair actions
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let (sol_id, chamber_id, cantina_id, _borga_id, user_id) = 
        create_test_entities_for_reconciliation(&entity_manager, &test_app.db_pool).await;

    // Setup mock AI for movement repair
    let mock_ai = Arc::new(MockAiClient::new_with_response(
        json!({
            "goal": "Repair missing movement for entity",
            "actions": [{
                "id": "repair_movement",
                "name": "move_entity",
                "parameters": {
                    "entity_to_move": sol_id.to_string(),
                    "new_parent": cantina_id.to_string()
                },
                "preconditions": {
                    "entity_exists": [{
                        "entity_id": sol_id.to_string()
                    }]
                },
                "effects": {
                    "entity_moved": {
                        "entity_id": sol_id.to_string(),
                        "new_location": cantina_id.to_string()
                    }
                },
                "dependencies": []
            }],
            "metadata": {
                "estimated_duration": 30,
                "confidence": 0.8,
                "alternative_considered": "Auto-generated movement repair"
            }
        }).to_string()
    ));

    let repair_service = PlanRepairService::new(
        entity_manager.clone(),
        mock_ai,
        (*test_app.config).clone(),
    );

    // Create inconsistency analysis for missing movement
    let analysis = InconsistencyAnalysis {
        inconsistency_type: InconsistencyType::MissingMovement,
        narrative_evidence: vec!["Sol walks into the cantina".to_string()],
        ecs_state_summary: "Sol is in Chamber but should be in Cantina".to_string(),
        repair_reasoning: "Sol needs to move to cantina based on narrative".to_string(),
        confidence_score: 0.85,
        detection_timestamp: Utc::now(),
    };

    let original_plan = Plan {
        goal: "Sol orders a drink".to_string(),
        actions: vec![],
        metadata: PlanMetadata {
            estimated_duration: Some(60),
            confidence: 0.8,
            alternative_considered: None,
        },
    };

    // Generate repair plan
    let repair_plan = repair_service.generate_repair_plan(&analysis, &original_plan, user_id).await.unwrap();
    
    // Verify repair plan
    assert!(!repair_plan.actions.is_empty());
    assert!(repair_plan.goal.contains("movement"));
    
    // Test plan combination
    let combined_plan = repair_service.combine_plans(&repair_plan, &original_plan);
    assert!(combined_plan.actions.len() >= repair_plan.actions.len());
    assert!(combined_plan.goal.contains("Repair"));
}

#[tokio::test]
async fn test_plan_repair_service_relationship_repair() {
    // Test repair of missing relationships
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let (sol_id, _chamber_id, _cantina_id, borga_id, user_id) = 
        create_test_entities_for_reconciliation(&entity_manager, &test_app.db_pool).await;

    // Setup mock AI for relationship repair
    let mock_ai = Arc::new(MockAiClient::new_with_response(
        json!({
            "goal": "Repair missing relationship between entities",
            "actions": [{
                "id": "repair_relationship",
                "name": "update_relationship",
                "parameters": {
                    "source_entity_id": sol_id.to_string(),
                    "target_entity_id": borga_id.to_string(),
                    "trust": 0.5,
                    "affection": 0.0,
                    "relationship_type": "acquaintance"
                },
                "preconditions": {
                    "entity_exists": [
                        {"entity_id": sol_id.to_string()},
                        {"entity_id": borga_id.to_string()}
                    ]
                },
                "effects": {
                    "relationship_changed": {
                        "source_entity": sol_id.to_string(),
                        "target_entity": borga_id.to_string(),
                        "trust_change": 0.5,
                        "affection_change": 0.0
                    }
                },
                "dependencies": []
            }],
            "metadata": {
                "estimated_duration": 20,
                "confidence": 0.6,
                "alternative_considered": "Auto-generated relationship repair"
            }
        }).to_string()
    ));

    let repair_service = PlanRepairService::new(
        entity_manager.clone(),
        mock_ai,
        (*test_app.config).clone(),
    );

    // Create inconsistency analysis for missing relationship
    let analysis = InconsistencyAnalysis {
        inconsistency_type: InconsistencyType::MissingRelationship,
        narrative_evidence: vec!["Sol greets his old friend Borga".to_string()],
        ecs_state_summary: "No relationship exists between Sol and Borga".to_string(),
        repair_reasoning: "Sol and Borga need friendship relationship".to_string(),
        confidence_score: 0.90,
        detection_timestamp: Utc::now(),
    };

    let original_plan = Plan {
        goal: "Sol expresses trust in Borga".to_string(),
        actions: vec![],
        metadata: PlanMetadata {
            estimated_duration: Some(30),
            confidence: 0.8,
            alternative_considered: None,
        },
    };

    // Generate repair plan
    let repair_plan = repair_service.generate_repair_plan(&analysis, &original_plan, user_id).await.unwrap();
    
    // Verify repair plan
    assert!(!repair_plan.actions.is_empty());
    assert!(repair_plan.goal.contains("relationship"));
    
    // Verify repair action has relationship parameters
    let repair_action = &repair_plan.actions[0];
    assert_eq!(repair_action.name, ActionName::UpdateRelationship);
    
    // Test plan combination
    let combined_plan = repair_service.combine_plans(&repair_plan, &original_plan);
    assert!(combined_plan.actions.len() >= repair_plan.actions.len());
}

#[tokio::test]
async fn test_plan_repair_service_component_repair() {
    // Test repair of missing components
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // TODO: Implement once PlanRepairService is created
    
    // Expected behavior:
    // 1. Detect missing Reputation component based on pilot context
    // 2. Generate add_component action for Reputation
    // 3. Combine with original component update
    // 4. Validate combined plan succeeds
}

#[tokio::test]
async fn test_enhanced_plan_validator_integration() {
    // Test full integration of enhanced plan validator with repair capability
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let (sol_id, chamber_id, cantina_id, _borga_id, user_id) = 
        create_test_entities_for_reconciliation(&entity_manager, &test_app.db_pool).await;

    // Setup mock AI for inconsistency analysis with high confidence
    let mock_ai = Arc::new(MockAiClient::new_with_response(
        json!({
            "has_inconsistency": true,
            "inconsistency_type": "MissingMovement",
            "confidence_score": 0.85,
            "narrative_evidence": ["Sol walks into cantina"],
            "ecs_state_summary": "Sol in chamber, should be cantina",
            "repair_reasoning": "Movement needed for narrative consistency"
        }).to_string()
    ));

    // Create enhanced validator with repair capability
    let plan_validator = PlanValidatorService::with_repair_capability(
        entity_manager.clone(),
        test_app.redis_client.clone(),
        mock_ai,
        (*test_app.config).clone(),
    );

    // Create a plan that should trigger repair (Sol in wrong location)
    let plan = Plan {
        goal: "Sol orders a drink at the cantina".to_string(),
        actions: vec![
            PlannedAction {
                id: "action_1".to_string(),
                name: ActionName::UpdateEntity,
                parameters: json!({
                    "entity_id": sol_id.to_string(),
                    "component_updates": {"has_drink": true}
                }),
                preconditions: Preconditions {
                    entity_at_location: Some(vec![
                        EntityLocationCheck {
                            entity_id: sol_id.to_string(),
                            location_id: cantina_id.to_string(),
                        }
                    ]),
                    ..Default::default()
                },
                effects: Effects::default(),
                dependencies: vec![],
            }
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(60),
            confidence: 0.8,
            alternative_considered: None,
        },
    };

    // Create chat context supporting repair
    let recent_context = create_mock_chat_messages("missing_movement");

    // Test 1: validate_plan_with_repair method exists and works
    let result = plan_validator.validate_plan_with_repair(&plan, user_id, &recent_context).await;
    assert!(result.is_ok(), "validate_plan_with_repair should not fail");

    // Test 2: Should return RepairableInvalidPlan when appropriate (high confidence)
    match result.unwrap() {
        PlanValidationResult::RepairableInvalid(repairable) => {
            assert_eq!(repairable.original_plan.goal, plan.goal);
            assert!(!repairable.repair_actions.is_empty());
            assert!(repairable.confidence_score > 0.7);
            assert!(matches!(repairable.inconsistency_analysis.inconsistency_type, InconsistencyType::MissingMovement));
        }
        other => panic!("Expected RepairableInvalid but got: {:?}", other),
    }

    // Test 3: Standard validation should fail for comparison
    let standard_result = plan_validator.validate_plan(&plan, user_id).await.unwrap();
    assert!(matches!(standard_result, PlanValidationResult::Invalid(_)));
}

#[tokio::test]
async fn test_confidence_scoring_accuracy() {
    // Test that confidence scoring correctly distinguishes valid repairs from invalid plans
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let (sol_id, _chamber_id, cantina_id, _borga_id, user_id) = 
        create_test_entities_for_reconciliation(&entity_manager, &test_app.db_pool).await;

    // Test Case 1: High confidence - Clear narrative evidence
    let high_confidence_ai = Arc::new(MockAiClient::new_with_response(
        json!({
            "has_inconsistency": true,
            "inconsistency_type": "MissingMovement",
            "confidence_score": 0.95,
            "narrative_evidence": ["Sol walks into cantina", "Sol is now in the cantina"],
            "ecs_state_summary": "Sol in chamber, narrative says cantina",
            "repair_reasoning": "Clear movement indicated in narrative"
        }).to_string()
    ));

    let high_confidence_validator = PlanValidatorService::with_repair_capability(
        entity_manager.clone(),
        test_app.redis_client.clone(),
        high_confidence_ai,
        (*test_app.config).clone(),
    );

    // Test Case 2: Low confidence - Ambiguous evidence
    let low_confidence_ai = Arc::new(MockAiClient::new_with_response(
        json!({
            "has_inconsistency": true,
            "inconsistency_type": "OutdatedState",
            "confidence_score": 0.45,
            "narrative_evidence": ["Ambiguous statement"],
            "ecs_state_summary": "Unclear state",
            "repair_reasoning": "Uncertain if repair needed"
        }).to_string()
    ));

    let low_confidence_validator = PlanValidatorService::with_repair_capability(
        entity_manager.clone(),
        test_app.redis_client.clone(),
        low_confidence_ai,
        (*test_app.config).clone(),
    );

    let plan = Plan {
        goal: "Test confidence scoring".to_string(),
        actions: vec![
            PlannedAction {
                id: "action_1".to_string(),
                name: ActionName::UpdateEntity,
                parameters: json!({"entity_id": sol_id.to_string()}),
                preconditions: Preconditions {
                    entity_at_location: Some(vec![
                        EntityLocationCheck {
                            entity_id: sol_id.to_string(),
                            location_id: cantina_id.to_string(),
                        }
                    ]),
                    ..Default::default()
                },
                effects: Effects::default(),
                dependencies: vec![],
            }
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(30),
            confidence: 0.8,
            alternative_considered: None,
        },
    };

    let context = create_mock_chat_messages("missing_movement");

    // High confidence should produce RepairableInvalid
    let high_result = high_confidence_validator.validate_plan_with_repair(&plan, user_id, &context).await.unwrap();
    match high_result {
        PlanValidationResult::RepairableInvalid(repairable) => {
            assert!(repairable.confidence_score > 0.7);
        }
        _ => panic!("High confidence should produce RepairableInvalid"),
    }

    // Low confidence should produce standard Invalid
    let low_result = low_confidence_validator.validate_plan_with_repair(&plan, user_id, &context).await.unwrap();
    match low_result {
        PlanValidationResult::Invalid(_) => {
            // Expected for low confidence
        }
        PlanValidationResult::RepairableInvalid(repairable) => {
            assert!(repairable.confidence_score <= 0.7, "Low confidence should not be repairable");
        }
        _ => panic!("Low confidence should produce Invalid result"),
    }
}

#[tokio::test]
async fn test_repair_validation_prevents_new_inconsistencies() {
    // Test that repair plans themselves are validated to prevent new problems
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // TODO: Implement safety checks for repair plans
    
    // Expected behavior:
    // 1. Repair plans must pass validation before being accepted
    // 2. Circular repair detection (repair A requires repair B requires repair A)
    // 3. Invalid repair actions are rejected
}

#[tokio::test]
async fn test_repair_caching_and_performance() {
    // Test that repair analysis results are cached appropriately
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // TODO: Implement caching tests
    
    // Expected behavior:
    // 1. Repair analysis results are cached with user isolation
    // 2. Cache invalidation works when ECS state changes
    // 3. Performance is acceptable for real-time chat
}

#[tokio::test]
async fn test_end_to_end_missing_movement_scenario() {
    // Complete end-to-end test for missing movement repair
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let (sol_id, chamber_id, cantina_id, _borga_id, user_id) = 
        create_test_entities_for_reconciliation(&entity_manager, &test_app.db_pool).await;
    
    // Verify initial state: Sol is in chamber
    let sol_entity = entity_manager.get_entity(user_id, sol_id).await.unwrap().unwrap();
    let parent_link = sol_entity.components.iter()
        .find(|c| c.component_type == "ParentLink")
        .expect("Sol should have ParentLink component");
    let parent_data: ParentLinkComponent = 
        serde_json::from_value(parent_link.component_data.clone()).unwrap();
    assert_eq!(parent_data.parent_entity_id, chamber_id);
    
    // TODO: Once repair system is implemented:
    // 1. Run enhanced validation with repair
    // 2. Verify RepairableInvalidPlan is returned
    // 3. Execute repair actions
    // 4. Verify Sol is now in cantina
    // 5. Verify original plan now validates successfully
}

#[tokio::test]
async fn test_end_to_end_missing_relationship_scenario() {
    // Complete end-to-end test for missing relationship repair
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let (sol_id, _chamber_id, _cantina_id, borga_id, user_id) = 
        create_test_entities_for_reconciliation(&entity_manager, &test_app.db_pool).await;
    
    // Verify initial state: No relationship between Sol and Borga
    let relationships = entity_manager.get_relationships(user_id, sol_id).await.unwrap();
    assert!(!relationships.iter().any(|r| r.target_entity_id == borga_id));
    
    // TODO: Once repair system is implemented:
    // 1. Run enhanced validation with repair for relationship update
    // 2. Verify RepairableInvalidPlan with MissingRelationship
    // 3. Execute repair actions (create base relationship)
    // 4. Execute original plan (update relationship trust)
    // 5. Verify relationship exists with appropriate trust level
}

#[tokio::test]
async fn test_end_to_end_missing_component_scenario() {
    // Complete end-to-end test for missing component repair
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let (sol_id, _chamber_id, _cantina_id, _borga_id, user_id) = 
        create_test_entities_for_reconciliation(&entity_manager, &test_app.db_pool).await;
    
    // Verify initial state: Sol has no Reputation component
    let sol_entity = entity_manager.get_entity(user_id, sol_id).await.unwrap().unwrap();
    assert!(!sol_entity.components.iter().any(|c| c.component_type == "Reputation"));
    
    // TODO: Once repair system is implemented:
    // 1. Run enhanced validation with repair for component update
    // 2. Verify RepairableInvalidPlan with MissingComponent
    // 3. Execute repair actions (add Reputation component)
    // 4. Execute original plan (update pilot_skill)
    // 5. Verify Reputation component exists with updated data
}