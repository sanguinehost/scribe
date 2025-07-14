use scribe_backend::{
    services::{
        planning::{
            PlanValidatorService,
            types::*,
        },
        EcsEntityManager,
    },
    models::{
        ecs::*,
        chats::{ChatMessage, MessageRole},
    },
    test_helpers::{spawn_app, TestDataGuard, db::create_test_user},
    PgPool,
};
use std::sync::Arc;
use uuid::Uuid;
use chrono::Utc;

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
    // Create test user
    let user = create_test_user(db_pool, "reconciliation_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;

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
    let test_app = spawn_app(false, false, false).await;
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
    let test_app = spawn_app(false, false, false).await;
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
    let test_app = spawn_app(false, false, false).await;
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
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // This test will validate the repair action generation logic
    // TODO: Implement once PlanRepairService is created
    
    // Expected behavior:
    // 1. Detect that Sol should be in cantina based on chat context
    // 2. Generate move_entity action from chamber to cantina
    // 3. Combine with original plan
    // 4. Validate combined plan succeeds
}

#[tokio::test]
async fn test_plan_repair_service_relationship_repair() {
    // Test repair of missing relationships
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // TODO: Implement once PlanRepairService is created
    
    // Expected behavior:
    // 1. Detect missing friendship based on "old friend" in chat
    // 2. Generate create_relationship action with appropriate trust level
    // 3. Combine with original relationship update
    // 4. Validate combined plan succeeds
}

#[tokio::test]
async fn test_plan_repair_service_component_repair() {
    // Test repair of missing components
    let test_app = spawn_app(false, false, false).await;
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
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // TODO: Implement once enhanced PlanValidatorService is complete
    
    // Expected behavior:
    // 1. validate_plan_with_repair method exists and works
    // 2. Returns RepairableInvalidPlan when appropriate
    // 3. Returns standard Invalid when confidence is low
    // 4. Returns Valid when no repairs needed
}

#[tokio::test]
async fn test_confidence_scoring_accuracy() {
    // Test that confidence scoring correctly distinguishes valid repairs from invalid plans
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // TODO: Implement comprehensive confidence scoring tests
    
    // Test cases:
    // High confidence: Clear narrative evidence for ECS inconsistency
    // Low confidence: Ambiguous or contradictory evidence  
    // Zero confidence: Genuinely invalid plan with no repair possibility
}

#[tokio::test]
async fn test_repair_validation_prevents_new_inconsistencies() {
    // Test that repair plans themselves are validated to prevent new problems
    let test_app = spawn_app(false, false, false).await;
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
    let test_app = spawn_app(false, false, false).await;
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
    let test_app = spawn_app(false, false, false).await;
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
    let test_app = spawn_app(false, false, false).await;
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
    let test_app = spawn_app(false, false, false).await;
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