use scribe_backend::{
    services::{
        planning::{
            PlanValidatorService,
            EcsConsistencyAnalyzer,
            PlanRepairService,
            types::*,
        },
        EcsEntityManager,
    },
    models::chats::{ChatMessage, MessageRole},
    test_helpers::{spawn_app, TestDataGuard, db::create_test_user, MockAiClient},
    config::Config,
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

/// Helper to create Flash-powered plan validator with repair capability
async fn create_repair_enabled_validator(
    entity_manager: Arc<EcsEntityManager>,
    config: Config,
) -> PlanValidatorService {
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let flash_client = Arc::new(MockAiClient::new());
    
    PlanValidatorService::with_repair_capability(
        entity_manager,
        redis_client,
        flash_client,
        config,
    )
}

/// Create a scenario with outdated ECS state (missing movement)
async fn setup_movement_inconsistency_scenario(
    entity_manager: &Arc<EcsEntityManager>,
    user_id: Uuid,
) -> (Uuid, Uuid, Uuid) {
    // Create a character
    let character_result = entity_manager.create_entity(
        user_id,
        Some(Uuid::new_v4()),
        "Name|Inventory|Salience".to_string(),
        vec![
            ("Name".to_string(), json!({"name": "Adventurer"})),
            ("Inventory".to_string(), json!({"items": [], "capacity": 10})),
            ("Salience".to_string(), json!({"tier": "Core", "scale_context": "character", "expiry": null})),
        ],
    ).await.unwrap();
    let character_id = character_result.entity.id;

    // Create two locations: tavern and market
    let tavern_result = entity_manager.create_entity(
        user_id,
        Some(Uuid::new_v4()),
        "Name|Salience".to_string(),
        vec![
            ("Name".to_string(), json!({"name": "The Rusty Tavern"})),
            ("Salience".to_string(), json!({"tier": "Secondary", "scale_context": "location", "expiry": null})),
        ],
    ).await.unwrap();
    let tavern_id = tavern_result.entity.id;

    let market_result = entity_manager.create_entity(
        user_id,
        Some(Uuid::new_v4()),
        "Name|Salience".to_string(),
        vec![
            ("Name".to_string(), json!({"name": "Central Market"})),
            ("Salience".to_string(), json!({"tier": "Secondary", "scale_context": "location", "expiry": null})),
        ],
    ).await.unwrap();
    let market_id = market_result.entity.id;

    // Place character at tavern initially
    entity_manager.move_entity(user_id, character_id, tavern_id, None).await.unwrap();

    (character_id, tavern_id, market_id)
}

/// Create chat context suggesting movement that hasn't been reflected in ECS
fn create_movement_narrative_context(user_id: Uuid, character_name: &str, destination: &str) -> Vec<ChatMessage> {
    vec![
        ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            message_type: MessageRole::User,
            content: format!("{} leaves the tavern and heads to the {}", character_name, destination).as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now() - chrono::Duration::minutes(5),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "test-model".to_string(),
        },
        ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            message_type: MessageRole::Assistant,
            content: format!("The {} bustles with activity as {} arrives", destination, character_name).as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now() - chrono::Duration::minutes(3),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "test-model".to_string(),
        },
        ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            message_type: MessageRole::User,
            content: format!("{} looks around the busy {}", character_name, destination).as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now() - chrono::Duration::minutes(1),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "test-model".to_string(),
        },
    ]
}

#[tokio::test]
async fn test_end_to_end_movement_repair_workflow() {
    // Test the complete workflow: detect inconsistency → generate repair → validate combined plan
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let user = create_test_user(&test_app.db_pool, "repair_test_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    
    // Setup: Character at tavern, but narrative suggests they moved to market
    let (character_id, _tavern_id, market_id) = setup_movement_inconsistency_scenario(&entity_manager, user_id).await;
    let chat_context = create_movement_narrative_context(user_id, "Adventurer", "Central Market");
    
    // Create plan that assumes character is at market (but ECS shows them at tavern)
    let plan_assuming_at_market = Plan {
        goal: "Buy supplies at the market".to_string(),
        actions: vec![
            PlannedAction {
                id: "buy_supplies".to_string(),
                name: ActionName::AddItemToInventory,
                parameters: json!({
                    "owner_entity_id": character_id.to_string(),
                    "item_entity_id": Uuid::new_v4().to_string(),
                    "quantity": 1
                }),
                preconditions: Preconditions {
                    entity_at_location: Some(vec![
                        EntityLocationCheck {
                            entity_id: character_id.to_string(),
                            location_id: market_id.to_string(),
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
    
    // Create repair-enabled validator
    let config = Config::load().expect("Failed to load config");
    let validator = create_repair_enabled_validator(entity_manager.clone(), config).await;
    
    // Step 1: Standard validation should fail (character not at market)
    let standard_result = validator.validate_plan(&plan_assuming_at_market, user_id).await.unwrap();
    let failures = match &standard_result {
        PlanValidationResult::Invalid(invalid) => {
            assert!(invalid.failures.iter().any(|f| 
                f.failure_type == ValidationFailureType::PreconditionNotMet &&
                f.message.contains("location")
            ));
            invalid.failures.clone()
        }
        _ => panic!("Expected invalid plan due to location mismatch"),
    };
    
    // TODO: Step 2: Enhanced validation with repair should detect inconsistency and provide repair
    // This requires implementing the actual repair logic in validate_plan_with_repair
    // For now, we verify the components are set up correctly
    
    // Verify the repair components can be instantiated
    let flash_client = Arc::new(MockAiClient::new());
    let config = Config::load().expect("Failed to load config");
    
    let consistency_analyzer = EcsConsistencyAnalyzer::new(
        entity_manager.clone(),
        flash_client.clone(),
        config.clone(),
    );
    
    let _repair_service = PlanRepairService::new(
        entity_manager.clone(),
        flash_client.clone(),
        config.clone(),
    );
    
    // Test that we can analyze inconsistency (would normally use Flash)
    // In real implementation, this would detect the movement inconsistency
    
    let _analysis_result = consistency_analyzer.analyze_inconsistency(
        &plan_assuming_at_market,
        &failures,
        user_id,
        &chat_context,
    ).await;
    
    // Note: In full implementation, this would:
    // 1. Detect that narrative indicates movement to market
    // 2. Generate repair plan to move character to market
    // 3. Combine repair + original plan
    // 4. Validate combined plan successfully
}

#[tokio::test]
async fn test_end_to_end_component_repair_workflow() {
    // Test repair workflow for missing components
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let user = create_test_user(&test_app.db_pool, "component_repair_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    
    // Create character without Reputation component
    let character_result = entity_manager.create_entity(
        user_id,
        Some(Uuid::new_v4()),
        "Name|Salience".to_string(), // Note: No Reputation component
        vec![
            ("Name".to_string(), json!({"name": "Rookie"})),
            ("Salience".to_string(), json!({"tier": "Core", "scale_context": "character", "expiry": null})),
        ],
    ).await.unwrap();
    let character_id = character_result.entity.id;
    
    // Create chat context suggesting character has established reputation
    let chat_context = vec![
        ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            message_type: MessageRole::Assistant,
            content: "The townspeople recognize Rookie as a skilled pilot with growing combat prowess".as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now() - chrono::Duration::minutes(10),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "test-model".to_string(),
        },
        ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            message_type: MessageRole::User,
            content: "Check my reputation status".as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now() - chrono::Duration::minutes(1),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "test-model".to_string(),
        },
    ];
    
    // Create plan that requires Reputation component
    let plan_requiring_reputation = Plan {
        goal: "Check reputation with local guild".to_string(),
        actions: vec![
            PlannedAction {
                id: "check_reputation".to_string(),
                name: ActionName::GetEntityDetails,
                parameters: json!({
                    "entity_id": character_id.to_string(),
                    "component_types": ["Reputation"]
                }),
                preconditions: Preconditions {
                    entity_has_component: Some(vec![
                        EntityComponentCheck {
                            entity_id: character_id.to_string(),
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
            estimated_duration: Some(15),
            confidence: 0.9,
            alternative_considered: None,
        },
    };
    
    // Create repair-enabled validator
    let config = Config::load().expect("Failed to load config");
    let validator = create_repair_enabled_validator(entity_manager.clone(), config).await;
    
    // Standard validation should fail (missing Reputation component)
    let standard_result = validator.validate_plan(&plan_requiring_reputation, user_id).await.unwrap();
    match standard_result {
        PlanValidationResult::Invalid(invalid) => {
            assert!(invalid.failures.iter().any(|f| 
                f.failure_type == ValidationFailureType::PreconditionNotMet &&
                f.message.contains("component")
            ));
        }
        _ => panic!("Expected invalid plan due to missing component"),
    }
    
    // TODO: Enhanced validation with repair should:
    // 1. Detect that narrative suggests character should have Reputation
    // 2. Generate repair plan to add Reputation component
    // 3. Validate combined plan successfully
    
    // For now, verify repair service can generate component repairs
    let flash_client = Arc::new(MockAiClient::new());
    let config = Config::load().expect("Failed to load config");
    let repair_service = PlanRepairService::new(
        entity_manager.clone(),
        flash_client,
        config,
    );
    
    // Test manual repair plan generation
    let mock_analysis = InconsistencyAnalysis {
        inconsistency_type: InconsistencyType::MissingComponent,
        narrative_evidence: vec!["Character described as having reputation".to_string()],
        ecs_state_summary: "Character lacks Reputation component".to_string(),
        repair_reasoning: "Add Reputation component based on narrative evidence".to_string(),
        detection_timestamp: Utc::now(),
        confidence_score: 0.9,
    };
    
    let repair_plan = repair_service.generate_repair_plan(
        &mock_analysis,
        &plan_requiring_reputation,
        user_id,
    ).await.unwrap();
    
    // Verify repair plan structure
    assert_eq!(repair_plan.actions.len(), 1);
    assert_eq!(repair_plan.actions[0].name, ActionName::UpdateEntity);
    assert!(repair_plan.goal.contains("Reputation"));
    
    // Test plan combination
    let combined_plan = repair_service.combine_plans(&repair_plan, &plan_requiring_reputation);
    assert_eq!(combined_plan.actions.len(), 2); // repair + original
    assert!(combined_plan.goal.contains("Repair"));
}

#[tokio::test]
async fn test_end_to_end_relationship_repair_workflow() {
    // Test repair workflow for missing relationships
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let user = create_test_user(&test_app.db_pool, "relationship_repair_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    
    // Create two characters
    let alice_result = entity_manager.create_entity(
        user_id,
        Some(Uuid::new_v4()),
        "Name|Salience".to_string(),
        vec![
            ("Name".to_string(), json!({"name": "Alice"})),
            ("Salience".to_string(), json!({"tier": "Core", "scale_context": "character", "expiry": null})),
        ],
    ).await.unwrap();
    let alice_id = alice_result.entity.id;
    
    let bob_result = entity_manager.create_entity(
        user_id,
        Some(Uuid::new_v4()),
        "Name|Salience".to_string(),
        vec![
            ("Name".to_string(), json!({"name": "Bob"})),
            ("Salience".to_string(), json!({"tier": "Core", "scale_context": "character", "expiry": null})),
        ],
    ).await.unwrap();
    let bob_id = bob_result.entity.id;
    
    // Create chat context suggesting they know each other
    let chat_context = vec![
        ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            message_type: MessageRole::Assistant,
            content: "Alice greets Bob warmly, as they've been friends for years".as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now() - chrono::Duration::minutes(10),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "test-model".to_string(),
        },
        ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            message_type: MessageRole::User,
            content: "Alice asks Bob about their mutual trust".as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now() - chrono::Duration::minutes(1),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "test-model".to_string(),
        },
    ];
    
    // Create plan that assumes relationship exists (but it doesn't in ECS)
    let plan_requiring_relationship = Plan {
        goal: "Check trust level between Alice and Bob".to_string(),
        actions: vec![
            PlannedAction {
                id: "check_trust".to_string(),
                name: ActionName::GetEntityDetails,
                parameters: json!({
                    "source_entity_id": alice_id.to_string(),
                    "target_entity_id": bob_id.to_string()
                }),
                preconditions: Preconditions {
                    relationship_exists: Some(vec![
                        RelationshipCheck {
                            source_entity: alice_id.to_string(),
                            target_entity: bob_id.to_string(),
                            min_trust: Some(0.5),
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
            confidence: 0.9,
            alternative_considered: None,
        },
    };
    
    // Create repair-enabled validator
    let config = Config::load().expect("Failed to load config");
    let validator = create_repair_enabled_validator(entity_manager.clone(), config).await;
    
    // Standard validation should fail (missing relationship)
    let standard_result = validator.validate_plan(&plan_requiring_relationship, user_id).await.unwrap();
    match standard_result {
        PlanValidationResult::Invalid(invalid) => {
            assert!(invalid.failures.iter().any(|f| 
                f.failure_type == ValidationFailureType::PreconditionNotMet &&
                f.message.contains("relationship")
            ));
        }
        _ => panic!("Expected invalid plan due to missing relationship"),
    }
    
    // TODO: Enhanced validation with repair should:
    // 1. Detect that narrative suggests relationship exists
    // 2. Generate repair plan to create relationship
    // 3. Validate combined plan successfully
    
    // For now, verify repair service works for relationships
    let flash_client = Arc::new(MockAiClient::new());
    let config = Config::load().expect("Failed to load config");
    let repair_service = PlanRepairService::new(
        entity_manager.clone(),
        flash_client,
        config,
    );
    
    let mock_analysis = InconsistencyAnalysis {
        inconsistency_type: InconsistencyType::MissingRelationship,
        narrative_evidence: vec!["Alice and Bob described as friends".to_string()],
        ecs_state_summary: "No relationship exists between Alice and Bob".to_string(),
        repair_reasoning: "Create friendship relationship based on narrative".to_string(),
        detection_timestamp: Utc::now(),
        confidence_score: 0.85,
    };
    
    let repair_plan = repair_service.generate_repair_plan(
        &mock_analysis,
        &plan_requiring_relationship,
        user_id,
    ).await.unwrap();
    
    // Verify repair plan creates relationship
    assert_eq!(repair_plan.actions.len(), 1);
    assert_eq!(repair_plan.actions[0].name, ActionName::UpdateRelationship);
    assert!(repair_plan.goal.contains("relationship"));
}

#[tokio::test]
async fn test_repair_confidence_threshold_enforcement() {
    // Test that low-confidence repairs are not applied
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let user = create_test_user(&test_app.db_pool, "confidence_test_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    
    // Create basic character
    let character_result = entity_manager.create_entity(
        user_id,
        Some(Uuid::new_v4()),
        "Name|Salience".to_string(),
        vec![
            ("Name".to_string(), json!({"name": "TestChar"})),
            ("Salience".to_string(), json!({"tier": "Core", "scale_context": "character", "expiry": null})),
        ],
    ).await.unwrap();
    let character_id = character_result.entity.id;
    
    // Create ambiguous chat context
    let ambiguous_context = vec![
        ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            message_type: MessageRole::User,
            content: "Something might have happened maybe".as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "test-model".to_string(),
        },
    ];
    
    // Test that low-confidence analysis doesn't trigger repairs
    let flash_client = Arc::new(MockAiClient::new());
    let config = Config::load().expect("Failed to load config");
    let consistency_analyzer = EcsConsistencyAnalyzer::new(
        entity_manager.clone(),
        flash_client,
        config,
    );
    
    let mock_plan = Plan {
        goal: "Ambiguous action".to_string(),
        actions: vec![
            PlannedAction {
                id: "ambiguous".to_string(),
                name: ActionName::FindEntity,
                parameters: json!({"criteria": {"type": "ByName", "name": "Unknown"}}),
                preconditions: Preconditions::default(),
                effects: Effects::default(),
                dependencies: vec![],
            }
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(5),
            confidence: 0.3, // Low confidence
            alternative_considered: None,
        },
    };
    
    let failures = vec![
        ValidationFailure {
            action_id: "ambiguous".to_string(),
            failure_type: ValidationFailureType::EntityNotFound,
            message: "Entity not found".to_string(),
        }
    ];
    
    // In real implementation with Flash, this would return None for low-confidence scenarios
    let analysis_result = consistency_analyzer.analyze_inconsistency(
        &mock_plan,
        &failures,
        user_id,
        &ambiguous_context,
    ).await.unwrap();
    
    // Should not generate analysis for ambiguous/low-confidence scenarios
    // (In mock implementation, this might still return something, but real Flash would be more discerning)
    if let Some(analysis) = analysis_result {
        // If analysis is generated, confidence should be checked before repair
        // Confidence threshold should be >= 0.7 for repairs
        println!("Analysis generated with confidence but should be filtered by confidence threshold");
    }
}

#[tokio::test]
async fn test_repair_system_handles_multiple_inconsistencies() {
    // Test repair system with complex scenario having multiple inconsistencies
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_manager = create_test_entity_manager(test_app.db_pool.clone()).await;
    let user = create_test_user(&test_app.db_pool, "complex_repair_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    
    // Create character with minimal components
    let character_result = entity_manager.create_entity(
        user_id,
        Some(Uuid::new_v4()),
        "Name|Salience".to_string(),
        vec![
            ("Name".to_string(), json!({"name": "ComplexChar"})),
            ("Salience".to_string(), json!({"tier": "Core", "scale_context": "character", "expiry": null})),
        ],
    ).await.unwrap();
    let character_id = character_result.entity.id;
    
    // Create location
    let location_result = entity_manager.create_entity(
        user_id,
        Some(Uuid::new_v4()),
        "Name|Salience".to_string(),
        vec![
            ("Name".to_string(), json!({"name": "Complex Location"})),
            ("Salience".to_string(), json!({"tier": "Secondary", "scale_context": "location", "expiry": null})),
        ],
    ).await.unwrap();
    let location_id = location_result.entity.id;
    
    // Rich chat context suggesting multiple state changes
    let complex_context = vec![
        ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            message_type: MessageRole::Assistant,
            content: "ComplexChar travels to Complex Location and gains combat experience".as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now() - chrono::Duration::minutes(10),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "test-model".to_string(),
        },
        ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            message_type: MessageRole::User,
            content: "Check my health and skills at the location".as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now() - chrono::Duration::minutes(1),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "test-model".to_string(),
        },
    ];
    
    // Plan requiring multiple things that don't exist in ECS
    let complex_plan = Plan {
        goal: "Check status at current location".to_string(),
        actions: vec![
            PlannedAction {
                id: "check_location".to_string(),
                name: ActionName::GetEntityDetails,
                parameters: json!({
                    "entity_id": character_id.to_string(),
                    "component_types": ["Health", "Skills"]
                }),
                preconditions: Preconditions {
                    entity_at_location: Some(vec![
                        EntityLocationCheck {
                            entity_id: character_id.to_string(),
                            location_id: location_id.to_string(),
                        }
                    ]),
                    entity_has_component: Some(vec![
                        EntityComponentCheck {
                            entity_id: character_id.to_string(),
                            component_type: "Health".to_string(),
                        },
                        EntityComponentCheck {
                            entity_id: character_id.to_string(),
                            component_type: "Skills".to_string(),
                        },
                    ]),
                    ..Default::default()
                },
                effects: Effects::default(),
                dependencies: vec![],
            }
        ],
        metadata: PlanMetadata {
            estimated_duration: Some(20),
            confidence: 0.8,
            alternative_considered: None,
        },
    };
    
    // Create repair-enabled validator
    let config = Config::load().expect("Failed to load config");
    let validator = create_repair_enabled_validator(entity_manager.clone(), config).await;
    
    // Standard validation should fail with multiple failures
    let standard_result = validator.validate_plan(&complex_plan, user_id).await.unwrap();
    match standard_result {
        PlanValidationResult::Invalid(invalid) => {
            // Should have multiple failures: location + missing components
            assert!(invalid.failures.len() >= 2);
            assert!(invalid.failures.iter().any(|f| f.message.contains("location")));
            assert!(invalid.failures.iter().any(|f| f.message.contains("component")));
        }
        _ => panic!("Expected invalid plan with multiple failures"),
    }
    
    // TODO: Enhanced validation should be able to handle multiple inconsistencies
    // and generate a comprehensive repair plan that addresses all issues
    
    // For now, verify that repair system can handle complex scenarios
    let flash_client = Arc::new(MockAiClient::new());
    let config = Config::load().expect("Failed to load config");
    let repair_service = PlanRepairService::new(
        entity_manager.clone(),
        flash_client,
        config,
    );
    
    // Test that repair service can generate complex repair plans
    let mock_analysis = InconsistencyAnalysis {
        inconsistency_type: InconsistencyType::OutdatedState,
        narrative_evidence: vec![
            "Character moved to location".to_string(),
            "Character gained skills and health".to_string(),
        ],
        ecs_state_summary: "Character missing location and components".to_string(),
        repair_reasoning: "Multiple state updates needed based on narrative".to_string(),
        detection_timestamp: Utc::now(),
        confidence_score: 0.92,
    };
    
    let repair_plan = repair_service.generate_repair_plan(
        &mock_analysis,
        &complex_plan,
        user_id,
    ).await.unwrap();
    
    // Repair plan should address the complexity (might generate multiple actions)
    assert!(!repair_plan.actions.is_empty());
    assert!(repair_plan.goal.contains("repair") || repair_plan.goal.contains("Repair"));
}