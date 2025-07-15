// NOTE: These integration tests validate that all systems from Epic 0-3 work together

use std::sync::Arc;
use uuid::Uuid;
use serde_json::json;

use scribe_backend::{
    errors::AppError,
    models::{
        chats::{ChatMessage, MessageRole},
    },
    services::{
        planning::{
            PlanningService, PlanValidatorService,
            types::*,
        },
        EcsEntityManager,
        context_assembly_engine::{EnrichedContext, SubGoal, ValidatedPlan, StrategicDirective, EntityContext, SpatialContext, TemporalContext},
    },
    test_helpers::{spawn_app_permissive_rate_limiting, TestDataGuard, MockAiClient},
    auth::session_dek::SessionDek,
    PgPool,
};
use chrono::Utc;
use std::collections::HashMap;

/// Test Suite for Task 3.5: Planning and Validation Integration Tests
/// 
/// NOTE: These integration tests are currently disabled as they depend on:
/// 1. Full repair system implementation (Task 3.4)
/// 2. Updated PlanningService API that uses EnrichedContext
/// 3. Complete MockAiClient interface
/// 
/// This comprehensive test suite validates that all systems from Epic 0-3 work together:
/// - Epic 0: World Ontology (hierarchical spatial model, salience tiers, AI-driven tools)
/// - Epic 1: Flash integration and AI-driven logic conversion  
/// - Epic 2: Tactical toolkit (world interaction tools)
/// - Epic 3: Planning & Reasoning Cortex with ECS State Reconciliation
/// 
/// These tests ensure the entire "Planning & Reasoning Cortex" is ready for Epic 4 agent implementation.
/// TODO: Re-enable these tests once the repair system and new planning interfaces are complete.

/// Helper to create test entity manager
async fn create_test_entity_manager(db_pool: Arc<PgPool>) -> Arc<EcsEntityManager> {
    let redis_client = Arc::new(
        redis::Client::open("redis://127.0.0.1:6379/")
            .expect("Failed to create Redis client for tests")
    );
    
    Arc::new(EcsEntityManager::new(
        db_pool,
        redis_client,
        None,
    ))
}

/// Helper to create a test entity with a given name and archetype
async fn create_test_entity(
    entity_manager: &Arc<EcsEntityManager>,
    user_id: Uuid,
    name: &str,
    entity_type: &str,
) -> Uuid {
    let entity_id = Uuid::new_v4();
    let mut components = vec![];
    
    // Add name component if provided
    if !name.is_empty() {
        components.push((
            "Name".to_string(),
            json!({
                "name": name
            })
        ));
    }
    
    // Add archetype-specific components
    match entity_type {
        "Location" => {
            components.push((
                "SpatialArchetype".to_string(),
                json!({
                    "archetype": "Location",
                    "scale": "Planetary"
                })
            ));
        }
        "Character" => {
            components.push((
                "Character".to_string(),
                json!({
                    "character_type": "NPC"
                })
            ));
        }
        _ => {}
    }
    
    entity_manager.create_entity(
        user_id,
        Some(entity_id),
        entity_type.to_string(),
        components,
    )
    .await
    .expect("Failed to create test entity");
    
    entity_id
}

/// Create a minimal test user manually
async fn create_test_user(db_pool: &PgPool, username: String, _password: String) -> Result<TestUser, AppError> {
    Ok(TestUser {
        id: Uuid::new_v4(),
        username,
    })
}

/// Minimal user for testing
struct TestUser {
    pub id: Uuid,
    pub username: String,
}

/// Helper to create enriched context for testing
fn create_test_enriched_context(
    _entities: Vec<(Uuid, String, String)>, // (id, name, type)
    _relationships: Vec<(Uuid, Uuid, String)>, // (from, to, relationship_type)
) -> EnrichedContext {
    // Create a minimal EnrichedContext for testing
    EnrichedContext {
        strategic_directive: None,
        validated_plan: ValidatedPlan {
            plan_id: Uuid::new_v4(),
            steps: vec![],
            preconditions_met: true,
            causal_consistency_verified: true,
            entity_dependencies: vec![],
        },
        current_sub_goal: SubGoal {
            goal_id: Uuid::new_v4(),
            description: "Test sub-goal".to_string(),
            actionable_directive: "Test directive".to_string(),
            required_entities: vec![],
            success_criteria: vec![],
            context_requirements: vec![],
            priority_level: 1.0,
        },
        relevant_entities: vec![],
        spatial_context: None,
        temporal_context: None,
    }
}

/// Helper to setup mock AI for valid plan generation
fn setup_mock_ai_for_valid_plan(castle_id: Uuid, hero_id: Uuid, dragon_id: Uuid) -> MockAiClient {
    let plan_json = json!({
        "goal": "Hero defeats the dragon",
        "actions": [
            {
                "id": "action_1",
                "name": "move_entity",
                "parameters": {
                    "entity_id": hero_id,
                    "target_location_id": castle_id
                },
                "preconditions": {
                    "entity_exists": [{
                        "entity_id": hero_id.to_string(),
                        "entity_name": "Hero"
                    }],
                    "entity_at_location": []
                },
                "effects": {
                    "entity_location_changes": [{
                        "entity_id": hero_id.to_string(),
                        "new_location_id": castle_id.to_string()
                    }]
                },
                "dependencies": []
            },
            {
                "id": "action_2",
                "name": "update_entity",
                "parameters": {
                    "entity_id": dragon_id,
                    "component_updates": {
                        "state": "defeated"
                    }
                },
                "preconditions": {
                    "entity_at_location": [
                        {
                            "entity_id": hero_id.to_string(),
                            "location_id": castle_id.to_string()
                        },
                        {
                            "entity_id": dragon_id.to_string(),
                            "location_id": castle_id.to_string()
                        }
                    ]
                },
                "effects": {
                    "entity_component_changes": [{
                        "entity_id": dragon_id.to_string(),
                        "component_changes": {
                            "state": "defeated"
                        }
                    }]
                },
                "dependencies": ["action_1"]
            }
        ],
        "metadata": {
            "estimated_duration": 300,
            "confidence": 0.9,
            "alternative_considered": "Direct combat without movement"
        }
    });
    
    MockAiClient::new_with_response(plan_json.to_string())
}

/// Helper to setup mock AI for invalid plan generation (missing preconditions)
fn setup_mock_ai_for_invalid_plan(castle_id: Uuid, hero_id: Uuid, dragon_id: Uuid) -> MockAiClient {
    let plan_json = json!({
        "goal": "Hero defeats the dragon",
        "actions": [
            {
                "id": "action_1",
                "name": "update_entity",
                "parameters": {
                    "entity_id": dragon_id,
                    "component_updates": {
                        "state": "defeated"
                    }
                },
                "preconditions": {
                    "entity_at_location": [
                        {
                            "entity_id": hero_id.to_string(),
                            "location_id": castle_id.to_string()
                        },
                        {
                            "entity_id": dragon_id.to_string(),
                            "location_id": castle_id.to_string()
                        }
                    ]
                },
                "effects": {
                    "entity_component_changes": [{
                        "entity_id": dragon_id.to_string(),
                        "component_changes": {
                            "state": "defeated"
                        }
                    }]
                },
                "dependencies": []
            }
        ],
        "metadata": {
            "estimated_duration": 100,
            "confidence": 0.85,
            "alternative_considered": null
        }
    });
    
    MockAiClient::new_with_response(plan_json.to_string())
}

/// Helper to setup mock AI for plan repair
fn setup_mock_ai_for_repair(castle_id: Uuid, hero_id: Uuid, dragon_id: Uuid, village_id: Uuid) -> MockAiClient {
    let repair_json = json!({
        "goal": "Hero defeats the dragon",
        "actions": [
            {
                "id": "action_1",
                "name": "move_entity",
                "parameters": {
                    "entity_id": hero_id,
                    "target_location_id": castle_id
                },
                "preconditions": {
                    "entity_exists": [{
                        "entity_id": hero_id.to_string(),
                        "entity_name": "Hero"
                    }],
                    "entity_at_location": [{
                        "entity_id": hero_id.to_string(),
                        "location_id": village_id.to_string()
                    }]
                },
                "effects": {
                    "entity_location_changes": [{
                        "entity_id": hero_id.to_string(),
                        "new_location_id": castle_id.to_string()
                    }]
                },
                "dependencies": []
            },
            {
                "id": "action_2",
                "name": "update_entity",
                "parameters": {
                    "entity_id": dragon_id,
                    "component_updates": {
                        "state": "defeated"
                    }
                },
                "preconditions": {
                    "entity_at_location": [
                        {
                            "entity_id": hero_id.to_string(),
                            "location_id": castle_id.to_string()
                        },
                        {
                            "entity_id": dragon_id.to_string(),
                            "location_id": castle_id.to_string()
                        }
                    ]
                },
                "effects": {
                    "entity_component_changes": [{
                        "entity_id": dragon_id.to_string(),
                        "component_changes": {
                            "state": "defeated"
                        }
                    }]
                },
                "dependencies": ["action_1"]
            }
        ],
        "metadata": {
            "estimated_duration": 400,
            "confidence": 0.95,
            "alternative_considered": "Direct teleportation"
        }
    });
    
    MockAiClient::new_with_response(repair_json.to_string())
}

/// Helper to setup mock AI for cross-user access test
fn setup_mock_ai_for_cross_user_plan(other_user_entity: &Uuid, location_id: &Uuid) -> MockAiClient {
    let plan_json = json!({
        "goal": "Move other user's entity (should fail)",
        "actions": [
            {
                "id": "action_1",
                "name": "move_entity",
                "parameters": {
                    "entity_id": other_user_entity,
                    "target_location_id": location_id
                },
                "preconditions": {
                    "entity_exists": [{
                        "entity_id": other_user_entity.to_string(),
                        "entity_name": "OtherUserEntity"
                    }]
                },
                "effects": {
                    "entity_location_changes": [{
                        "entity_id": other_user_entity.to_string(),
                        "new_location_id": location_id.to_string()
                    }]
                },
                "dependencies": []
            }
        ],
        "metadata": {
            "estimated_duration": 100,
            "confidence": 0.8,
            "alternative_considered": null
        }
    });
    
    MockAiClient::new_with_response(plan_json.to_string())
}

/// Helper to setup mock AI for complex multi-step plan
fn setup_mock_ai_for_complex_plan(sol_id: &Uuid, cantina_id: &Uuid, borga_id: &Uuid) -> MockAiClient {
    let plan_json = json!({
        "goal": "Sol moves to cantina and greets Borga",
        "actions": [
            {
                "id": "action_1",
                "name": "move_entity",
                "parameters": {
                    "entity_id": sol_id,
                    "target_location_id": cantina_id
                },
                "preconditions": {
                    "entity_exists": [{
                        "entity_id": sol_id.to_string(),
                        "entity_name": "Sol"
                    }]
                },
                "effects": {
                    "entity_location_changes": [{
                        "entity_id": sol_id.to_string(),
                        "new_location_id": cantina_id.to_string()
                    }]
                },
                "dependencies": []
            },
            {
                "id": "action_2",
                "name": "update_relationship",
                "parameters": {
                    "from_entity_id": sol_id,
                    "to_entity_id": borga_id,
                    "trust_delta": 0.1,
                    "affection_delta": 0.2
                },
                "preconditions": {
                    "entity_at_location": [
                        {
                            "entity_id": sol_id.to_string(),
                            "location_id": cantina_id.to_string()
                        },
                        {
                            "entity_id": borga_id.to_string(),
                            "location_id": cantina_id.to_string()
                        }
                    ]
                },
                "effects": {
                    "relationship_changes": [{
                        "from_entity_id": sol_id.to_string(),
                        "to_entity_id": borga_id.to_string(),
                        "trust_delta": 0.1,
                        "affection_delta": 0.2
                    }]
                },
                "dependencies": ["action_1"]
            }
        ],
        "metadata": {
            "estimated_duration": 180,
            "confidence": 0.95,
            "alternative_considered": "Direct greeting without movement"
        }
    });
    
    MockAiClient::new_with_response(plan_json.to_string())
}

/// Helper to create a failing mock AI client
fn setup_failing_mock_ai() -> MockAiClient {
    // Return a mock that will produce errors when used
    // For now, just return a basic mock - we'll check that errors are handled gracefully in the planning service
    MockAiClient::new_with_response("Error: AI service unavailable".to_string())
}

/// Helper to setup mock AI for repair scenario
fn setup_mock_ai_for_repair_scenario(sol_id: &Uuid, cantina_id: &Uuid, action_type: &str) -> MockAiClient {
    let plan_json = match action_type {
        "drink" => json!({
            "goal": "Sol orders a drink",
            "actions": [
                {
                    "id": "action_1",
                    "name": "update_entity",
                    "parameters": {
                        "entity_id": sol_id,
                        "component_updates": {
                            "has_drink": true
                        }
                    },
                    "preconditions": {
                        "entity_at_location": [{
                            "entity_id": sol_id.to_string(),
                            "location_id": cantina_id.to_string()
                        }]
                    },
                    "effects": {
                        "entity_component_changes": [{
                            "entity_id": sol_id.to_string(),
                            "component_changes": {
                                "has_drink": true
                            }
                        }]
                    },
                    "dependencies": []
                }
            ],
            "metadata": {
                "estimated_duration": 60,
                "confidence": 0.9,
                "alternative_considered": null
            }
        }),
        _ => json!({
            "goal": "Generic action",
            "actions": [],
            "metadata": {
                "estimated_duration": 60,
                "confidence": 0.5,
                "alternative_considered": null
            }
        })
    };
    
    MockAiClient::new_with_response(plan_json.to_string())
}

/// Helper to setup mock AI for relationship scenario
fn setup_mock_ai_for_relationship_scenario(sol_id: &Uuid, borga_id: &Uuid) -> MockAiClient {
    let plan_json = json!({
        "goal": "Sol increases trust in Borga",
        "actions": [
            {
                "id": "action_1",
                "name": "update_relationship",
                "parameters": {
                    "from_entity_id": sol_id,
                    "to_entity_id": borga_id,
                    "trust_delta": 0.2,
                    "affection_delta": 0.0
                },
                "preconditions": {
                    "relationship_exists": [{
                        "from_entity_id": sol_id.to_string(),
                        "to_entity_id": borga_id.to_string()
                    }]
                },
                "effects": {
                    "relationship_changes": [{
                        "from_entity_id": sol_id.to_string(),
                        "to_entity_id": borga_id.to_string(),
                        "trust_delta": 0.2,
                        "affection_delta": 0.0
                    }]
                },
                "dependencies": []
            }
        ],
        "metadata": {
            "estimated_duration": 30,
            "confidence": 0.95,
            "alternative_considered": null
        }
    });
    
    MockAiClient::new_with_response(plan_json.to_string())
}

/// Helper to create a chat message for test scenarios
fn create_chat_message(
    user_id: Uuid,
    role: MessageRole,
    content: &str,
    minutes_ago: i64,
) -> ChatMessage {
    ChatMessage {
        id: Uuid::new_v4(),
        session_id: Uuid::new_v4(),
        user_id,
        message_type: role,
        content: content.as_bytes().to_vec(),
        content_nonce: None,
        created_at: Utc::now() - chrono::Duration::minutes(minutes_ago),
        prompt_tokens: None,
        completion_tokens: None,
        model_name: "test".to_string(),
    }
}

#[tokio::test]
async fn test_valid_plan_workflow() {
    // Test the basic planning-validation loop with a valid plan
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let db_pool: Arc<PgPool> = test_app.db_pool.clone().into();
    let entity_manager = create_test_entity_manager(db_pool.clone()).await;
    let user = create_test_user(&test_app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Create test entities in ECS
    let chamber_id = create_test_entity(&entity_manager, user_id, "Chamber", "Location").await;
    let cantina_id = create_test_entity(&entity_manager, user_id, "Cantina", "Location").await;
    let sol_id = create_test_entity(&entity_manager, user_id, "Sol", "Character").await;

    // Place Sol in the Chamber initially
    entity_manager.move_entity(user_id, sol_id, chamber_id, None).await.unwrap();

    // Setup services
    let mock_ai = setup_mock_ai_for_valid_plan(cantina_id, sol_id, Uuid::new_v4()); // castle_id, hero_id, dragon_id
    let planning_service = PlanningService::new(
        Arc::new(mock_ai),
        entity_manager.clone(),
        Arc::clone(&test_app.redis_client),
        db_pool.clone(),
    );
    let plan_validator = PlanValidatorService::new(entity_manager.clone(), Arc::clone(&test_app.redis_client));

    // Execute planning workflow
    let goal = "Sol wants to go to the cantina";
    let context = create_test_enriched_context(
        vec![(sol_id, "Sol".to_string(), "Character".to_string()),
             (cantina_id, "Cantina".to_string(), "Location".to_string()),
             (chamber_id, "Chamber".to_string(), "Location".to_string())],
        vec![],
    );
    let ai_plan = planning_service.generate_plan(goal, &context, user_id, &session_dek).await.unwrap();

    // Validate the plan
    let validation_result = plan_validator.validate_plan(&ai_plan.plan, user_id).await.unwrap();

    // Assert successful validation
    match validation_result {
        PlanValidationResult::Valid(valid_plan) => {
            assert_eq!(valid_plan.original_plan.goal, goal);
            assert!(valid_plan.original_plan.actions.len() >= 1);
        }
        _ => panic!("Expected valid plan but got: {:?}", validation_result),
    }
}

#[tokio::test]
async fn test_invalid_plan_precondition_failure() {
    // Test that invalid plans are properly rejected by the validator
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let db_pool: Arc<PgPool> = test_app.db_pool.clone().into();
    let entity_manager = create_test_entity_manager(db_pool.clone()).await;
    let user = create_test_user(&test_app.db_pool, "test_user2".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    let session_dek = SessionDek::new(vec![0u8; 32]); // Create a test session DEK

    // Create test entities but don't set up proper preconditions
    let chamber_id = create_test_entity(&entity_manager, user_id, "Chamber", "Location").await;
    let cantina_id = create_test_entity(&entity_manager, user_id, "Cantina", "Location").await;
    let sol_id = create_test_entity(&entity_manager, user_id, "Sol", "Character").await;

    // Sol is in chamber, but we'll create a plan that requires Sol to be in cantina
    entity_manager.move_entity(user_id, sol_id, chamber_id, None).await.unwrap();

    // Setup services with a plan that violates preconditions
    let mock_ai = setup_mock_ai_for_invalid_plan(cantina_id, sol_id, Uuid::new_v4());
    let planning_service = PlanningService::new(
        Arc::new(mock_ai),
        entity_manager.clone(),
        test_app.redis_client.clone(),
        Arc::new(test_app.db_pool.clone()),
    );
    let plan_validator = PlanValidatorService::new(entity_manager.clone(), test_app.redis_client.clone());

    // Execute planning workflow  
    let goal = "Sol orders a drink (but he's not in cantina)";
    let context = create_test_enriched_context(
        vec![(sol_id, "Sol".to_string(), "Character".to_string()),
             (cantina_id, "Cantina".to_string(), "Location".to_string()),
             (chamber_id, "Chamber".to_string(), "Location".to_string())],
        vec![],
    );
    let ai_plan = planning_service.generate_plan(goal, &context, user_id, &session_dek).await.unwrap();

    // Validate the plan - should fail
    let validation_result = plan_validator.validate_plan(&ai_plan.plan, user_id).await.unwrap();

    // Assert validation failure
    match validation_result {
        PlanValidationResult::Invalid(invalid_plan) => {
            assert!(!invalid_plan.failures.is_empty());
            assert!(invalid_plan.failures.iter().any(|failure| 
                failure.message.contains("not at location") || 
                failure.message.contains("Entity not in expected location") ||
                failure.message.contains("precondition")
            ));
        }
        _ => panic!("Expected invalid plan but got: {:?}", validation_result),
    }
}

#[tokio::test]
async fn test_cross_user_security_validation() {
    // Test that plans cannot access entities from other users (A01: Broken Access Control)
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let db_pool: Arc<PgPool> = test_app.db_pool.clone().into();
    let entity_manager = create_test_entity_manager(db_pool.clone()).await;
    
    // Create two users
    let user1 = create_test_user(&test_app.db_pool, "user1".to_string(), "password123".to_string()).await.unwrap();
    let user2 = create_test_user(&test_app.db_pool, "user2".to_string(), "password123".to_string()).await.unwrap();
    let user1_id = user1.id;
    let user2_id = user2.id;
    let session_dek1 = SessionDek::new(vec![0u8; 32]);

    // Create entities for user1
    let user1_sol_id = create_test_entity(&entity_manager, user1_id, "User1_Sol", "Character").await;
    let user1_cantina_id = create_test_entity(&entity_manager, user1_id, "User1_Cantina", "Location").await;

    // Create entities for user2  
    let user2_sol_id = create_test_entity(&entity_manager, user2_id, "User2_Sol", "Character").await;

    // Setup planning service for user1 but try to plan with user2's entity
    let mock_ai = setup_mock_ai_for_cross_user_plan(&user2_sol_id, &user1_cantina_id);
    let planning_service = PlanningService::new(
        Arc::new(mock_ai),
        entity_manager.clone(),
        test_app.redis_client.clone(),
        db_pool.clone(),
    );
    let plan_validator = PlanValidatorService::new(entity_manager.clone(), test_app.redis_client.clone());

    // Execute planning workflow as user1 but targeting user2's entity
    let goal = "Move user2's Sol to user1's cantina (should fail)";
    let context = create_test_enriched_context(
        vec![(user1_sol_id, "User1_Sol".to_string(), "Character".to_string()),
             (user1_cantina_id, "User1_Cantina".to_string(), "Location".to_string())],
        vec![],
    );
    let ai_plan = planning_service.generate_plan(goal, &context, user1_id, &session_dek1).await.unwrap();

    // Validate the plan - should fail due to access control
    let validation_result = plan_validator.validate_plan(&ai_plan.plan, user1_id).await.unwrap();

    // Assert validation failure due to cross-user access
    match validation_result {
        PlanValidationResult::Invalid(invalid_plan) => {
            assert!(!invalid_plan.failures.is_empty());
            // Should fail because user1 cannot access user2's entities
            assert!(invalid_plan.failures.iter().any(|f| 
                f.message.contains("Entity does not exist") || 
                f.message.contains("not found") ||
                f.message.contains("access")
            ));
        }
        _ => panic!("Expected invalid plan due to cross-user access but got: {:?}", validation_result),
    }
}

#[tokio::test]
async fn test_planning_service_validator_integration() {
    // Test that PlanningService and PlanValidatorService work together correctly
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let db_pool: Arc<PgPool> = test_app.db_pool.clone().into();
    let entity_manager = create_test_entity_manager(db_pool.clone()).await;
    let user = create_test_user(&test_app.db_pool, "test_user4".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Create complex test scenario with multiple entities and relationships
    let chamber_id = create_test_entity(&entity_manager, user_id, "Chamber", "Location").await;
    let cantina_id = create_test_entity(&entity_manager, user_id, "Cantina", "Location").await;
    let sol_id = create_test_entity(&entity_manager, user_id, "Sol", "Character").await;
    let borga_id = create_test_entity(&entity_manager, user_id, "Borga", "Character").await;

    // Setup initial world state
    entity_manager.move_entity(user_id, sol_id, chamber_id, None).await.unwrap();
    entity_manager.move_entity(user_id, borga_id, cantina_id, None).await.unwrap();

    // Create relationship between Sol and Borga
    entity_manager.update_relationship(
        user_id,
        sol_id,
        borga_id,
        Some(0.7), // trust
        Some(0.5), // affection
        Some("friend".to_string()),
        serde_json::json!({}),
    ).await.unwrap();

    // Setup services with a complex multi-step plan
    let mock_ai = setup_mock_ai_for_complex_plan(&sol_id, &cantina_id, &borga_id);
    let planning_service = PlanningService::new(
        Arc::new(mock_ai),
        entity_manager.clone(),
        test_app.redis_client.clone(),
        db_pool.clone(),
    );
    let plan_validator = PlanValidatorService::new(entity_manager.clone(), test_app.redis_client.clone());

    // Execute planning workflow
    let goal = "Sol moves to cantina and greets Borga";
    let context = create_test_enriched_context(
        vec![(sol_id, "Sol".to_string(), "Character".to_string()),
             (cantina_id, "Cantina".to_string(), "Location".to_string()),
             (chamber_id, "Chamber".to_string(), "Location".to_string()),
             (borga_id, "Borga".to_string(), "Character".to_string())],
        vec![(sol_id, borga_id, "friend".to_string())],
    );
    let ai_plan = planning_service.generate_plan(goal, &context, user_id, &session_dek).await.unwrap();

    // Validate the plan
    let validation_result = plan_validator.validate_plan(&ai_plan.plan, user_id).await.unwrap();

    // Assert successful validation of complex plan
    match validation_result {
        PlanValidationResult::Valid(valid_plan) => {
            assert_eq!(valid_plan.original_plan.goal, goal);
            assert!(valid_plan.original_plan.actions.len() >= 2); // Move + UpdateRelationship
            
            // Verify move action
            let move_action = valid_plan.original_plan.actions.iter()
                .find(|a| a.name == ActionName::MoveEntity)
                .expect("Should have move action");
            
            // Verify relationship action
            let relationship_action = valid_plan.original_plan.actions.iter()
                .find(|a| a.name == ActionName::UpdateRelationship)
                .expect("Should have relationship action");
        }
        _ => panic!("Expected valid complex plan but got: {:?}", validation_result),
    }
}

#[tokio::test]
async fn test_service_error_handling_and_graceful_degradation() {
    // Test error handling and graceful degradation in planning workflow
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let db_pool: Arc<PgPool> = test_app.db_pool.clone().into();
    let entity_manager = create_test_entity_manager(db_pool.clone()).await;
    let user = create_test_user(&test_app.db_pool, "test_user5".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Setup services with failing AI client
    let mock_ai = setup_failing_mock_ai();
    let planning_service = PlanningService::new(
        Arc::new(mock_ai),
        entity_manager.clone(),
        test_app.redis_client.clone(),
        db_pool.clone(),
    );

    // Execute planning workflow - should handle AI failure gracefully
    let goal = "Test graceful degradation";
    let context = create_test_enriched_context(vec![], vec![]);
    let result = planning_service.generate_plan(goal, &context, user_id, &session_dek).await;

    // Should get a reasonable error, not a panic
    match result {
        Err(AppError::InternalServerErrorGeneric(msg)) => {
            assert!(msg.contains("AI") || msg.contains("planning") || msg.contains("failed"));
        }
        Err(_) => {
            // Other error types are also acceptable for graceful degradation
        }
        Ok(_) => panic!("Expected error due to failing AI but got success"),
    }
}

// ========================================================================================
// Task 3.5.4: End-to-End Integration Testing with Repair System
// 
// These tests validate the complete planning → validation → repair → execution pipeline
// as specified in the Living World Implementation Roadmap.
// 
// NOTE: These tests are designed to be forward-compatible with the repair system.
// They will gracefully handle cases where repair functionality isn't fully implemented.
// ========================================================================================

// Additional tests for Task 3.5.4 would go here but are currently disabled
// until the repair system methods are fully implemented
// These tests would cover:
// - End-to-end missing movement repair scenarios
// - Missing relationship repair scenarios  
// - Missing component repair scenarios
// - Complete planning → validation → repair → execution pipeline
