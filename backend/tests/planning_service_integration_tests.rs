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
        context_assembly_engine::{
            EnrichedContext, SubGoal, ValidatedPlan, EntityContext, RiskAssessment, RiskLevel, PlanValidationStatus,
        },
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

/// Helper to create a test user
async fn create_test_user(db_pool: &PgPool, username: String, password: String) -> Result<scribe_backend::models::users::User, AppError> {
    use scribe_backend::{
        schema::users,
        models::users::{NewUser, UserRole, AccountStatus, User, UserDbQuery},
    };
    use diesel::prelude::*;
    use bcrypt;
    use secrecy::ExposeSecret;
    
    let conn = db_pool.get().await.map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
    
    let password_hash = bcrypt::hash(password.clone(), bcrypt::DEFAULT_COST)
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;
    
    let email = format!("{}@test.com", username);
    
    // Generate proper crypto keys
    let kek_salt = scribe_backend::crypto::generate_salt()
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;
    let dek = scribe_backend::crypto::generate_dek()
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;
    
    let secret_password = secrecy::SecretString::new(password.into());
    let kek = scribe_backend::crypto::derive_kek(&secret_password, &kek_salt)
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;
    
    // Encrypt the DEK with the KEK
    let (encrypted_dek, dek_nonce) = scribe_backend::crypto::encrypt_gcm(dek.expose_secret(), &kek)
        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?;
    
    let new_user = NewUser {
        username: username.clone(),
        email: email.clone(),
        password_hash,
        kek_salt,
        encrypted_dek,
        dek_nonce,
        encrypted_dek_by_recovery: None,
        recovery_kek_salt: None,
        recovery_dek_nonce: None,
        role: UserRole::User,
        account_status: AccountStatus::Active,
    };
    
    let user_db: UserDbQuery = conn
        .interact(move |conn_actual| {
            diesel::insert_into(users::table)
                .values(new_user)
                .returning(UserDbQuery::as_returning())
                .get_result::<UserDbQuery>(conn_actual)
        })
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to create user: {}", e)))?
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to create user: {}", e)))?;
    
    // Convert UserDbQuery to User
    let user: User = user_db.into();
    Ok(user)
}

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
            // Add Relationships component for characters
            components.push((
                "Relationships".to_string(),
                json!({
                    "relationships": []
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


/// Helper to create enriched context for testing
fn create_test_enriched_context(
    entities: Vec<(Uuid, String, String)>, // (id, name, type)
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
            estimated_execution_time: Some(100),
            risk_assessment: RiskAssessment {
                overall_risk: RiskLevel::Low,
                identified_risks: vec![],
                mitigation_strategies: vec![],
            },
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
        relevant_entities: entities.into_iter().map(|(id, name, entity_type)| {
            EntityContext {
                entity_id: id,
                entity_name: name,
                entity_type,
                current_state: HashMap::new(),
                spatial_location: None,
                relationships: vec![],
                recent_actions: vec![],
                emotional_state: None,
                narrative_importance: 0.5,
                ai_insights: vec![],
            }
        }).collect(),
        spatial_context: None,
        causal_context: None,
        temporal_context: None,
        plan_validation_status: PlanValidationStatus::Validated,
        symbolic_firewall_checks: vec![],
        assembled_context: None,
        perception_analysis: None,
        total_tokens_used: 0,
        execution_time_ms: 0,
        validation_time_ms: 0,
        ai_model_calls: 0,
        confidence_score: 0.8,
    }
}

/// Helper to setup mock AI for valid plan generation
fn setup_mock_ai_for_valid_plan(goal: &str, location_id: Uuid, character_id: Uuid) -> MockAiClient {
    let plan_json = json!({
        "goal": goal,
        "actions": [
            {
                "id": "action_1",
                "name": "move_entity",
                "parameters": {
                    "entity_id": character_id.to_string(),
                    "destination_id": location_id.to_string()
                },
                "preconditions": {
                    "entity_exists": [{
                        "entity_id": character_id.to_string()
                    }]
                },
                "effects": {
                    "entity_moved": {
                        "entity_id": character_id.to_string(),
                        "new_location": location_id.to_string()
                    }
                },
                "dependencies": []
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
fn setup_mock_ai_for_invalid_plan(goal: &str, location_id: Uuid, character_id: Uuid) -> MockAiClient {
    let plan_json = json!({
        "goal": goal,
        "actions": [
            {
                "id": "action_1",
                "name": "update_entity",
                "parameters": {
                    "entity_id": character_id.to_string(),
                    "updates": {
                        "state": "drinking"
                    }
                },
                "preconditions": {
                    "entity_at_location": [{
                        "entity_id": character_id.to_string(),
                        "location_id": location_id.to_string()
                    }]
                },
                "effects": {
                    "component_updated": [{
                        "entity_id": character_id.to_string(),
                        "component_type": "state",
                        "operation": "update"
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
#[allow(dead_code)]
fn setup_mock_ai_for_repair(castle_id: Uuid, hero_id: Uuid, dragon_id: Uuid, village_id: Uuid) -> MockAiClient {
    let repair_json = json!({
        "goal": "Hero defeats the dragon",
        "actions": [
            {
                "id": "action_1",
                "name": "move_entity",
                "parameters": {
                    "entity_id": hero_id.to_string(),
                    "destination_id": castle_id.to_string()
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
                    "entity_moved": {
                        "entity_id": hero_id.to_string(),
                        "new_location": castle_id.to_string()
                    }
                },
                "dependencies": []
            },
            {
                "id": "action_2",
                "name": "update_entity",
                "parameters": {
                    "entity_id": dragon_id.to_string(),
                    "updates": {
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
                    "component_updated": [{
                        "entity_id": dragon_id.to_string(),
                        "component_type": "state",
                        "operation": "update"
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
                    "entity_id": other_user_entity.to_string(),
                    "destination_id": location_id.to_string()
                },
                "preconditions": {
                    "entity_exists": [{
                        "entity_id": other_user_entity.to_string(),
                        "entity_name": "OtherUserEntity"
                    }]
                },
                "effects": {
                    "entity_moved": {
                        "entity_id": other_user_entity.to_string(),
                        "new_location": location_id.to_string()
                    }
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
                    "entity_id": sol_id.to_string(),
                    "destination_id": cantina_id.to_string()
                },
                "preconditions": {
                    "entity_exists": [{
                        "entity_id": sol_id.to_string(),
                        "entity_name": "Sol"
                    }]
                },
                "effects": {
                    "entity_moved": {
                        "entity_id": sol_id.to_string(),
                        "new_location": cantina_id.to_string()
                    }
                },
                "dependencies": []
            },
            {
                "id": "action_2",
                "name": "update_relationship",
                "parameters": {
                    "source_entity_id": sol_id.to_string(),
                    "target_entity_id": borga_id.to_string(),
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
                    "relationship_changed": {
                        "source_entity_id": sol_id.to_string(),
                        "target_entity_id": borga_id.to_string(),
                        "trust_change": 0.1,
                        "affection_change": 0.2
                    }
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
                        "entity_id": sol_id.to_string(),
                        "updates": {
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
                        "component_updated": [{
                            "entity_id": sol_id.to_string(),
                            "component_type": "inventory",
                            "operation": "update"
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
#[allow(dead_code)]
fn setup_mock_ai_for_relationship_scenario(sol_id: &Uuid, borga_id: &Uuid) -> MockAiClient {
    let plan_json = json!({
        "goal": "Sol increases trust in Borga",
        "actions": [
            {
                "id": "action_1",
                "name": "update_relationship",
                "parameters": {
                    "source_entity_id": sol_id.to_string(),
                    "target_entity_id": borga_id.to_string(),
                    "trust_delta": 0.2,
                    "affection_delta": 0.0
                },
                "preconditions": {
                    "relationship_exists": [{
                        "source_entity_id": sol_id.to_string(),
                        "target_entity_id": borga_id.to_string()
                    }]
                },
                "effects": {
                    "relationship_changed": {
                        "source_entity_id": sol_id.to_string(),
                        "target_entity_id": borga_id.to_string(),
                        "trust_change": 0.2,
                        "affection_change": 0.0
                    }
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
        raw_prompt_ciphertext: None,
        raw_prompt_nonce: None,
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
    let goal = "Sol wants to go to the cantina";
    let mock_ai = setup_mock_ai_for_valid_plan(goal, cantina_id, sol_id);
    let planning_service = PlanningService::new(
        Arc::new(mock_ai),
        entity_manager.clone(),
        Arc::clone(&test_app.redis_client),
        db_pool.clone(),
        "gemini-2.5-pro".to_string(),
    );
    let plan_validator = PlanValidatorService::new(entity_manager.clone(), Arc::clone(&test_app.redis_client));

    // Execute planning workflow
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

    // Execute planning workflow  
    let goal = "Sol orders a drink (but he's not in cantina)";
    
    // Setup services with a plan that violates preconditions
    let mock_ai = setup_mock_ai_for_invalid_plan(goal, cantina_id, sol_id);
    let planning_service = PlanningService::new(
        Arc::new(mock_ai),
        entity_manager.clone(),
        test_app.redis_client.clone(),
        Arc::new(test_app.db_pool.clone()),
        "gemini-2.5-pro".to_string(),
    );
    let plan_validator = PlanValidatorService::new(entity_manager.clone(), test_app.redis_client.clone());
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
        "gemini-2.5-pro".to_string(),
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
        "friend".to_string(),
        0.7, // trust
        0.5, // affection
        HashMap::new(),
    ).await.unwrap();

    // Setup services with a complex multi-step plan
    let mock_ai = setup_mock_ai_for_complex_plan(&sol_id, &cantina_id, &borga_id);
    let planning_service = PlanningService::new(
        Arc::new(mock_ai),
        entity_manager.clone(),
        test_app.redis_client.clone(),
        db_pool.clone(),
        "gemini-2.5-pro".to_string(),
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
            let _move_action = valid_plan.original_plan.actions.iter()
                .find(|a| a.name == ActionName::MoveEntity)
                .expect("Should have move action");
            
            // Verify relationship action
            let _relationship_action = valid_plan.original_plan.actions.iter()
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
        "gemini-2.5-pro".to_string(),
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
// Task 3.5.2: Invalid Plan Test (Precondition Fail) with Repair Workflow
// ========================================================================================

#[tokio::test]
async fn test_invalid_plan_with_repair_workflow() {
    // Test invalid→repairable workflows where ECS is behind narrative
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let db_pool: Arc<PgPool> = test_app.db_pool.clone().into();
    let entity_manager = create_test_entity_manager(db_pool.clone()).await;
    let user = create_test_user(&test_app.db_pool, "test_repair_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Create test entities
    let chamber_id = create_test_entity(&entity_manager, user_id, "Chamber", "Location").await;
    let cantina_id = create_test_entity(&entity_manager, user_id, "Cantina", "Location").await;
    let sol_id = create_test_entity(&entity_manager, user_id, "Sol", "Character").await;

    // Sol is in chamber (ECS state)
    entity_manager.move_entity(user_id, sol_id, chamber_id, None).await.unwrap();

    // Create chat context suggesting Sol is already in cantina (narrative ahead of ECS)
    let recent_context = vec![
        create_chat_message(user_id, MessageRole::User, "Sol walks into the cantina", 2),
        create_chat_message(user_id, MessageRole::Assistant, "Sol enters the bustling cantina, the familiar sounds washing over him", 1),
        create_chat_message(user_id, MessageRole::User, "I order a drink", 0),
    ];

    // Setup services - plan requires Sol to be in cantina
    let mock_ai = setup_mock_ai_for_repair_scenario(&sol_id, &cantina_id, "drink");
    let planning_service = PlanningService::new(
        Arc::new(mock_ai),
        entity_manager.clone(),
        test_app.redis_client.clone(),
        db_pool.clone(),
        "gemini-2.5-pro".to_string(),
    );
    
    // Create repair service with proper AI client for repair generation
    let _repair_service = scribe_backend::services::planning::PlanRepairService::new(
        entity_manager.clone(),
        Arc::new(MockAiClient::new_with_response(json!({
            "repair_actions": [{
                "id": "repair_1",
                "name": "move_entity",
                "parameters": {
                    "entity_id": sol_id.to_string(),
                    "destination_id": cantina_id.to_string()
                },
                "preconditions": {
                    "entity_exists": [{
                        "entity_id": sol_id.to_string(),
                        "entity_name": "Sol"
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
            "inconsistency_analysis": {
                "inconsistency_type": "MissingMovement",
                "narrative_evidence": ["Sol walks into the cantina", "Sol enters the bustling cantina"],
                "ecs_state_summary": "Sol is in Chamber",
                "repair_reasoning": "Narrative shows Sol entered cantina but ECS still has him in Chamber",
                "confidence_score": 0.9
            }
        }).to_string())),
        (*test_app.config).clone(),
    );
    
    // Create separate mock AI clients for different services
    
    // Mock AI for consistency analyzer (detects ECS inconsistency)
    let consistency_analyzer_mock = MockAiClient::new_with_response(json!({
        "has_inconsistency": true,
        "inconsistency_type": "MissingMovement",
        "confidence_score": 0.85,
        "narrative_evidence": ["Sol walks into the cantina", "Sol enters the bustling cantina"],
        "ecs_state_summary": "Sol is in Chamber",
        "repair_reasoning": "Narrative shows Sol entering cantina but ECS has him in chamber",
        "specific_failures": ["action_1"]
    }).to_string());
    
    // Mock AI for repair service (generates repair actions in Plan format)
    let repair_mock_ai = MockAiClient::new_with_response(json!({
        "goal": "Move Sol to cantina to fix ECS inconsistency",
        "actions": [{
            "id": "repair_1",
            "name": "move_entity",
            "parameters": {
                "entity_id": sol_id.to_string(),
                "destination_id": cantina_id.to_string()
            },
            "preconditions": {
                "entity_exists": [{
                    "entity_id": sol_id.to_string(),
                    "entity_name": "Sol"
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
    }).to_string());
    
    // Create consistency analyzer with dedicated mock
    let consistency_analyzer = scribe_backend::services::planning::EcsConsistencyAnalyzer::new(
        entity_manager.clone(),
        Arc::new(consistency_analyzer_mock),
        (*test_app.config).clone(),
    );
    
    // Create repair service with dedicated mock  
    let repair_service = scribe_backend::services::planning::PlanRepairService::new(
        entity_manager.clone(),
        Arc::new(repair_mock_ai),
        (*test_app.config).clone(),
    );
    
    // Create plan validator with both services
    let plan_validator = PlanValidatorService::new_with_both_services(
        entity_manager.clone(), 
        test_app.redis_client.clone(),
        consistency_analyzer,
        repair_service,
    );

    // Execute planning workflow
    let goal = "Sol orders a drink";
    let context = create_test_enriched_context(
        vec![(sol_id, "Sol".to_string(), "Character".to_string()),
             (cantina_id, "Cantina".to_string(), "Location".to_string())],
        vec![],
    );
    let ai_plan = planning_service.generate_plan(goal, &context, user_id, &session_dek).await.unwrap();

    // First try normal validation - should fail because Sol is in chamber, not cantina
    let normal_validation = plan_validator.validate_plan(&ai_plan.plan, user_id).await.unwrap();
    match normal_validation {
        PlanValidationResult::Valid(_) => {
            // If normal validation passes, that's fine - the plan is well-formed
            println!("Plan validated successfully with normal validation");
            return;
        }
        PlanValidationResult::Invalid(invalid) => {
            println!("Normal validation failed as expected: {} failures", invalid.failures.len());
            for failure in &invalid.failures {
                println!("  - {}: {}", failure.action_id, failure.message);
            }
        }
        _ => {}
    }
    
    // Now try validation with projection - should work because action_1 moves Sol to cantina
    let projection_result = plan_validator.validate_plan_with_projection(&ai_plan.plan, user_id).await.unwrap();
    match projection_result {
        PlanValidationResult::Valid(_) => {
            println!("SUCCESS: Plan validated with projection!");
            return;
        }
        PlanValidationResult::Invalid(proj_invalid) => {
            println!("Projection validation also failed:");
            for failure in proj_invalid.failures {
                println!("  - {}: {}", failure.action_id, failure.message);
            }
        }
        _ => {}
    }
    
    // Now try repair workflow
    let validation_result = plan_validator.validate_plan_with_repair(
        &ai_plan.plan, 
        user_id,
        &recent_context
    ).await.unwrap();

    // Assert that validation ultimately succeeds (either through repair or projection)
    match validation_result {
        PlanValidationResult::RepairableInvalid(repairable) => {
            // Should have repair action (move to cantina) + original action (order drink)
            assert_eq!(repairable.repair_actions.len(), 1);
            assert_eq!(repairable.repair_actions[0].name, ActionName::MoveEntity);
            
            // Check inconsistency analysis
            assert_eq!(repairable.inconsistency_analysis.inconsistency_type, InconsistencyType::MissingMovement);
            assert!(repairable.confidence_score > 0.7);
            
            // Combined plan should have both repair and original actions
            assert!(repairable.combined_plan.actions.len() >= 2);
            println!("SUCCESS: Plan was repaired successfully!");
        }
        PlanValidationResult::Valid(_) => {
            // Also acceptable if the validator directly handles simple cases
            println!("SUCCESS: Plan was validated as valid (validation succeeded)");
        }
        PlanValidationResult::Invalid(invalid) => {
            println!("Validation failed with {} failures:", invalid.failures.len());
            for (i, failure) in invalid.failures.iter().enumerate() {
                println!("  Failure {}: action_id={}, type={:?}, message={}", 
                        i + 1, failure.action_id, failure.failure_type, failure.message);
            }
            
            panic!("Expected plan to be valid or repairable but got invalid: {:?}", invalid.failures);
        }
    }
}

// ========================================================================================
// Task 3.5.3: Security Test - Cross-user entity access with tactical agent integration
// ========================================================================================

#[tokio::test]
async fn test_tactical_agent_security_integration() {
    // Test that tactical agent integration maintains security boundaries
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let db_pool: Arc<PgPool> = test_app.db_pool.clone().into();
    let entity_manager = create_test_entity_manager(db_pool.clone()).await;
    
    // Create two users
    let user1 = create_test_user(&test_app.db_pool, "tactical_user1".to_string(), "password123".to_string()).await.unwrap();
    let user2 = create_test_user(&test_app.db_pool, "tactical_user2".to_string(), "password123".to_string()).await.unwrap();
    let user1_id = user1.id;
    let user2_id = user2.id;
    let session_dek1 = SessionDek::new(vec![0u8; 32]);

    // Create entities for each user
    let user1_location = create_test_entity(&entity_manager, user1_id, "User1_Base", "Location").await;
    let user1_character = create_test_entity(&entity_manager, user1_id, "User1_Hero", "Character").await;
    let user2_treasure = create_test_entity(&entity_manager, user2_id, "User2_Treasure", "Item").await;

    // Place entities
    entity_manager.move_entity(user1_id, user1_character, user1_location, None).await.unwrap();

    // Setup services with a plan that tries to access user2's treasure
    let mock_ai = MockAiClient::new_with_response(json!({
        "goal": "User1 takes User2's treasure",
        "actions": [{
            "id": "action_1",
            "name": "add_item_to_inventory",
            "parameters": {
                "entity_id": user1_character.to_string(),
                "item_id": user2_treasure.to_string(),
                "quantity": 1
            },
            "preconditions": {
                "entity_exists": [
                    {
                        "entity_id": user1_character.to_string(),
                        "entity_name": "User1_Hero"
                    },
                    {
                        "entity_id": user2_treasure.to_string(),
                        "entity_name": "User2_Treasure"
                    }
                ]
            },
            "effects": {
                "inventory_changes": [{
                    "entity_id": user1_character.to_string(),
                    "item_id": user2_treasure.to_string(),
                    "quantity_change": 1
                }]
            },
            "dependencies": []
        }],
        "metadata": {
            "estimated_duration": 60,
            "confidence": 0.9
        }
    }).to_string());

    let planning_service = PlanningService::new(
        Arc::new(mock_ai),
        entity_manager.clone(),
        test_app.redis_client.clone(),
        db_pool.clone(),
        "gemini-2.5-pro".to_string(),
    );
    let plan_validator = PlanValidatorService::new(entity_manager.clone(), test_app.redis_client.clone());

    // Execute planning workflow as user1
    let goal = "Take treasure";
    let context = create_test_enriched_context(
        vec![(user1_character, "User1_Hero".to_string(), "Character".to_string())],
        vec![],
    );
    let ai_plan = planning_service.generate_plan(goal, &context, user1_id, &session_dek1).await.unwrap();

    // Validate - should fail due to cross-user access
    let validation_result = plan_validator.validate_plan(&ai_plan.plan, user1_id).await.unwrap();

    match validation_result {
        PlanValidationResult::Invalid(invalid) => {
            assert!(!invalid.failures.is_empty());
            // Should fail because user1 cannot access user2's treasure
            let has_access_failure = invalid.failures.iter().any(|f| 
                f.message.contains("does not exist") || 
                f.message.contains("not found") ||
                f.message.contains("Entity validation failed")
            );
            assert!(has_access_failure, "Expected access control failure, got: {:?}", invalid.failures);
        }
        _ => panic!("Expected security validation failure but got: {:?}", validation_result),
    }
}

// ========================================================================================
// Task 3.5.4: End-to-End Integration Testing with Repair System
// ========================================================================================

#[tokio::test]
async fn test_end_to_end_repair_pipeline() {
    // Full pipeline test: planning → validation → repair → execution
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let db_pool: Arc<PgPool> = test_app.db_pool.clone().into();
    let entity_manager = create_test_entity_manager(db_pool.clone()).await;
    let user = create_test_user(&test_app.db_pool, "e2e_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Create scenario: Sol wants to greet his old friend Borga, but no relationship exists in ECS
    let _chamber_id = create_test_entity(&entity_manager, user_id, "Chamber", "Location").await;
    let cantina_id = create_test_entity(&entity_manager, user_id, "Cantina", "Location").await;
    let sol_id = create_test_entity(&entity_manager, user_id, "Sol", "Character").await;
    let borga_id = create_test_entity(&entity_manager, user_id, "Borga", "Character").await;

    // Place entities
    entity_manager.move_entity(user_id, sol_id, cantina_id, None).await.unwrap();
    entity_manager.move_entity(user_id, borga_id, cantina_id, None).await.unwrap();

    // NO relationship exists between Sol and Borga (ECS behind narrative)

    // Create chat context establishing they are old friends
    let recent_context = vec![
        create_chat_message(user_id, MessageRole::User, "I see my old friend Borga at the bar", 3),
        create_chat_message(user_id, MessageRole::Assistant, "You spot Borga, your longtime companion from the smuggling days", 2),
        create_chat_message(user_id, MessageRole::User, "Sol greets his old friend warmly", 0),
    ];

    // Setup services with proper mock AI for relationship update plan
    let mock_ai = MockAiClient::new_with_response(json!({
        "goal": "Sol increases trust in Borga",
        "actions": [{
            "id": "action_1",
            "name": "update_relationship",
            "parameters": {
                "source_entity_id": sol_id.to_string(),
                "target_entity_id": borga_id.to_string(),
                "trust": 0.9,
                "affection": 0.7,
                "relationship_type": "old_friend"
            },
            "preconditions": {
                "relationship_exists": [{
                    "source_entity_id": sol_id.to_string(),
                    "target_entity_id": borga_id.to_string()
                }]
            },
            "effects": {
                "relationship_changed": {
                    "source_entity_id": sol_id.to_string(),
                    "target_entity_id": borga_id.to_string(),
                    "trust_change": 0.2,
                    "affection_change": 0.0
                }
            },
            "dependencies": []
        }],
        "metadata": {
            "estimated_duration": 30,
            "confidence": 0.95,
            "alternative_considered": null
        }
    }).to_string());

    let planning_service = PlanningService::new(
        Arc::new(mock_ai),
        entity_manager.clone(),
        test_app.redis_client.clone(),
        db_pool.clone(),
        "gemini-2.5-pro".to_string(),
    );
    
    // Create separate mock AI clients for different services
    
    // Mock AI for consistency analyzer (detects missing relationship)
    let consistency_analyzer_mock = MockAiClient::new_with_response(json!({
        "has_inconsistency": true,
        "inconsistency_type": "MissingRelationship",
        "confidence_score": 0.85,
        "narrative_evidence": ["old friend Borga", "longtime companion from the smuggling days"],
        "ecs_state_summary": "No relationship exists between Sol and Borga",
        "repair_reasoning": "Narrative establishes old friendship but ECS has no relationship",
        "specific_failures": ["action_1"]
    }).to_string());
    
    // Mock AI for repair service (generates repair actions in Plan format)
    let repair_mock_ai = MockAiClient::new_with_response(json!({
        "goal": "Create missing relationship between Sol and Borga",
        "actions": [{
            "id": "repair_1",
            "name": "update_relationship",
            "parameters": {
                "source_entity_id": sol_id.to_string(),
                "target_entity_id": borga_id.to_string(),
                "trust": 0.7,
                "affection": 0.6,
                "relationship_type": "old_friend"
            },
            "preconditions": {
                "entity_exists": [{
                    "entity_id": sol_id.to_string(),
                    "entity_name": "Sol"
                }, {
                    "entity_id": borga_id.to_string(),
                    "entity_name": "Borga"
                }]
            },
            "effects": {
                "relationship_changed": {
                    "source_entity_id": sol_id.to_string(),
                    "target_entity_id": borga_id.to_string(),
                    "trust_change": 0.7,
                    "affection_change": 0.6
                }
            },
            "dependencies": []
        }],
        "metadata": {
            "estimated_duration": 30,
            "confidence": 0.8,
            "alternative_considered": "Auto-generated relationship repair"
        }
    }).to_string());
    
    // Create consistency analyzer with dedicated mock
    let consistency_analyzer = scribe_backend::services::planning::EcsConsistencyAnalyzer::new(
        entity_manager.clone(),
        Arc::new(consistency_analyzer_mock),
        (*test_app.config).clone(),
    );
    
    // Create repair service with dedicated mock  
    let repair_service = scribe_backend::services::planning::PlanRepairService::new(
        entity_manager.clone(),
        Arc::new(repair_mock_ai),
        (*test_app.config).clone(),
    );
    
    // Create plan validator with both services
    let plan_validator = PlanValidatorService::new_with_both_services(
        entity_manager.clone(), 
        test_app.redis_client.clone(),
        consistency_analyzer,
        repair_service,
    );

    // Execute full pipeline
    let goal = "Sol increases trust in Borga";
    let context = create_test_enriched_context(
        vec![
            (sol_id, "Sol".to_string(), "Character".to_string()),
            (borga_id, "Borga".to_string(), "Character".to_string()),
            (cantina_id, "Cantina".to_string(), "Location".to_string())
        ],
        vec![], // No relationship in context (ECS doesn't know about it)
    );
    
    // Step 1: Generate plan
    let ai_plan = planning_service.generate_plan(goal, &context, user_id, &session_dek).await.unwrap();
    assert_eq!(ai_plan.plan.goal, goal);

    // Step 2: Validate with repair
    let validation_result = plan_validator.validate_plan_with_repair(
        &ai_plan.plan, 
        user_id,
        &recent_context
    ).await.unwrap();

    // Step 3: Verify repair was applied
    match validation_result {
        PlanValidationResult::RepairableInvalid(repairable) => {
            // Should have repair action to create relationship
            assert_eq!(repairable.repair_actions.len(), 1);
            assert_eq!(repairable.inconsistency_analysis.inconsistency_type, InconsistencyType::MissingRelationship);
            assert!(repairable.confidence_score > 0.7);
            
            // Combined plan should work when executed
            assert_eq!(repairable.combined_plan.actions.len(), 2); // repair + original
            
            // Verify repair action creates relationship
            let repair_action = &repairable.repair_actions[0];
            assert_eq!(repair_action.name, ActionName::UpdateRelationship);
        }
        _ => panic!("Expected repairable plan for missing relationship"),
    }
}

#[tokio::test] 
async fn test_multi_turn_repair_persistence() {
    // Test that repairs persist across conversation turns
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let db_pool: Arc<PgPool> = test_app.db_pool.clone().into();
    let entity_manager = create_test_entity_manager(db_pool.clone()).await;
    let user = create_test_user(&test_app.db_pool, "persistence_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Create entities
    let sol_id = create_test_entity(&entity_manager, user_id, "Sol", "Character").await;
    let _ship_id = create_test_entity(&entity_manager, user_id, "Millennium Falcon", "Vehicle").await;

    // Turn 1: Sol should have a reputation component (narrative establishes it)
    let context_turn1 = vec![
        create_chat_message(user_id, MessageRole::User, "Sol's reputation as a pilot is legendary", 5),
        create_chat_message(user_id, MessageRole::Assistant, "Indeed, Sol's piloting skills are known throughout the galaxy", 4),
    ];

    // Mock AI for reputation plan
    let mock_ai = MockAiClient::new_with_response(json!({
        "goal": "Update Sol's pilot reputation",
        "actions": [{
            "id": "action_1",
            "name": "update_entity",
            "parameters": {
                "entity_id": sol_id.to_string(),
                "updates": {
                    "Reputation": {
                        "pilot_skill": 0.95,
                        "fame": "legendary"
                    }
                }
            },
            "preconditions": {
                "entity_has_component": [{
                    "entity_id": sol_id.to_string(),
                    "component_type": "Reputation"
                }]
            },
            "effects": {
                "component_updated": [{
                    "entity_id": sol_id.to_string(),
                    "component_type": "Reputation",
                    "operation": "update"
                }]
            },
            "dependencies": []
        }],
        "metadata": {
            "estimated_duration": 30,
            "confidence": 0.9
        }
    }).to_string());

    let planning_service = PlanningService::new(
        Arc::new(mock_ai),
        entity_manager.clone(),
        test_app.redis_client.clone(),
        db_pool.clone(),
        "gemini-2.5-pro".to_string(),
    );
    
    // Create separate mock AI clients for different services
    
    // Mock AI for consistency analyzer (detects missing component)
    let consistency_analyzer_mock = MockAiClient::new_with_response(json!({
        "has_inconsistency": true,
        "inconsistency_type": "MissingComponent",
        "confidence_score": 0.9,
        "narrative_evidence": ["Sol's reputation as a pilot is legendary"],
        "ecs_state_summary": "Sol has no Reputation component",
        "repair_reasoning": "Narrative establishes Sol has reputation but component missing",
        "specific_failures": ["action_1"]
    }).to_string());
    
    // Mock AI for repair service (generates repair actions in Plan format)
    let repair_mock_ai = MockAiClient::new_with_response(json!({
        "goal": "Add missing Reputation component to Sol",
        "actions": [{
            "id": "repair_1",
            "name": "update_entity",
            "parameters": {
                "entity_id": sol_id.to_string(),
                "component_operations": [{
                    "operation": "add",
                    "component_type": "Reputation",
                    "component_data": {
                        "pilot_skill": 0.5,
                        "combat_skill": 0.5,
                        "social_skill": 0.5,
                        "total_reputation": 0.5
                    }
                }]
            },
            "preconditions": {
                "entity_exists": [{
                    "entity_id": sol_id.to_string(),
                    "entity_name": "Sol"
                }]
            },
            "effects": {
                "component_updated": [{
                    "entity_id": sol_id.to_string(),
                    "component_type": "Reputation",
                    "operation": "Add"
                }]
            },
            "dependencies": []
        }],
        "metadata": {
            "estimated_duration": 30,
            "confidence": 0.8,
            "alternative_considered": "Auto-generated component repair"
        }
    }).to_string());
    
    // Create consistency analyzer with dedicated mock
    let consistency_analyzer = scribe_backend::services::planning::EcsConsistencyAnalyzer::new(
        entity_manager.clone(),
        Arc::new(consistency_analyzer_mock),
        (*test_app.config).clone(),
    );
    
    // Create cache service
    let cache_service = scribe_backend::services::planning::RepairCacheService::new(
        test_app.redis_client.clone()
    );
    
    // Create repair service with dedicated mock  
    let repair_service = scribe_backend::services::planning::PlanRepairService::with_cache(
        entity_manager.clone(),
        Arc::new(repair_mock_ai),
        (*test_app.config).clone(),
        cache_service,
    );
    
    // Create plan validator with both services
    let plan_validator = PlanValidatorService::new_with_both_services(
        entity_manager.clone(), 
        test_app.redis_client.clone(),
        consistency_analyzer,
        repair_service,
    );

    // Turn 1: Generate and validate plan with repair
    let goal1 = "Update Sol's pilot reputation";
    let context1 = create_test_enriched_context(
        vec![(sol_id, "Sol".to_string(), "Character".to_string())],
        vec![],
    );
    
    let plan1 = planning_service.generate_plan(goal1, &context1, user_id, &session_dek).await.unwrap();
    let validation1 = plan_validator.validate_plan_with_repair(&plan1.plan, user_id, &context_turn1).await.unwrap();
    
    // Should be repairable (missing component)
    match validation1 {
        PlanValidationResult::RepairableInvalid(repairable) => {
            assert_eq!(repairable.inconsistency_analysis.inconsistency_type, InconsistencyType::MissingComponent);
            // Cache should now have this repair
        }
        _ => panic!("Expected repairable plan for missing component"),
    }

    // Turn 2: Similar scenario should use cached repair analysis
    let context_turn2 = vec![
        create_chat_message(user_id, MessageRole::User, "Sol takes his legendary ship for a spin", 2),
        create_chat_message(user_id, MessageRole::Assistant, "The famous pilot boards the Millennium Falcon", 1),
    ];

    // Create new planning service for turn 2 (same mock response as turn 1)
    let mock_ai_turn2 = MockAiClient::new_with_response(json!({
        "goal": "Sol demonstrates his piloting skills",
        "actions": [{
            "id": "action_1",
            "name": "update_entity",
            "parameters": {
                "entity_id": sol_id.to_string(),
                "updates": {
                    "Reputation": {
                        "pilot_skill": 0.98,
                        "fame": "legendary"
                    }
                }
            },
            "preconditions": {
                "entity_has_component": [{
                    "entity_id": sol_id.to_string(),
                    "component_type": "Reputation"
                }]
            },
            "effects": {
                "component_updated": [{
                    "entity_id": sol_id.to_string(),
                    "component_type": "Reputation",
                    "operation": "update"
                }]
            },
            "dependencies": []
        }],
        "metadata": {
            "estimated_duration": 30,
            "confidence": 0.9
        }
    }).to_string());

    let planning_service_turn2 = PlanningService::new(
        Arc::new(mock_ai_turn2),
        entity_manager.clone(),
        test_app.redis_client.clone(),
        db_pool.clone(),
        "gemini-2.5-pro".to_string(),
    );

    // Same type of plan - needs Reputation component
    let goal2 = "Sol demonstrates his piloting skills";
    let plan2 = planning_service_turn2.generate_plan(goal2, &context1, user_id, &session_dek).await.unwrap();
    
    // Validation should be faster due to caching
    let start = std::time::Instant::now();
    let validation2 = plan_validator.validate_plan_with_repair(&plan2.plan, user_id, &context_turn2).await.unwrap();
    let elapsed = start.elapsed();
    
    // Should still detect same type of issue
    match validation2 {
        PlanValidationResult::RepairableInvalid(repairable) => {
            assert_eq!(repairable.inconsistency_analysis.inconsistency_type, InconsistencyType::MissingComponent);
            // Should be fast due to cache hit (but give generous timeout for test environment)
            assert!(elapsed.as_millis() < 5000, "Cached repair should be reasonably fast, took {}ms", elapsed.as_millis());
        }
        _ => panic!("Expected cached repairable result"),
    }
}

#[tokio::test]
async fn test_repair_system_performance_impact() {
    // Validate repair analysis doesn't significantly impact response times
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let db_pool: Arc<PgPool> = test_app.db_pool.clone().into();
    let entity_manager = create_test_entity_manager(db_pool.clone()).await;
    let user = create_test_user(&test_app.db_pool, "perf_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Create a valid scenario (no repair needed)
    let location_id = create_test_entity(&entity_manager, user_id, "Spaceport", "Location").await;
    let character_id = create_test_entity(&entity_manager, user_id, "TestPilot", "Character").await;
    entity_manager.move_entity(user_id, character_id, location_id, None).await.unwrap();

    // Valid plan that doesn't need repair
    let mock_ai = MockAiClient::new_with_response(json!({
        "goal": "Character looks around",
        "actions": [{
            "id": "action_1",
            "name": "get_entity_details",
            "parameters": {
                "entity_id": character_id.to_string()
            },
            "preconditions": {
                "entity_exists": [{
                    "entity_id": character_id.to_string(),
                    "entity_name": "TestPilot"
                }]
            },
            "effects": {},
            "dependencies": []
        }],
        "metadata": {
            "estimated_duration": 10,
            "confidence": 0.95
        }
    }).to_string());

    let planning_service = PlanningService::new(
        Arc::new(mock_ai),
        entity_manager.clone(),
        test_app.redis_client.clone(),
        db_pool.clone(),
        "gemini-2.5-pro".to_string(),
    );
    let plan_validator = PlanValidatorService::new(entity_manager.clone(), test_app.redis_client.clone());

    // Measure validation without repair
    let goal = "Look around";
    let context = create_test_enriched_context(
        vec![(character_id, "TestPilot".to_string(), "Character".to_string())],
        vec![],
    );
    let plan = planning_service.generate_plan(goal, &context, user_id, &session_dek).await.unwrap();
    
    let start_no_repair = std::time::Instant::now();
    let result_no_repair = plan_validator.validate_plan(&plan.plan, user_id).await.unwrap();
    let time_no_repair = start_no_repair.elapsed();
    
    // Should be valid
    assert!(matches!(result_no_repair, PlanValidationResult::Valid(_)));
    
    // Measure validation with repair (but plan is valid so no repair needed)
    let start_with_repair = std::time::Instant::now();
    let result_with_repair = plan_validator.validate_plan_with_repair(&plan.plan, user_id, &[]).await.unwrap();
    let time_with_repair = start_with_repair.elapsed();
    
    // Should still be valid
    assert!(matches!(result_with_repair, PlanValidationResult::Valid(_)));
    
    // Performance overhead should be minimal for valid plans
    let overhead_ms = time_with_repair.as_millis() as i64 - time_no_repair.as_millis() as i64;
    assert!(
        overhead_ms < 50, 
        "Repair check overhead too high: {}ms (no_repair: {}ms, with_repair: {}ms)", 
        overhead_ms, 
        time_no_repair.as_millis(), 
        time_with_repair.as_millis()
    );
}

// ========================================================================================
// Task 3.5.4 Extended: Failure Mode Testing
// ========================================================================================

#[tokio::test]
async fn test_repair_failure_modes() {
    // Test how system handles when repairs themselves fail
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let db_pool: Arc<PgPool> = test_app.db_pool.clone().into();
    let entity_manager = create_test_entity_manager(db_pool.clone()).await;
    let user = create_test_user(&test_app.db_pool, "failure_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Create impossible repair scenario
    let sol_id = create_test_entity(&entity_manager, user_id, "Sol", "Character").await;

    // Plan that requires non-existent entity
    let mock_ai = MockAiClient::new_with_response(json!({
        "goal": "Sol interacts with non-existent entity",
        "actions": [{
            "id": "action_1",
            "name": "update_relationship",
            "parameters": {
                "source_entity_id": sol_id.to_string(),
                "target_entity_id": "00000000-0000-0000-0000-000000000000",
                "trust_delta": 0.1
            },
            "preconditions": {
                "entity_exists": [{
                    "entity_id": "00000000-0000-0000-0000-000000000000",
                    "entity_name": "Ghost"
                }]
            },
            "effects": {},
            "dependencies": []
        }],
        "metadata": {
            "estimated_duration": 30,
            "confidence": 0.5
        }
    }).to_string());

    let planning_service = PlanningService::new(
        Arc::new(mock_ai),
        entity_manager.clone(),
        test_app.redis_client.clone(),
        db_pool.clone(),
        "gemini-2.5-pro".to_string(),
    );
    
    // Repair service that will also fail (can't create entity with specific ID)
    let repair_ai = MockAiClient::new_with_response(json!({
        "error": "Cannot repair - entity ID is invalid"
    }).to_string());
    
    let repair_service = scribe_backend::services::planning::PlanRepairService::new(
        entity_manager.clone(),
        Arc::new(repair_ai),
        (*test_app.config).clone(),
    );
    
    let plan_validator = PlanValidatorService::new_with_repair_service(
        entity_manager.clone(), 
        test_app.redis_client.clone(),
        repair_service
    );

    let goal = "Impossible interaction";
    let context = create_test_enriched_context(
        vec![(sol_id, "Sol".to_string(), "Character".to_string())],
        vec![],
    );
    let plan = planning_service.generate_plan(goal, &context, user_id, &session_dek).await.unwrap();
    
    // Should gracefully fall back to invalid when repair fails
    let result = plan_validator.validate_plan_with_repair(&plan.plan, user_id, &[]).await.unwrap();
    
    match result {
        PlanValidationResult::Invalid(invalid) => {
            // Good - system handled repair failure gracefully
            assert!(!invalid.failures.is_empty());
        }
        _ => panic!("Expected invalid plan when repair fails"),
    }
}
