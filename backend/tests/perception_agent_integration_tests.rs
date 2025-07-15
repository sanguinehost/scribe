use scribe_backend::services::agentic::perception_agent::PerceptionAgent;
use scribe_backend::services::agentic::tactical_agent::TacticalAgent;
use scribe_backend::services::context_assembly_engine::{
    EnrichedContext, EntityContext, SpatialContext, TemporalContext,
    StrategicDirective, EmotionalState, SpatialLocation, RiskAssessment,
    RiskLevel, PlotSignificance, WorldImpactLevel, ValidatedPlan,
    SubGoal, SubGoalStatus, PlanValidationStatus
};
use scribe_backend::services::planning::{PlanningService, PlanValidatorService};
use scribe_backend::services::planning::types::{Plan, Action, ActionName, Parameter};
use scribe_backend::services::chat::ChatService;
use scribe_backend::test_helpers::*;
use scribe_backend::auth::session_dek::SessionDek;
use scribe_backend::errors::AppError;
use scribe_backend::models::chats::{NewChatSession, ChatMessage as DbChatMessage};
use uuid::Uuid;
use std::sync::Arc;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use tokio::time::{sleep, Duration};
use tracing::{info, debug};

// Helper to create a full app state with all agents
async fn create_app_with_agents(app: &TestApp) -> Arc<PerceptionAgent> {
    let planning_service = Arc::new(PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.app_state.pool.clone()),
    ));
    
    let plan_validator = Arc::new(PlanValidatorService::new(
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    ));
    
    Arc::new(PerceptionAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
    ))
}

#[tokio::test]
async fn test_perception_agent_chat_service_integration() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    // Create user and session
    let user = create_test_user(&app, user_id).await;
    let session = app.app_state.chat_service
        .create_session(
            NewChatSession {
                user_id,
                mode: "creative".to_string(),
                model: Some("test-model".to_string()),
                temperature: Some(0.7),
                max_tokens: Some(1000),
                character_id: None,
            },
            &user_dek,
        )
        .await
        .expect("Failed to create session");
    
    // Create perception agent
    let perception_agent = create_app_with_agents(&app).await;
    
    // Simulate chat service generating a response
    let ai_response = "Sol walked into the cantina and ordered a drink.";
    
    // Create enriched context (would normally come from TacticalAgent)
    let context = EnrichedContext {
        strategic_directives: vec![],
        validated_plans: vec![],
        sub_goals: vec![],
        entity_context: HashMap::new(),
        spatial_context: SpatialContext {
            primary_location: SpatialLocation {
                entity_id: Uuid::new_v4(),
                name: "Chamber".to_string(),
                scale: "room".to_string(),
                coordinates: None,
                parent_id: None,
            },
            nearby_locations: vec![],
            scale_context: "intimate".to_string(),
        },
        temporal_context: TemporalContext {
            current_time: Utc::now(),
            time_period: "evening".to_string(),
            recent_events: vec![],
            time_constraints: vec![],
        },
        risk_assessment: RiskAssessment {
            overall_risk: RiskLevel::Low,
            identified_risks: vec![],
            mitigation_strategies: vec![],
        },
        performance_metrics: HashMap::new(),
        context_cache: None,
    };
    
    // Process AI response in background (simulating chat service behavior)
    let agent_clone = perception_agent.clone();
    let response_clone = ai_response.to_string();
    let context_clone = context.clone();
    let dek_clone = user_dek.clone();
    
    let handle = tokio::spawn(async move {
        info!("Starting background perception processing");
        agent_clone.process_ai_response(
            &response_clone,
            &context_clone,
            user_id,
            &dek_clone,
        ).await
    });
    
    // Give background task time to complete
    sleep(Duration::from_millis(100)).await;
    
    // Verify background processing completed
    let result = handle.await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());
}

#[tokio::test]
async fn test_perception_agent_multi_turn_conversation() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    // Create entities that will be referenced
    let sol_id = app.app_state.ecs_entity_manager
        .create_entity_with_components(
            user_id,
            &user_dek,
            "Sol",
            Some("character"),
            vec![],
        )
        .await
        .expect("Failed to create Sol");
    
    let cantina_id = app.app_state.ecs_entity_manager
        .create_entity_with_components(
            user_id,
            &user_dek,
            "Cantina",
            Some("location"),
            vec![],
        )
        .await
        .expect("Failed to create Cantina");
    
    let perception_agent = create_app_with_agents(&app).await;
    
    // Turn 1: Sol enters cantina
    let response1 = "Sol entered the dimly lit cantina.";
    let context1 = create_context_with_entities(sol_id, cantina_id);
    
    let result1 = perception_agent.process_ai_response(
        response1,
        &context1,
        user_id,
        &user_dek,
    ).await;
    assert!(result1.is_ok());
    
    // Turn 2: Sol meets someone
    let response2 = "A hooded figure approached Sol and whispered something urgent.";
    let context2 = create_context_with_entities(sol_id, cantina_id);
    
    let result2 = perception_agent.process_ai_response(
        response2,
        &context2,
        user_id,
        &user_dek,
    ).await;
    assert!(result2.is_ok());
    
    // Verify new entity was created for hooded figure
    let perception_result2 = result2.unwrap();
    assert!(!perception_result2.created_entities.is_empty());
    
    // Turn 3: Action happens
    let response3 = "Sol quickly grabbed the datapad the figure offered and left the cantina.";
    let context3 = create_context_with_entities(sol_id, cantina_id);
    
    let result3 = perception_agent.process_ai_response(
        response3,
        &context3,
        user_id,
        &user_dek,
    ).await;
    assert!(result3.is_ok());
    
    // Verify multiple state changes detected
    let perception_result3 = result3.unwrap();
    assert!(!perception_result3.state_changes.is_empty());
    assert!(perception_result3.state_changes.iter()
        .any(|c| c.change_type == "location_change"));
    assert!(perception_result3.state_changes.iter()
        .any(|c| c.change_type == "inventory_change"));
}

#[tokio::test]
async fn test_perception_agent_parallel_processing() {
    let app = spawn_app(false, false, false).await;
    let perception_agent = create_app_with_agents(&app).await;
    
    // Create multiple users with different sessions
    let mut handles = vec![];
    
    for i in 0..3 {
        let user_id = Uuid::new_v4();
        let user_dek = SessionDek::new(vec![i as u8; 32]);
        let agent_clone = perception_agent.clone();
        
        let handle = tokio::spawn(async move {
            let response = format!("User {}'s character performed action {}", i, i);
            let context = EnrichedContext {
                strategic_directives: vec![],
                validated_plans: vec![],
                sub_goals: vec![],
                entity_context: HashMap::new(),
                spatial_context: SpatialContext {
                    primary_location: SpatialLocation {
                        entity_id: Uuid::new_v4(),
                        name: format!("Location{}", i),
                        scale: "room".to_string(),
                        coordinates: None,
                        parent_id: None,
                    },
                    nearby_locations: vec![],
                    scale_context: "intimate".to_string(),
                },
                temporal_context: TemporalContext {
                    current_time: Utc::now(),
                    time_period: "day".to_string(),
                    recent_events: vec![],
                    time_constraints: vec![],
                },
                risk_assessment: RiskAssessment {
                    overall_risk: RiskLevel::Low,
                    identified_risks: vec![],
                    mitigation_strategies: vec![],
                },
                performance_metrics: HashMap::new(),
                context_cache: None,
            };
            
            agent_clone.process_ai_response(
                &response,
                &context,
                user_id,
                &user_dek,
            ).await
        });
        
        handles.push(handle);
    }
    
    // All parallel processes should complete successfully
    let results: Vec<_> = futures::future::join_all(handles).await;
    for result in results {
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }
}

#[tokio::test]
async fn test_perception_agent_error_recovery() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    let perception_agent = create_app_with_agents(&app).await;
    
    // Test 1: Malformed response recovery
    let malformed_response = "{ broken json }";
    let context = create_basic_context();
    
    let result1 = perception_agent.process_ai_response(
        malformed_response,
        &context,
        user_id,
        &user_dek,
    ).await;
    
    // Should handle gracefully
    assert!(result1.is_ok() || matches!(result1, Err(AppError::BadRequest(_))));
    
    // Test 2: Valid response after error
    let valid_response = "Sol continued their journey.";
    
    let result2 = perception_agent.process_ai_response(
        valid_response,
        &context,
        user_id,
        &user_dek,
    ).await;
    
    // Should process normally after previous error
    assert!(result2.is_ok());
}

#[tokio::test]
async fn test_perception_agent_plan_execution_tracking() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    // Create entities
    let sol_id = app.app_state.ecs_entity_manager
        .create_entity_with_components(
            user_id,
            &user_dek,
            "Sol",
            Some("character"),
            vec![],
        )
        .await
        .expect("Failed to create Sol");
    
    let datapad_id = app.app_state.ecs_entity_manager
        .create_entity_with_components(
            user_id,
            &user_dek,
            "Datapad",
            Some("item"),
            vec![],
        )
        .await
        .expect("Failed to create datapad");
    
    let perception_agent = create_app_with_agents(&app).await;
    
    // Create context with an active plan
    let mut context = create_basic_context();
    context.validated_plans = vec![ValidatedPlan {
        plan_id: Uuid::new_v4(),
        actions: vec![
            Action {
                name: ActionName::AddItemToInventory,
                parameters: vec![
                    Parameter::EntityId(sol_id),
                    Parameter::EntityId(datapad_id),
                    Parameter::Number(1.0),
                ],
                preconditions: vec![],
                effects: vec![],
                description: Some("Sol picks up the datapad".to_string()),
            }
        ],
        validation_status: PlanValidationStatus::Valid,
        confidence_score: 0.9,
        risk_assessment: None,
    }];
    
    // Process response that shows plan execution
    let response = "Sol reached down and picked up the datapad, placing it in their inventory.";
    
    let result = perception_agent.process_ai_response(
        response,
        &context,
        user_id,
        &user_dek,
    ).await;
    
    assert!(result.is_ok());
    let perception_result = result.unwrap();
    
    // Should detect plan execution
    assert!(!perception_result.plan_execution_status.is_empty());
    assert!(perception_result.plan_execution_status.iter()
        .any(|status| status.success));
}

#[tokio::test]
async fn test_perception_agent_unexpected_outcome_detection() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    let perception_agent = create_app_with_agents(&app).await;
    
    // Create context with expected outcome
    let mut context = create_basic_context();
    context.sub_goals = vec![SubGoal {
        goal_id: Uuid::new_v4(),
        description: "Sol successfully negotiates with Borga".to_string(),
        priority: 0.8,
        status: SubGoalStatus::InProgress,
        dependencies: vec![],
        estimated_complexity: 0.5,
    }];
    
    // Process response showing unexpected outcome
    let response = "Borga angrily refused Sol's offer and ordered them to leave immediately.";
    
    let result = perception_agent.process_ai_response(
        response,
        &context,
        user_id,
        &user_dek,
    ).await;
    
    assert!(result.is_ok());
    let perception_result = result.unwrap();
    
    // Should detect deviation from expected outcome
    assert!(!perception_result.deviations.is_empty());
    assert!(perception_result.deviations.iter()
        .any(|d| d.deviation_type == "goal_failure"));
}

// Helper functions

fn create_basic_context() -> EnrichedContext {
    EnrichedContext {
        strategic_directives: vec![],
        validated_plans: vec![],
        sub_goals: vec![],
        entity_context: HashMap::new(),
        spatial_context: SpatialContext {
            primary_location: SpatialLocation {
                entity_id: Uuid::new_v4(),
                name: "Test Location".to_string(),
                scale: "room".to_string(),
                coordinates: None,
                parent_id: None,
            },
            nearby_locations: vec![],
            scale_context: "intimate".to_string(),
        },
        temporal_context: TemporalContext {
            current_time: Utc::now(),
            time_period: "day".to_string(),
            recent_events: vec![],
            time_constraints: vec![],
        },
        risk_assessment: RiskAssessment {
            overall_risk: RiskLevel::Low,
            identified_risks: vec![],
            mitigation_strategies: vec![],
        },
        performance_metrics: HashMap::new(),
        context_cache: None,
    }
}

fn create_context_with_entities(sol_id: Uuid, cantina_id: Uuid) -> EnrichedContext {
    let mut context = create_basic_context();
    
    context.entity_context.insert("Sol".to_string(), EntityContext {
        entity_id: sol_id,
        entity_name: "Sol".to_string(),
        entity_type: "character".to_string(),
        current_state: HashMap::new(),
        recent_actions: vec![],
        emotional_state: EmotionalState {
            primary_emotion: "curious".to_string(),
            intensity: 0.6,
            secondary_emotions: vec![],
        },
    });
    
    context.spatial_context.primary_location = SpatialLocation {
        entity_id: cantina_id,
        name: "Cantina".to_string(),
        scale: "building".to_string(),
        coordinates: None,
        parent_id: None,
    };
    
    context
}

async fn create_test_user(app: &TestApp, user_id: Uuid) -> User {
    use scribe_backend::models::users::NewUser;
    use diesel::prelude::*;
    use scribe_backend::schema::users;
    
    let mut conn = app.app_state.pool.get()
        .await
        .expect("Failed to get connection");
    
    let new_user = NewUser {
        id: user_id,
        username: format!("testuser_{}", user_id),
        email: format!("test{}@example.com", user_id),
        password_hash: "test_hash",
        account_status: "active",
        created_at: Utc::now().naive_utc(),
        updated_at: Utc::now().naive_utc(),
        recovery_key_salt: None,
        recovery_key_hash: None,
        api_usage_updated_at: None,
        api_usage_tokens_used: 0,
        serializable_secret_dek: None,
    };
    
    conn.interact(move |conn| {
        diesel::insert_into(users::table)
            .values(&new_user)
            .get_result::<User>(conn)
    })
    .await
    .expect("Failed to insert user")
    .expect("Failed to create user")
}