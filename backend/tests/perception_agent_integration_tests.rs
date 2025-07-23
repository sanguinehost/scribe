use scribe_backend::services::agentic::perception_agent::PerceptionAgent;
use scribe_backend::services::context_assembly_engine::{
    EnrichedContext, EntityContext, SpatialContext, TemporalContext,
    StrategicDirective, EmotionalState, SpatialLocation, RiskAssessment,
    RiskLevel, PlotSignificance, WorldImpactLevel, ValidatedPlan,
    SubGoal, PlanValidationStatus, PlanStep
};
use scribe_backend::services::planning::{PlanningService, PlanValidatorService};
use scribe_backend::test_helpers::{*, db::create_test_user};
use scribe_backend::auth::session_dek::SessionDek;
use scribe_backend::errors::AppError;
use uuid::Uuid;
use std::sync::Arc;
use std::collections::HashMap;
use chrono::Utc;
use tokio::time::{sleep, Duration};
use tracing::info;

// Helper to create a full app state with all agents
async fn create_app_with_agents(app: &TestApp) -> Arc<PerceptionAgent> {
    let planning_service = Arc::new(PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.app_state.pool.clone()),
        "gemini-2.5-flash".to_string(),
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
        app.app_state.clone(),
        "gemini-2.5-flash".to_string(),
    ))
}

#[tokio::test]
async fn test_perception_agent_chat_service_integration() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    // Create user and session
    let _user = create_test_user(&app.db_pool, format!("testuser_{}", user_id), "password123".to_string()).await.unwrap();
    let session_id = Uuid::new_v4(); // Just use a UUID for testing
    
    // Create perception agent
    let perception_agent = create_app_with_agents(&app).await;
    
    // Simulate chat service generating a response
    let ai_response = "Sol walked into the cantina and ordered a drink.";
    
    // Create enriched context (would normally come from TacticalAgent)
    let context = EnrichedContext {
        strategic_directive: Some(StrategicDirective {
            directive_id: Uuid::new_v4(),
            directive_type: "scene".to_string(),
            narrative_arc: "introduction".to_string(),
            plot_significance: PlotSignificance::Minor,
            emotional_tone: "casual".to_string(),
            character_focus: vec!["Sol".to_string()],
            world_impact_level: WorldImpactLevel::Local,
        }),
        validated_plan: ValidatedPlan {
            plan_id: Uuid::new_v4(),
            steps: vec![],
            preconditions_met: true,
            causal_consistency_verified: true,
            entity_dependencies: vec![],
            estimated_execution_time: None,
            risk_assessment: RiskAssessment {
                overall_risk: RiskLevel::Low,
                identified_risks: vec![],
                mitigation_strategies: vec![],
            },
        },
        current_sub_goal: SubGoal {
            goal_id: Uuid::new_v4(),
            description: "Generate cantina scene".to_string(),
            actionable_directive: "Describe Sol entering cantina".to_string(),
            required_entities: vec!["Sol".to_string()],
            success_criteria: vec![],
            context_requirements: vec![],
            priority_level: 1.0,
        },
        relevant_entities: vec![EntityContext {
            entity_id: Uuid::new_v4(),
            entity_name: "Sol".to_string(),
            entity_type: "character".to_string(),
            current_state: HashMap::new(),
            spatial_location: Some(SpatialLocation {
                location_id: Uuid::new_v4(),
                name: "Chamber".to_string(),
                coordinates: None,
                parent_location: None,
                location_type: "room".to_string(),
            }),
            relationships: vec![],
            recent_actions: vec![],
            emotional_state: None,
            narrative_importance: 0.8,
            ai_insights: vec![],
        }],
        spatial_context: Some(SpatialContext {
            current_location: SpatialLocation {
                location_id: Uuid::new_v4(),
                name: "Chamber".to_string(),
                coordinates: None,
                parent_location: None,
                location_type: "room".to_string(),
            },
            nearby_locations: vec![],
            environmental_factors: vec![],
            spatial_relationships: vec![],
        }),
        causal_context: None,
        temporal_context: Some(TemporalContext {
            current_time: Utc::now(),
            recent_events: vec![],
            future_scheduled_events: vec![],
            temporal_significance: 0.5,
        }),
        plan_validation_status: PlanValidationStatus::Validated,
        symbolic_firewall_checks: vec![],
        assembled_context: None,
        perception_analysis: None,
        total_tokens_used: 0,
        execution_time_ms: 0,
        validation_time_ms: 0,
        ai_model_calls: 0,
        confidence_score: 0.8,
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
    
    // Use simple UUIDs for test entities
    let sol_id = Uuid::new_v4();
    let cantina_id = Uuid::new_v4();
    
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
                strategic_directive: None,
                validated_plan: ValidatedPlan {
                    plan_id: Uuid::new_v4(),
                    steps: vec![],
                    preconditions_met: true,
                    causal_consistency_verified: true,
                    entity_dependencies: vec![],
                    estimated_execution_time: None,
                    risk_assessment: RiskAssessment {
                        overall_risk: RiskLevel::Low,
                        identified_risks: vec![],
                        mitigation_strategies: vec![],
                    },
                },
                current_sub_goal: SubGoal {
                    goal_id: Uuid::new_v4(),
                    description: format!("Process action {}", i),
                    actionable_directive: format!("Handle user {} action", i),
                    required_entities: vec![],
                    success_criteria: vec![],
                    context_requirements: vec![],
                    priority_level: 1.0,
                },
                relevant_entities: vec![],
                spatial_context: Some(SpatialContext {
                    current_location: SpatialLocation {
                        location_id: Uuid::new_v4(),
                        name: format!("Location{}", i),
                        coordinates: None,
                        parent_location: None,
                        location_type: "room".to_string(),
                    },
                    nearby_locations: vec![],
                    environmental_factors: vec![],
                    spatial_relationships: vec![],
                }),
                causal_context: None,
                temporal_context: Some(TemporalContext {
                    current_time: Utc::now(),
                    recent_events: vec![],
                    future_scheduled_events: vec![],
                    temporal_significance: 0.5,
                }),
                plan_validation_status: PlanValidationStatus::Validated,
                symbolic_firewall_checks: vec![],
                assembled_context: None,
                perception_analysis: None,
                total_tokens_used: 0,
                execution_time_ms: 0,
                validation_time_ms: 0,
                ai_model_calls: 0,
                confidence_score: 0.8,
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
    // Use simple UUIDs for test entities
    let sol_id = Uuid::new_v4();
    let datapad_id = Uuid::new_v4();
    
    let perception_agent = create_app_with_agents(&app).await;
    
    // Create context with an active plan
    let mut context = create_basic_context();
    // Update the validated plan - skip Action creation as it's not in the types
    context.validated_plan = ValidatedPlan {
        plan_id: Uuid::new_v4(),
        steps: vec![PlanStep {
            step_id: Uuid::new_v4(),
            description: "Sol picks up the datapad".to_string(),
            preconditions: vec!["Sol is near datapad".to_string()],
            expected_outcomes: vec!["Datapad in Sol's inventory".to_string()],
            required_entities: vec!["Sol".to_string(), "Datapad".to_string()],
            estimated_duration: Some(1000),
        }],
        preconditions_met: true,
        causal_consistency_verified: true,
        entity_dependencies: vec!["Sol".to_string(), "Datapad".to_string()],
        estimated_execution_time: Some(1000),
        risk_assessment: RiskAssessment {
            overall_risk: RiskLevel::Low,
            identified_risks: vec![],
            mitigation_strategies: vec![],
        },
    };
    
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
    context.current_sub_goal = SubGoal {
        goal_id: Uuid::new_v4(),
        description: "Sol successfully negotiates with Borga".to_string(),
        actionable_directive: "Negotiate with Borga".to_string(),
        required_entities: vec!["Sol".to_string(), "Borga".to_string()],
        success_criteria: vec!["Successful negotiation".to_string()],
        context_requirements: vec![],
        priority_level: 0.8,
    };
    
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
        strategic_directive: None,
        validated_plan: ValidatedPlan {
            plan_id: Uuid::new_v4(),
            steps: vec![],
            preconditions_met: true,
            causal_consistency_verified: true,
            entity_dependencies: vec![],
            estimated_execution_time: None,
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
        relevant_entities: vec![],
        spatial_context: Some(SpatialContext {
            current_location: SpatialLocation {
                location_id: Uuid::new_v4(),
                name: "Test Location".to_string(),
                coordinates: None,
                parent_location: None,
                location_type: "room".to_string(),
            },
            nearby_locations: vec![],
            environmental_factors: vec![],
            spatial_relationships: vec![],
        }),
        causal_context: None,
        temporal_context: Some(TemporalContext {
            current_time: Utc::now(),
            recent_events: vec![],
            future_scheduled_events: vec![],
            temporal_significance: 0.5,
        }),
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

fn create_context_with_entities(sol_id: Uuid, cantina_id: Uuid) -> EnrichedContext {
    let mut context = create_basic_context();
    
    context.relevant_entities = vec![EntityContext {
        entity_id: sol_id,
        entity_name: "Sol".to_string(),
        entity_type: "character".to_string(),
        current_state: HashMap::new(),
        spatial_location: Some(SpatialLocation {
            location_id: cantina_id,
            name: "Cantina".to_string(),
            coordinates: None,
            parent_location: None,
            location_type: "building".to_string(),
        }),
        relationships: vec![],
        recent_actions: vec![],
        emotional_state: Some(EmotionalState {
            primary_emotion: "curious".to_string(),
            intensity: 0.6,
            contributing_factors: vec![],
        }),
        narrative_importance: 0.8,
        ai_insights: vec![],
    }];
    
    if let Some(ref mut spatial_context) = context.spatial_context {
        spatial_context.current_location = SpatialLocation {
            location_id: cantina_id,
            name: "Cantina".to_string(),
            coordinates: None,
            parent_location: None,
            location_type: "building".to_string(),
        };
    }
    
    context
}

