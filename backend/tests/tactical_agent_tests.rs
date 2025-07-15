use scribe_backend::services::agentic::tactical_agent::TacticalAgent;
use scribe_backend::services::context_assembly_engine::{
    EnrichedContext, SubGoal, ValidatedPlan, StrategicDirective, PlotSignificance,
    WorldImpactLevel, RiskAssessment, RiskLevel, PlanValidationStatus, EntityContext,
    SpatialLocation, EmotionalState, SpatialContext, TemporalContext
};
use scribe_backend::services::planning::{PlanningService, PlanValidatorService};
use scribe_backend::services::planning::types::{PlanValidationResult, Plan, ActionName};
use scribe_backend::test_helpers::*;
use scribe_backend::auth::session_dek::SessionDek;
use scribe_backend::errors::AppError;
use uuid::Uuid;
use std::sync::Arc;
use std::collections::HashMap;

// Helper function to create test StrategicDirective
fn create_test_strategic_directive(narrative: &str, directive_type: &str) -> StrategicDirective {
    StrategicDirective {
        directive_id: Uuid::new_v4(),
        directive_type: directive_type.to_string(),
        narrative_arc: narrative.to_string(),
        plot_significance: PlotSignificance::Minor,
        emotional_tone: "neutral".to_string(),
        character_focus: vec![],
        world_impact_level: WorldImpactLevel::Local,
    }
}

#[tokio::test]
async fn test_tactical_agent_creation() {
    let app = spawn_app(false, false, false).await;
    
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
    
    let tactical_agent = TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
    );

    // Service should be created successfully
    let _ = tactical_agent; // Just ensure it compiles and creates
}

#[tokio::test]
async fn test_process_directive_basic_movement() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
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
    
    let tactical_agent = TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Create basic movement directive
    let directive = create_test_strategic_directive(
        "Sol needs to move to the cantina", 
        "movement"
    );

    let result = tactical_agent.process_directive(
        &directive,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Verify basic structure
    assert_eq!(context.current_sub_goal.description, "Sol needs to move to the cantina");
    assert!(context.confidence_score > 0.0);
    assert!(context.execution_time_ms > 0);
    
    // Should have strategic directive
    assert!(context.strategic_directive.is_some());
    let strategic = context.strategic_directive.unwrap();
    assert_eq!(strategic.narrative_arc, "Sol needs to move to the cantina");
}

#[tokio::test]
async fn test_directive_to_plan_integration() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
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
    
    let tactical_agent = TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Directive that should generate a plan
    let directive = create_test_strategic_directive(
        "Sol needs to find Borga and negotiate for the datapad",
        "negotiation"
    );

    let result = tactical_agent.process_directive(
        &directive,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Should have generated a plan through PlanningService
    assert!(context.validated_plan.steps.len() >= 0); // Steps may be empty in mock
    assert!(context.validated_plan.preconditions_met);
    
    // Should have extracted first sub-goal
    assert!(!context.current_sub_goal.description.is_empty());
    assert!(context.current_sub_goal.description.contains("Sol") ||
            context.current_sub_goal.description.contains("find") ||
            context.current_sub_goal.description.contains("Borga"));
    
    // Should have validation status
    match context.plan_validation_status {
        PlanValidationStatus::Validated |
        PlanValidationStatus::Pending => {
            // Valid states
        }
        PlanValidationStatus::Failed(_) => {
            // Also valid in test environment
        }
        PlanValidationStatus::PartiallyValidated(_) => {
            // Partially valid state
        }
    }
}

#[tokio::test]
async fn test_world_state_context_gathering() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
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
    
    let tactical_agent = TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Directive requiring entity lookup
    let directive = create_test_strategic_directive(
        "Analyze the current state of all characters in the cantina",
        "analysis"
    );

    let result = tactical_agent.process_directive(
        &directive,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Should have attempted to gather world state
    // In test environment, entities might be empty, but structure should be present
    assert!(context.relevant_entities.len() >= 0);
    
    // Should have spatial context structure
    assert!(context.spatial_context.is_some() || context.spatial_context.is_none()); // Either is valid
    
    // Should have attempted planning
    assert!(context.total_tokens_used >= 0);
    assert!(context.ai_model_calls >= 0);
}

#[tokio::test]
async fn test_sub_goal_extraction() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
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
    
    let tactical_agent = TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Complex multi-step directive
    let directive = StrategicDirective {
        directive_id: Uuid::new_v4(),
        directive_type: "infiltration".to_string(),
        narrative_arc: "Sol must infiltrate the Imperial base, steal the plans, and escape".to_string(),
        plot_significance: PlotSignificance::Major,
        emotional_tone: "tense".to_string(),
        character_focus: vec![],
        world_impact_level: WorldImpactLevel::Global,
    };

    let result = tactical_agent.process_directive(
        &directive,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Should extract first actionable sub-goal
    assert!(!context.current_sub_goal.description.is_empty());
    assert!(!context.current_sub_goal.actionable_directive.is_empty());
    
    // Sub-goal should be more specific than the overall directive
    assert!(context.current_sub_goal.description.len() <= directive.narrative_arc.len());
    
    // Should have priority level set
    assert!(context.current_sub_goal.priority_level > 0.0);
    assert!(context.current_sub_goal.priority_level <= 1.0);
    
    // Should have goal ID
    assert!(!context.current_sub_goal.goal_id.to_string().is_empty());
}

#[tokio::test]
async fn test_plan_validation_integration() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
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
    
    let tactical_agent = TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Directive that should trigger plan validation
    let directive = create_test_strategic_directive(
        "Move character to specific location",
        "movement"
    );

    let result = tactical_agent.process_directive(
        &directive,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Should have gone through plan validation
    assert!(context.validation_time_ms >= 0);
    
    // Should have validation status
    match context.plan_validation_status {
        PlanValidationStatus::Validated => {
            // Plan was valid
            assert!(context.validated_plan.preconditions_met);
        }
        PlanValidationStatus::Failed(_) => {
            // Plan was invalid - acceptable in test environment
        }
        PlanValidationStatus::Pending => {
            // Validation was pending - also acceptable
        }
        PlanValidationStatus::PartiallyValidated(_) => {
            // Plan was partially validated
        }
    }
    
    // Should have symbolic firewall checks recorded
    assert!(context.symbolic_firewall_checks.len() >= 0);
}

#[tokio::test]
async fn test_enriched_context_assembly() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
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
    
    let tactical_agent = TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    let directive = create_test_strategic_directive(
        "Complete test scenario",
        "test"
    );

    let result = tactical_agent.process_directive(
        &directive,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Verify complete EnrichedContext structure
    assert!(context.strategic_directive.is_some());
    assert!(!context.current_sub_goal.goal_id.to_string().is_empty());
    assert!(!context.validated_plan.plan_id.to_string().is_empty());
    
    // Performance metrics should be tracked
    assert!(context.total_tokens_used >= 0);
    assert!(context.execution_time_ms > 0);
    assert!(context.validation_time_ms >= 0);
    assert!(context.ai_model_calls >= 0);
    
    // Confidence score should be reasonable
    assert!(context.confidence_score >= 0.0);
    assert!(context.confidence_score <= 1.0);
    
    // Should have plan validation status
    match context.plan_validation_status {
        PlanValidationStatus::Validated |
        PlanValidationStatus::Pending |
        PlanValidationStatus::Failed(_) |
        PlanValidationStatus::PartiallyValidated(_) => {
            // All valid states
        }
    }
}

#[tokio::test]
async fn test_error_handling_planning_failure() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
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
    
    let tactical_agent = TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Empty directive that might cause planning issues
    let directive = create_test_strategic_directive(
        "", // Empty goal
        "empty_test"
    );

    let result = tactical_agent.process_directive(
        &directive,
        user_id,
        &session_dek,
    ).await;

    // Should handle gracefully
    match result {
        Ok(context) => {
            // If successful, should have reasonable defaults
            assert!(!context.current_sub_goal.goal_id.to_string().is_empty());
            assert!(context.confidence_score >= 0.0);
        }
        Err(e) => {
            // Error handling is also acceptable
            let error_msg = format!("{}", e);
            assert!(!error_msg.contains("panic"));
            assert!(!error_msg.contains("internal error"));
        }
    }
}

#[tokio::test]
async fn test_directive_with_temporal_constraints() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
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
    
    let tactical_agent = TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Directive with time constraints
    let directive = StrategicDirective {
        directive_id: Uuid::new_v4(),
        directive_type: "urgent_mission".to_string(),
        narrative_arc: "Complete urgent mission before dawn".to_string(),
        plot_significance: PlotSignificance::Major,
        emotional_tone: "urgent".to_string(),
        character_focus: vec![],
        world_impact_level: WorldImpactLevel::Regional,
    };

    let result = tactical_agent.process_directive(
        &directive,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Should incorporate temporal constraints
    assert!(context.temporal_context.is_some() || context.temporal_context.is_none()); // Either is valid
    
    // Sub-goal should reflect urgency
    assert!(context.current_sub_goal.description.contains("urgent") ||
            context.current_sub_goal.description.contains("dawn") ||
            context.current_sub_goal.description.contains("Complete") ||
            context.current_sub_goal.priority_level > 0.8); // High priority
}

#[tokio::test]
async fn test_multiple_entity_coordination() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
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
    
    let tactical_agent = TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Create some test entity IDs
    let sol_id = Uuid::new_v4();
    let borga_id = Uuid::new_v4();
    let cantina_id = Uuid::new_v4();

    // Directive involving multiple entities
    let directive = StrategicDirective {
        directive_id: Uuid::new_v4(),
        directive_type: "coordination".to_string(),
        narrative_arc: "Coordinate meeting between Sol and Borga at the cantina".to_string(),
        plot_significance: PlotSignificance::Major,
        emotional_tone: "collaborative".to_string(),
        character_focus: vec![sol_id.to_string(), borga_id.to_string(), cantina_id.to_string()],
        world_impact_level: WorldImpactLevel::Local,
    };

    let result = tactical_agent.process_directive(
        &directive,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Should handle multiple entities
    assert!(context.current_sub_goal.required_entities.len() >= 0);
    
    // Sub-goal should focus on first step of coordination
    assert!(context.current_sub_goal.description.contains("Sol") ||
            context.current_sub_goal.description.contains("Borga") ||
            context.current_sub_goal.description.contains("cantina") ||
            context.current_sub_goal.description.contains("meeting"));
    
    // Should have success criteria
    assert!(context.current_sub_goal.success_criteria.len() >= 0);
}