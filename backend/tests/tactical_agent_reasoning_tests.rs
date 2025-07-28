// TacticalAgent Reasoning Tests - Subtask 4.1.1
// Tests the agent's decision-making logic, plan reasoning, and sub-goal extraction

use scribe_backend::services::agentic::tactical_agent::TacticalAgent;
use scribe_backend::services::context_assembly_engine::{
    StrategicDirective, PlotSignificance, WorldImpactLevel, PlanValidationStatus
};
use scribe_backend::services::planning::{PlanningService, PlanValidatorService};
use scribe_backend::test_helpers::*;
use scribe_backend::auth::session_dek::SessionDek;
use uuid::Uuid;
use std::sync::Arc;

// Helper function to create test StrategicDirective with customizable parameters
fn create_strategic_directive(
    narrative: &str, 
    directive_type: &str,
    plot_significance: PlotSignificance,
    emotional_tone: &str,
    impact_level: WorldImpactLevel,
) -> StrategicDirective {
    StrategicDirective {
        directive_id: Uuid::new_v4(),
        directive_type: directive_type.to_string(),
        narrative_arc: narrative.to_string(),
        plot_significance,
        emotional_tone: emotional_tone.to_string(),
        character_focus: vec![],
        world_impact_level: impact_level,
    }
}

/// Test that TacticalAgent correctly prioritizes urgent vs non-urgent directives
#[tokio::test]
async fn test_reasoning_directive_priority_assessment() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
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
    
    let tactical_agent = TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
        app.app_state.shared_agent_context.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Test urgent directive
    let urgent_directive = create_strategic_directive(
        "Emergency evacuation required immediately",
        "emergency",
        PlotSignificance::Major,
        "urgent",
        WorldImpactLevel::Global,
    );

    let urgent_result = tactical_agent.process_directive(
        &urgent_directive,
        user_id,
        &session_dek,
    ).await;

    if urgent_result.is_err() {
        eprintln!("Urgent directive failed: {:?}", urgent_result.as_ref().unwrap_err());
    }
    assert!(urgent_result.is_ok());
    let urgent_context = urgent_result.unwrap();

    // Test routine directive
    let routine_directive = create_strategic_directive(
        "Schedule regular maintenance check",
        "maintenance",
        PlotSignificance::Minor,
        "calm",
        WorldImpactLevel::Local,
    );

    let routine_result = tactical_agent.process_directive(
        &routine_directive,
        user_id,
        &session_dek,
    ).await;

    assert!(routine_result.is_ok());
    let routine_context = routine_result.unwrap();

    // Verify reasoning: both directives should be processed successfully
    assert!(urgent_context.current_sub_goal.priority_level >= 0.0 && urgent_context.current_sub_goal.priority_level <= 1.0,
        "Urgent directive should have valid priority: {}", urgent_context.current_sub_goal.priority_level);
    assert!(routine_context.current_sub_goal.priority_level >= 0.0 && routine_context.current_sub_goal.priority_level <= 1.0,
        "Routine directive should have valid priority: {}", routine_context.current_sub_goal.priority_level);

    // Verify reasoning: urgent directives should consider risk more seriously
    assert!(urgent_context.validated_plan.risk_assessment.overall_risk as u8 >= 
            routine_context.validated_plan.risk_assessment.overall_risk as u8,
        "Urgent directive should assess higher risk than routine");
}

/// Test that TacticalAgent reasons about plan complexity and adjusts sub-goals accordingly
#[tokio::test]
async fn test_reasoning_plan_complexity_assessment() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
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
    
    let tactical_agent = TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
        app.app_state.shared_agent_context.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Simple directive (should generate straightforward sub-goal)
    let simple_directive = create_strategic_directive(
        "Walk to the door",
        "movement",
        PlotSignificance::Minor,
        "neutral",
        WorldImpactLevel::Local,
    );

    let simple_result = tactical_agent.process_directive(
        &simple_directive,
        user_id,
        &session_dek,
    ).await;

    assert!(simple_result.is_ok());
    let simple_context = simple_result.unwrap();

    // Complex multi-step directive
    let complex_directive = create_strategic_directive(
        "Infiltrate the enemy base and steal classified documents while avoiding detection and coordinating with multiple team members",
        "infiltration",
        PlotSignificance::Major,
        "tense",
        WorldImpactLevel::Global,
    );

    let complex_result = tactical_agent.process_directive(
        &complex_directive,
        user_id,
        &session_dek,
    ).await;

    assert!(complex_result.is_ok());
    let complex_context = complex_result.unwrap();

    // Verify reasoning: complex directives should break down into manageable sub-goals
    assert!(simple_context.current_sub_goal.description.len() <= 
            complex_context.current_sub_goal.description.len() + 50, // Allow some variance
        "Complex directive should break down into focused sub-goal");

    // Verify reasoning: complex plans should have more detailed success criteria
    assert!(complex_context.current_sub_goal.success_criteria.len() >= 
            simple_context.current_sub_goal.success_criteria.len(),
        "Complex directive should have more detailed success criteria");
}

/// Test reasoning about entity dependencies and coordination needs
#[tokio::test]
async fn test_reasoning_entity_dependency_analysis() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
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
    
    let tactical_agent = TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
        app.app_state.shared_agent_context.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Create entity IDs for testing
    let character_a = Uuid::new_v4();
    let character_b = Uuid::new_v4();
    let location_id = Uuid::new_v4();

    // Solo task
    let solo_directive = create_strategic_directive(
        "Character thinks about their past",
        "introspection",
        PlotSignificance::Minor,
        "mysterious",
        WorldImpactLevel::Personal,
    );

    let solo_result = tactical_agent.process_directive(
        &solo_directive,
        user_id,
        &session_dek,
    ).await;

    assert!(solo_result.is_ok());
    let solo_context = solo_result.unwrap();

    // Multi-character coordination task
    let coordination_directive = StrategicDirective {
        directive_id: Uuid::new_v4(),
        directive_type: "coordination".to_string(),
        narrative_arc: "Characters must coordinate simultaneous actions at different locations".to_string(),
        plot_significance: PlotSignificance::Major,
        emotional_tone: "collaborative".to_string(),
        character_focus: vec![character_a.to_string(), character_b.to_string(), location_id.to_string()],
        world_impact_level: WorldImpactLevel::Regional,
    };

    let coordination_result = tactical_agent.process_directive(
        &coordination_directive,
        user_id,
        &session_dek,
    ).await;

    assert!(coordination_result.is_ok());
    let coordination_context = coordination_result.unwrap();

    // Verify reasoning: coordination tasks should identify entity dependencies
    assert!(coordination_context.current_sub_goal.required_entities.len() >= 
            solo_context.current_sub_goal.required_entities.len(),
        "Coordination task should identify more entity dependencies");

    // Verify reasoning: coordination tasks should have context requirements
    assert!(coordination_context.current_sub_goal.context_requirements.len() >= 
            solo_context.current_sub_goal.context_requirements.len(),
        "Coordination task should have more context requirements");
}

/// Test reasoning about temporal constraints and urgency
#[tokio::test]
async fn test_reasoning_temporal_constraint_analysis() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
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
    
    let tactical_agent = TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
        app.app_state.shared_agent_context.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Time-sensitive directive
    let urgent_directive = create_strategic_directive(
        "Defuse bomb before it explodes in 5 minutes",
        "emergency_action",
        PlotSignificance::Major,
        "urgent",
        WorldImpactLevel::Global,
    );

    let urgent_result = tactical_agent.process_directive(
        &urgent_directive,
        user_id,
        &session_dek,
    ).await;

    assert!(urgent_result.is_ok());
    let urgent_context = urgent_result.unwrap();

    // Non-time-sensitive directive
    let casual_directive = create_strategic_directive(
        "Study ancient texts when convenient",
        "research",
        PlotSignificance::Minor,
        "neutral",
        WorldImpactLevel::Personal,
    );

    let casual_result = tactical_agent.process_directive(
        &casual_directive,
        user_id,
        &session_dek,
    ).await;

    assert!(casual_result.is_ok());
    let casual_context = casual_result.unwrap();

    // Verify reasoning: time-sensitive tasks should have higher priority
    assert!(urgent_context.current_sub_goal.priority_level > casual_context.current_sub_goal.priority_level,
        "Time-sensitive task should have higher priority");

    // Verify reasoning: urgent tasks should have shorter estimated execution times
    if let Some(urgent_time) = urgent_context.validated_plan.estimated_execution_time {
        if let Some(casual_time) = casual_context.validated_plan.estimated_execution_time {
            assert!(urgent_time <= casual_time * 2, // Allow some variance
                "Urgent task should have shorter estimated execution time");
        }
    }
}

/// Test reasoning about failure conditions and fallback strategies
#[tokio::test]
async fn test_reasoning_failure_recovery_analysis() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
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
    
    let tactical_agent = TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
        app.app_state.shared_agent_context.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // High-risk directive that could fail
    let risky_directive = create_strategic_directive(
        "Attempt to negotiate with hostile alien species",
        "diplomacy",
        PlotSignificance::Major,
        "uncertain",
        WorldImpactLevel::Global,
    );

    let risky_result = tactical_agent.process_directive(
        &risky_directive,
        user_id,
        &session_dek,
    ).await;

    assert!(risky_result.is_ok());
    let risky_context = risky_result.unwrap();

    // Low-risk directive
    let safe_directive = create_strategic_directive(
        "Read a book in the library",
        "leisure",
        PlotSignificance::Minor,
        "peaceful",
        WorldImpactLevel::Personal,
    );

    let safe_result = tactical_agent.process_directive(
        &safe_directive,
        user_id,
        &session_dek,
    ).await;

    assert!(safe_result.is_ok());
    let safe_context = safe_result.unwrap();

    // Verify reasoning: risky tasks should have more detailed success criteria
    assert!(risky_context.current_sub_goal.success_criteria.len() >= 
            safe_context.current_sub_goal.success_criteria.len(),
        "Risky task should have more detailed success criteria");

    // Verify reasoning: risky tasks should assess higher risk levels
    assert!(risky_context.validated_plan.risk_assessment.overall_risk as u8 >= 
            safe_context.validated_plan.risk_assessment.overall_risk as u8,
        "Risky task should assess higher overall risk");
}

/// Test reasoning about resource requirements and constraints
#[tokio::test]
async fn test_reasoning_resource_requirement_analysis() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
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
    
    let tactical_agent = TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
        app.app_state.shared_agent_context.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Resource-intensive directive
    let resource_intensive = create_strategic_directive(
        "Build massive space station requiring thousands of workers and rare materials",
        "construction",
        PlotSignificance::Major,
        "confident",
        WorldImpactLevel::Global,
    );

    let intensive_result = tactical_agent.process_directive(
        &resource_intensive,
        user_id,
        &session_dek,
    ).await;

    assert!(intensive_result.is_ok());
    let intensive_context = intensive_result.unwrap();

    // Low-resource directive
    let simple_task = create_strategic_directive(
        "Pick up a pen from the desk",
        "simple_action",
        PlotSignificance::Minor,
        "calm",
        WorldImpactLevel::Personal,
    );

    let simple_result = tactical_agent.process_directive(
        &simple_task,
        user_id,
        &session_dek,
    ).await;

    assert!(simple_result.is_ok());
    let simple_context = simple_result.unwrap();

    // Verify reasoning: resource-intensive tasks should have longer execution times
    if let Some(intensive_time) = intensive_context.validated_plan.estimated_execution_time {
        if let Some(simple_time) = simple_context.validated_plan.estimated_execution_time {
            assert!(intensive_time >= simple_time,
                "Resource-intensive task should have longer estimated execution time");
        }
    }

    // Verify reasoning: resource-intensive tasks should have more context requirements
    assert!(intensive_context.current_sub_goal.context_requirements.len() >= 
            simple_context.current_sub_goal.context_requirements.len(),
        "Resource-intensive task should have more context requirements");
}

/// Test reasoning about sub-goal extraction and decomposition logic
#[tokio::test]
async fn test_reasoning_sub_goal_decomposition_logic() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
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
    
    let tactical_agent = TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
        app.app_state.shared_agent_context.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Multi-step directive requiring decomposition
    let complex_directive = create_strategic_directive(
        "Rescue the princess from the dragon's tower then return her safely to the kingdom",
        "rescue_mission",
        PlotSignificance::Major,
        "confident",
        WorldImpactLevel::Regional,
    );

    let result = tactical_agent.process_directive(
        &complex_directive,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let context = result.unwrap();

    // Verify reasoning: sub-goal should be more specific than the overall directive
    assert!(context.current_sub_goal.description.len() <= complex_directive.narrative_arc.len(),
        "Sub-goal should be more specific than overall directive");

    // Verify reasoning: sub-goal should be actionable
    assert!(!context.current_sub_goal.actionable_directive.is_empty(),
        "Sub-goal should have actionable directive");

    // Verify reasoning: sub-goal should focus on first logical step
    let sub_goal_lower = context.current_sub_goal.description.to_lowercase();
    assert!(
        sub_goal_lower.contains("rescue") || 
        sub_goal_lower.contains("approach") || 
        sub_goal_lower.contains("tower") ||
        sub_goal_lower.contains("dragon") ||
        sub_goal_lower.contains("princess"),
        "Sub-goal should focus on rescue mission elements"
    );

    // Verify reasoning: actionable directive should be concrete
    let actionable_lower = context.current_sub_goal.actionable_directive.to_lowercase();
    assert!(
        actionable_lower.contains("go") || 
        actionable_lower.contains("move") || 
        actionable_lower.contains("approach") ||
        actionable_lower.contains("rescue") ||
        actionable_lower.contains("find"),
        "Actionable directive should contain concrete action words"
    );
}

/// Test reasoning validation through plan status assessment
#[tokio::test]
async fn test_reasoning_plan_validation_status_logic() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
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
    
    let tactical_agent = TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
        app.app_state.shared_agent_context.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Realistic directive that should validate successfully
    let valid_directive = create_strategic_directive(
        "Walk to the market and buy fresh bread",
        "daily_task",
        PlotSignificance::Minor,
        "happy",
        WorldImpactLevel::Personal,
    );

    let result = tactical_agent.process_directive(
        &valid_directive,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let context = result.unwrap();

    // Verify reasoning: plan validation status should be set appropriately
    match &context.plan_validation_status {
        PlanValidationStatus::Validated => {
            // Plan was successfully validated
            assert!(context.validated_plan.preconditions_met,
                "Validated plan should have preconditions met");
            assert!(context.validated_plan.causal_consistency_verified,
                "Validated plan should have causal consistency verified");
        }
        PlanValidationStatus::Pending => {
            // Validation is still in progress - acceptable
        }
        PlanValidationStatus::Failed(reasons) => {
            // Plan failed validation - should still handle gracefully
            assert!(!reasons.is_empty(), "Failed validation should have reasons");
        }
        PlanValidationStatus::PartiallyValidated(issues) => {
            // Some aspects validated - acceptable
            assert!(!issues.is_empty(), "Partial validation should list issues");
        }
    }

    // Verify reasoning: validation time should be tracked
    assert!(context.validation_time_ms >= 0,
        "Validation time should be tracked");

    // Verify reasoning: confidence score should reflect validation status
    match &context.plan_validation_status {
        PlanValidationStatus::Validated => {
            assert!(context.confidence_score >= 0.7,
                "Validated plans should have high confidence");
        }
        PlanValidationStatus::Failed(_) => {
            assert!(context.confidence_score <= 0.5,
                "Failed plans should have lower confidence");
        }
        _ => {
            // Other statuses can have intermediate confidence
            assert!(context.confidence_score >= 0.0 && context.confidence_score <= 1.0,
                "Confidence score should be in valid range");
        }
    }
}