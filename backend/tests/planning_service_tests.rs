use scribe_backend::services::planning::{PlanningService, Plan, AiGeneratedPlan, ActionName, PlannedAction};
use scribe_backend::services::context_assembly_engine::{
    EnrichedContext, SubGoal, ValidatedPlan, StrategicDirective, PlotSignificance, 
    WorldImpactLevel, PlanStep, RiskAssessment, RiskLevel, PlanValidationStatus
};
use scribe_backend::test_helpers::*;
use uuid::Uuid;
use std::sync::Arc;
use secrecy::SecretBox;

#[tokio::test]
async fn test_planning_service_creation() {
    let app = spawn_app(false, false, false).await;
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    // Service should be created successfully
    let _ = planning_service; // Just ensure it compiles and creates
}

#[tokio::test]
async fn test_generate_simple_movement_plan() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    // Create test context
    let context = create_test_enriched_context("Move Sol to the cantina");
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    // Create a test user DEK
    let user_dek = Arc::new(SecretBox::new(Box::new(vec![0u8; 32])));

    // Generate plan (currently returns placeholder)
    let result = planning_service.generate_plan(
        "Sol needs to go to the cantina",
        &context,
        user_id,
        &user_dek,
    ).await;

    assert!(result.is_ok());
    let plan = result.unwrap();
    assert_eq!(plan.plan.goal, "Sol needs to go to the cantina");
}

#[tokio::test]
async fn test_plan_caching_same_goal() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let context = create_test_enriched_context("Find Borga");
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    // Create a test user DEK
    let user_dek = Arc::new(SecretBox::new(Box::new(vec![0u8; 32])));

    // First call - should generate new plan
    let result1 = planning_service.generate_plan(
        "Sol needs to find Borga",
        &context,
        user_id,
        &user_dek,
    ).await;

    assert!(result1.is_ok());
    
    // Second call with same goal and context - should use cache (when implemented)
    let result2 = planning_service.generate_plan(
        "Sol needs to find Borga",
        &context,
        user_id,
        &user_dek,
    ).await;

    assert!(result2.is_ok());
}

#[tokio::test]
async fn test_plan_caching_different_users() {
    let app = spawn_app(false, false, false).await;
    let user1_id = Uuid::new_v4();
    let user2_id = Uuid::new_v4();
    
    let context = create_test_enriched_context("Find Borga");
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    // Create test user DEKs
    let user_dek1 = Arc::new(SecretBox::new(Box::new(vec![0u8; 32])));
    let user_dek2 = Arc::new(SecretBox::new(Box::new(vec![1u8; 32])));

    // Different users should have different cache entries
    let result1 = planning_service.generate_plan(
        "Sol needs to find Borga",
        &context,
        user1_id,
        &user_dek1,
    ).await;

    let result2 = planning_service.generate_plan(
        "Sol needs to find Borga",
        &context,
        user2_id,
        &user_dek2,
    ).await;

    assert!(result1.is_ok());
    assert!(result2.is_ok());
    
    // When implemented with real caching, should verify cache keys differ
}

#[tokio::test]
async fn test_complex_plan_generation() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let context = create_test_enriched_context("Complex multi-step goal");
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    // Create a test user DEK
    let user_dek = Arc::new(SecretBox::new(Box::new(vec![0u8; 32])));

    let result = planning_service.generate_plan(
        "Sol needs to find Borga, negotiate for the datapad, and return to base",
        &context,
        user_id,
        &user_dek,
    ).await;

    assert!(result.is_ok());
    let plan = result.unwrap();
    
    // When implemented, should have multiple actions
    assert!(plan.plan.goal.contains("Borga"));
    assert!(plan.plan.goal.contains("datapad"));
}

// Helper function to create test EnrichedContext
fn create_test_enriched_context(goal: &str) -> EnrichedContext {
    use scribe_backend::services::planning::types::ContextCache;
    use std::collections::HashMap;
    
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
            description: goal.to_string(),
            actionable_directive: goal.to_string(),
            required_entities: vec![],
            success_criteria: vec![],
            context_requirements: vec![],
            priority_level: 1.0,
        },
        relevant_entities: vec![],
        spatial_context: None,
        temporal_context: None,
        causal_context: None,
        plan_validation_status: PlanValidationStatus::Validated,
        symbolic_firewall_checks: vec![],
        assembled_context: None,
        total_tokens_used: 0,
        execution_time_ms: 0,
        validation_time_ms: 10,
        ai_model_calls: 0,
        confidence_score: 0.9,
    }
}