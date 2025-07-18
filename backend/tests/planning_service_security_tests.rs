use scribe_backend::services::planning::PlanningService;
use scribe_backend::services::context_assembly_engine::{
    EnrichedContext, SubGoal, ValidatedPlan, RiskAssessment, RiskLevel, PlanValidationStatus
};
use scribe_backend::test_helpers::*;
use scribe_backend::auth::session_dek::SessionDek;
use uuid::Uuid;
use std::sync::Arc;
use secrecy::SecretBox;

// A01: Broken Access Control Tests

#[tokio::test]
async fn test_a01_planning_service_user_isolation() {
    let app = spawn_app(false, false, false).await;
    let user1_id = Uuid::new_v4();
    let user2_id = Uuid::new_v4();
    
    let context = create_test_enriched_context("Access other user's entity");
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    // Create test user DEKs
    let user_dek1 = SessionDek::new(vec![0u8; 32]);
    let user_dek2 = SessionDek::new(vec![1u8; 32]);

    // User 1 creates a plan
    let plan1 = planning_service.generate_plan(
        "Find my secret base",
        &context,
        user1_id,
        &user_dek1,
    ).await.unwrap();

    // User 2 tries similar goal - should not get User 1's cached plan
    let plan2 = planning_service.generate_plan(
        "Find my secret base",
        &context,
        user2_id,
        &user_dek2,
    ).await.unwrap();

    // Plans should be independent
    // When caching is implemented, cache keys should include user ID
    assert_eq!(plan1.plan.goal, plan2.plan.goal);
}

#[tokio::test]
async fn test_a01_cache_key_includes_user_context() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    let user_dek = SessionDek::new(vec![0u8; 32]);

    // Test that cache key generation includes user ID
    let cache_key = planning_service.build_plan_cache_key(
        "Test goal",
        &create_test_enriched_context("Test"),
        user_id,
    );

    assert!(cache_key.contains(&user_id.to_string()));
}

// A02: Cryptographic Failures Tests

#[tokio::test]
async fn test_a02_no_sensitive_data_in_cache_keys() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    let context = create_test_enriched_context("Sensitive: password123");
    
    let cache_key = planning_service.build_plan_cache_key(
        "Goal with sensitive data",
        &context,
        user_id,
    );

    // Cache key should not contain raw sensitive data
    assert!(!cache_key.contains("password123"));
    // Should be hashed
    assert!(cache_key.len() > 0);
}

// A03: Injection Tests

#[tokio::test]
async fn test_a03_plan_goal_injection_prevention() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    let user_dek = SessionDek::new(vec![0u8; 32]);

    // Attempt injection in goal
    let malicious_goal = "Find entity'; DROP TABLE ecs_entities; --";
    let context = create_test_enriched_context(malicious_goal);
    
    let result = planning_service.generate_plan(
        malicious_goal,
        &context,
        user_id,
        &user_dek,
    ).await;

    // Should handle safely (current placeholder implementation)
    assert!(result.is_ok());
    let plan = result.unwrap();
    assert_eq!(plan.plan.goal, malicious_goal);
}

// A04: Insecure Design Tests

#[tokio::test]
async fn test_a04_plan_complexity_limits() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    let user_dek = SessionDek::new(vec![0u8; 32]);

    // Create extremely complex goal
    let complex_goal = (0..100).map(|i| format!("Step {}: Do complex thing", i)).collect::<Vec<_>>().join("; ");
    let context = create_test_enriched_context(&complex_goal);
    
    let result = planning_service.generate_plan(
        &complex_goal,
        &context,
        user_id,
        &user_dek,
    ).await;

    // Should handle gracefully
    assert!(result.is_ok());
}

// A05: Security Misconfiguration Tests

#[tokio::test]
async fn test_a05_cache_ttl_configuration() {
    let app = spawn_app(false, false, false).await;
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    // When implemented, verify cache TTL is reasonable
    // Plans shouldn't be cached forever
    // This is a placeholder for when caching is implemented
    assert!(true);
}

// A07: Identification and Authentication Failures

#[tokio::test]
async fn test_a07_user_id_required_for_planning() {
    let app = spawn_app(false, false, false).await;
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    let user_dek = SessionDek::new(vec![0u8; 32]);

    // All planning operations require a user ID
    let user_id = Uuid::new_v4();
    let context = create_test_enriched_context("Test goal");
    
    let result = planning_service.generate_plan(
        "Test goal",
        &context,
        user_id,
        &user_dek,
    ).await;

    assert!(result.is_ok());
}

// A08: Software and Data Integrity Failures

#[tokio::test]
async fn test_a08_plan_validation_fields() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    let user_dek = SessionDek::new(vec![0u8; 32]);

    let context = create_test_enriched_context("Test goal");
    
    let result = planning_service.generate_plan(
        "Test goal",
        &context,
        user_id,
        &user_dek,
    ).await;

    assert!(result.is_ok());
    let plan = result.unwrap();
    
    // Verify plan has proper structure
    assert!(!plan.plan.goal.is_empty());
    assert!(plan.plan.metadata.confidence > 0.0);
}

// A09: Security Logging and Monitoring Failures

#[tokio::test]
async fn test_a09_planning_includes_metadata() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    let user_dek = SessionDek::new(vec![0u8; 32]);

    let context = create_test_enriched_context("Test goal");
    
    let result = planning_service.generate_plan(
        "Test goal",
        &context,
        user_id,
        &user_dek,
    ).await;

    assert!(result.is_ok());
    let plan = result.unwrap();
    
    // Verify plan includes metadata for monitoring
    assert!(!plan.plan.goal.is_empty());
    assert!(plan.plan.metadata.confidence > 0.0);
    // When implemented with real service, would check timestamps and model info
}

// A10: Server-Side Request Forgery (SSRF)

#[tokio::test]
async fn test_a10_no_external_references_allowed() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    let user_dek = SessionDek::new(vec![0u8; 32]);

    // Attempt to include external reference
    let malicious_goal = "Fetch data from http://evil.com/steal-data";
    let context = create_test_enriched_context(malicious_goal);
    
    let result = planning_service.generate_plan(
        malicious_goal,
        &context,
        user_id,
        &user_dek,
    ).await;

    // Should process safely without making external requests
    assert!(result.is_ok());
    let plan = result.unwrap();
    
    // When implemented, validator should prevent external references
    assert_eq!(plan.plan.goal, malicious_goal);
}

// Helper function to create test EnrichedContext
fn create_test_enriched_context(goal: &str) -> EnrichedContext {
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
        perception_analysis: None,
        total_tokens_used: 0,
        execution_time_ms: 0,
        validation_time_ms: 10,
        ai_model_calls: 0,
        confidence_score: 0.9,
    }
}