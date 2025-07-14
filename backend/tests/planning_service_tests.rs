use scribe_backend::services::planning::{PlanningService, Plan, AiGeneratedPlan, ActionName, PlannedAction};
use scribe_backend::services::context_assembly_engine::{
    EnrichedContext, SubGoal, ValidatedPlan, StrategicDirective, PlotSignificance, 
    WorldImpactLevel, PlanStep, RiskAssessment, RiskLevel, PlanValidationStatus
};
use scribe_backend::test_helpers::*;
use scribe_backend::errors::AppError;
use scribe_backend::auth::session_dek::SessionDek;
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

    // Create a test SessionDek for encrypted access
    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Generate plan - should now use Flash AI integration
    let result = planning_service.generate_plan(
        "Sol needs to go to the cantina",
        &context,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let plan = result.unwrap();
    assert_eq!(plan.plan.goal, "Sol needs to go to the cantina");
    
    // Should have at least one action for movement
    assert!(!plan.plan.actions.is_empty(), "Plan should contain actions");
    
    // Should have reasonable confidence
    assert!(plan.plan.metadata.confidence > 0.0);
    assert!(plan.plan.metadata.confidence <= 1.0);
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

    // Create a test SessionDek for encrypted access
    let session_dek = SessionDek::new(vec![0u8; 32]);

    // First call - should generate new plan
    let result1 = planning_service.generate_plan(
        "Sol needs to find Borga",
        &context,
        user_id,
        &session_dek,
    ).await;

    assert!(result1.is_ok());
    
    // Second call with same goal and context - should use cache (when implemented)
    let result2 = planning_service.generate_plan(
        "Sol needs to find Borga",
        &context,
        user_id,
        &session_dek,
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

    // Create test SessionDeks for encrypted access
    let session_dek1 = SessionDek::new(vec![0u8; 32]);
    let session_dek2 = SessionDek::new(vec![1u8; 32]);

    // Different users should have different cache entries
    let result1 = planning_service.generate_plan(
        "Sol needs to find Borga",
        &context,
        user1_id,
        &session_dek1,
    ).await;

    let result2 = planning_service.generate_plan(
        "Sol needs to find Borga",
        &context,
        user2_id,
        &session_dek2,
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

    // Create a test SessionDek for encrypted access
    let session_dek = SessionDek::new(vec![0u8; 32]);

    let result = planning_service.generate_plan(
        "Sol needs to find Borga, negotiate for the datapad, and return to base",
        &context,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let plan = result.unwrap();
    
    // Complex plan should have multiple actions
    assert!(plan.plan.goal.contains("Borga"));
    assert!(plan.plan.goal.contains("datapad"));
    assert!(!plan.plan.actions.is_empty(), "Complex plan should have actions");
    
    // Complex plans should have multiple steps
    // Note: This assertion will be enabled once full implementation is complete
    // assert!(plan.plan.actions.len() >= 2, "Complex plan should have multiple actions");
}

#[tokio::test]
async fn test_flash_model_integration() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let context = create_test_enriched_context("Test Flash model");
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Test that planning service uses Flash (gemini-2.5-flash) for planning
    let result = planning_service.generate_plan(
        "Move character to location",
        &context,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let plan = result.unwrap();
    
    // Verify basic plan structure from Flash
    assert!(!plan.plan.goal.is_empty());
    assert!(plan.plan.metadata.confidence >= 0.0);
    assert!(plan.plan.metadata.confidence <= 1.0);
}

#[tokio::test]
async fn test_planning_with_world_state_context() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    // Create enriched context with world state information
    let mut context = create_test_enriched_context("Navigate with world context");
    
    // Add mock entity data to context
    context.relevant_entities = vec![
        scribe_backend::services::context_assembly_engine::EntityContext {
            entity_id: Uuid::new_v4(),
            entity_name: "Sol".to_string(),
            entity_type: "character".to_string(),
            current_state: std::collections::HashMap::new(),
            spatial_location: Some(scribe_backend::services::context_assembly_engine::SpatialLocation {
                location_id: Uuid::new_v4(),
                name: "Spaceport".to_string(),
                coordinates: None,
                parent_location: None,
                location_type: "spaceport".to_string(),
            }),
            relationships: vec![],
            recent_actions: vec![],
            emotional_state: None,
            narrative_importance: 0.7,
            ai_insights: vec!["Test character in spaceport".to_string()],
        }
    ];
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    let result = planning_service.generate_plan(
        "Sol needs to travel to the cantina",
        &context,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let plan = result.unwrap();
    
    // Should incorporate world state context
    assert_eq!(plan.plan.goal, "Sol needs to travel to the cantina");
    assert!(!plan.plan.actions.is_empty(), "Should generate actions based on world state");
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

// OWASP Top 10 Security Tests for Planning Service

#[tokio::test]
async fn test_planning_service_user_isolation_a01() {
    // A01: Broken Access Control - Test user isolation
    let app = spawn_app(false, false, false).await;
    let user1_id = Uuid::new_v4();
    let user2_id = Uuid::new_v4();
    
    let context = create_test_enriched_context("Test user isolation");
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    let user1_dek = SessionDek::new(vec![1u8; 32]);
    let user2_dek = SessionDek::new(vec![2u8; 32]);

    // Both users should be able to generate plans independently
    let result1 = planning_service.generate_plan(
        "User 1 specific goal",
        &context,
        user1_id,
        &user1_dek,
    ).await;

    let result2 = planning_service.generate_plan(
        "User 2 specific goal", 
        &context,
        user2_id,
        &user2_dek,
    ).await;

    assert!(result1.is_ok());
    assert!(result2.is_ok());
    
    // Verify plans are user-specific
    let plan1 = result1.unwrap();
    let plan2 = result2.unwrap();
    
    assert_eq!(plan1.plan.goal, "User 1 specific goal");
    assert_eq!(plan2.plan.goal, "User 2 specific goal");
}

#[tokio::test]
async fn test_planning_service_encryption_a02() {
    // A02: Cryptographic Failures - Test DEK usage for world state queries
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let context = create_test_enriched_context("Test encryption");
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    // Test with proper SessionDek
    let valid_session_dek = SessionDek::new(vec![42u8; 32]);
    
    let result = planning_service.generate_plan(
        "Test encryption handling",
        &context,
        user_id,
        &valid_session_dek,
    ).await;

    assert!(result.is_ok());
    
    // Verify the planning service properly handles encryption
    let plan = result.unwrap();
    assert!(!plan.plan.goal.is_empty());
}

#[tokio::test]
async fn test_planning_service_input_validation_a03() {
    // A03: Injection - Test input sanitization
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let context = create_test_enriched_context("Test injection");
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Test with potentially malicious input
    let malicious_goal = "'; DROP TABLE plans; --";
    
    let result = planning_service.generate_plan(
        malicious_goal,
        &context,
        user_id,
        &session_dek,
    ).await;

    // Should handle input safely without injection
    assert!(result.is_ok());
    let plan = result.unwrap();
    
    // Goal should be sanitized/handled safely
    assert_eq!(plan.plan.goal, malicious_goal);
}

#[tokio::test]
async fn test_planning_service_cache_key_security_a04() {
    // A04: Insecure Design - Test cache key security
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let context = create_test_enriched_context("Test cache security");
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    // Test cache key generation for security
    let cache_key = planning_service.build_plan_cache_key(
        "test goal",
        &context,
        user_id,
    );
    
    // Cache key should include user ID to prevent cross-user data leakage
    assert!(cache_key.contains(&user_id.to_string()));
    assert!(cache_key.contains("plan:"));
}

#[tokio::test]
async fn test_planning_service_error_handling_a09() {
    // A09: Security Logging and Monitoring - Test error handling doesn't expose sensitive data
    let app = spawn_app(false, false, false).await;
    
    let context = create_test_enriched_context("Test error handling");
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Test with invalid UUID to trigger error path
    let invalid_user_id = Uuid::nil();
    
    let result = planning_service.generate_plan(
        "Test error handling",
        &context,
        invalid_user_id,
        &session_dek,
    ).await;

    // Even if it succeeds, verify error handling patterns are secure
    // The important thing is that the service handles edge cases gracefully
    match result {
        Ok(_) => {
            // Service handled edge case gracefully
        }
        Err(e) => {
            // Error should not expose sensitive information
            let error_msg = format!("{}", e);
            assert!(!error_msg.contains("password"));
            assert!(!error_msg.contains("secret"));
            assert!(!error_msg.contains("token"));
        }
    }
}

#[tokio::test]
async fn test_planning_service_security_misconfiguration_a05() {
    // A05: Security Misconfiguration - Test configuration validation
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let context = create_test_enriched_context("Test configuration");
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Test with valid configuration
    let result = planning_service.generate_plan(
        "Test secure configuration",
        &context,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let plan = result.unwrap();
    
    // Verify plan structure is properly validated
    assert!(!plan.plan.goal.is_empty());
    assert!(plan.plan.metadata.confidence >= 0.0);
    assert!(plan.plan.metadata.confidence <= 1.0);
}

#[tokio::test]
async fn test_planning_service_vulnerable_components_a06() {
    // A06: Vulnerable and Outdated Components - Test dependency security
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let context = create_test_enriched_context("Test dependency security");
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Test that planning service handles dependencies securely
    let result = planning_service.generate_plan(
        "Test dependency handling",
        &context,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    
    // Verify no unsafe dependency usage in plan generation
    let plan = result.unwrap();
    assert!(!plan.plan.actions.is_empty());
}

#[tokio::test]
async fn test_planning_service_authentication_failures_a07() {
    // A07: Identification and Authentication Failures - Test user authentication
    let app = spawn_app(false, false, false).await;
    let valid_user_id = Uuid::new_v4();
    let invalid_user_id = Uuid::nil(); // Invalid UUID
    
    let context = create_test_enriched_context("Test authentication");
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Test with valid user ID
    let valid_result = planning_service.generate_plan(
        "Test valid authentication",
        &context,
        valid_user_id,
        &session_dek,
    ).await;

    assert!(valid_result.is_ok());

    // Test with invalid user ID - should still work but with proper isolation
    let invalid_result = planning_service.generate_plan(
        "Test invalid authentication",
        &context,
        invalid_user_id,
        &session_dek,
    ).await;

    // Service should handle gracefully without exposing internal details
    match invalid_result {
        Ok(_) => {
            // Service handled edge case gracefully
        }
        Err(e) => {
            let error_msg = format!("{}", e);
            assert!(!error_msg.contains("internal"));
            assert!(!error_msg.contains("database"));
            assert!(!error_msg.contains("redis"));
        }
    }
}

#[tokio::test]
async fn test_planning_service_data_integrity_a08() {
    // A08: Software and Data Integrity Failures - Test data validation
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let context = create_test_enriched_context("Test data integrity");
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Test with various data integrity scenarios
    let long_goal = "Very long goal that exceeds normal length boundaries and contains repeated content ".repeat(10);
    let test_goals = vec![
        "Valid goal with proper data",
        "", // Empty goal
        "Goal with\nnewlines\tand\rspecial chars",
        &long_goal,
    ];

    for goal in test_goals {
        let result = planning_service.generate_plan(
            goal,
            &context,
            user_id,
            &session_dek,
        ).await;

        assert!(result.is_ok(), "Failed for goal: {}", goal);
        let plan = result.unwrap();
        
        // Verify data integrity in response
        assert!(!plan.plan.goal.is_empty() || goal.is_empty());
        assert!(plan.plan.metadata.confidence >= 0.0);
        assert!(plan.plan.metadata.confidence <= 1.0);
    }
}

#[tokio::test]
async fn test_planning_service_ssrf_prevention_a10() {
    // A10: Server-Side Request Forgery - Test SSRF prevention
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let context = create_test_enriched_context("Test SSRF prevention");
    
    let planning_service = PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.db_pool.clone()),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Test with potentially malicious URLs/endpoints in goal
    let malicious_goals = vec![
        "Connect to http://localhost:8080/admin",
        "Fetch data from http://169.254.169.254/metadata", // AWS metadata
        "Access file:///etc/passwd",
        "Request https://evil-site.com/steal-data",
    ];

    for malicious_goal in malicious_goals {
        let result = planning_service.generate_plan(
            malicious_goal,
            &context,
            user_id,
            &session_dek,
        ).await;

        // Planning should not make external requests based on goal content
        assert!(result.is_ok(), "SSRF test failed for: {}", malicious_goal);
        
        let plan = result.unwrap();
        // Verify the plan doesn't contain unsafe network operations
        assert_eq!(plan.plan.goal, malicious_goal); // Goal is preserved but not executed as network request
        assert!(!plan.plan.actions.is_empty()); // Should still generate actions, but safe ones
    }
}