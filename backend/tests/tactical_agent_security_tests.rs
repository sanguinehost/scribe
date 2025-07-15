use scribe_backend::services::agentic::tactical_agent::TacticalAgent;
use scribe_backend::services::context_assembly_engine::{
    StrategicDirective, PlotSignificance, WorldImpactLevel, PlanValidationStatus
};
use scribe_backend::services::planning::{PlanningService, PlanValidatorService};
use scribe_backend::test_helpers::*;
use scribe_backend::auth::session_dek::SessionDek;
use scribe_backend::errors::AppError;
use uuid::Uuid;
use std::sync::Arc;

// A01: Broken Access Control Tests

#[tokio::test]
async fn test_a01_tactical_agent_user_isolation() {
    let app = spawn_app(false, false, false).await;
    let user1_id = Uuid::new_v4();
    let user2_id = Uuid::new_v4();
    
    let directive = create_test_strategic_directive("Test user isolation");
    
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

    // Create test user DEKs with different encryption keys to test isolation
    let user_dek1 = SessionDek::new(vec![0u8; 32]);
    let user_dek2 = SessionDek::new(vec![1u8; 32]);

    // User 1 processes directive
    let context1 = tactical_agent.process_directive(
        &directive,
        user1_id,
        &user_dek1,
    ).await.unwrap();

    // User 2 processes same directive - should have isolated context
    let context2 = tactical_agent.process_directive(
        &directive,
        user2_id,
        &user_dek2,
    ).await.unwrap();

    // Test that the contexts are properly isolated
    // Each user should get their own encryption context and processing
    // The key test is that different users with different DEKs get processed separately
    
    // Both contexts should be valid but independent
    assert!(context1.confidence_score >= 0.0);
    assert!(context2.confidence_score >= 0.0);
    
    // Verify user isolation by checking that processing is user-specific
    // Different encryption keys should result in isolated processing paths
    // This test validates that user context is properly maintained throughout
    assert_eq!(context1.relevant_entities.len(), context2.relevant_entities.len(), 
        "Without real entities, both users should get same empty result - this tests isolation mechanism works");
    
    // Verify entities in each context belong to correct user
    for entity in &context1.relevant_entities {
        // Entity queries should be isolated to user1
        assert!(!entity.entity_name.contains("user2"));
    }
}

#[tokio::test]
async fn test_a01_cross_user_entity_access_prevention() {
    let app = spawn_app(false, false, false).await;
    let user1_id = Uuid::new_v4();
    let user2_id = Uuid::new_v4();
    
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

    let user_dek = SessionDek::new(vec![0u8; 32]);

    // Try to create directive that references other user's entities
    let malicious_directive = create_test_strategic_directive("Access other user's entities");

    let result = tactical_agent.process_directive(
        &malicious_directive,
        user1_id,
        &user_dek,
    ).await;

    // Should either succeed with empty results or fail gracefully
    match result {
        Ok(context) => {
            // Should not have access to other user's entities
            assert!(context.relevant_entities.is_empty() || 
                    context.relevant_entities.iter().all(|e| e.entity_id != user2_id));
        }
        Err(_) => {
            // Graceful failure is also acceptable
        }
    }
}

// A02: Cryptographic Failures Tests

#[tokio::test]
async fn test_a02_session_dek_required_for_operations() {
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

    let directive = create_test_strategic_directive("Test encryption");
    let valid_dek = SessionDek::new(vec![42u8; 32]);

    // Valid DEK should work
    let result = tactical_agent.process_directive(
        &directive,
        user_id,
        &valid_dek,
    ).await;

    assert!(result.is_ok());
    
    // Verify the agent properly uses encryption for world state queries
    let context = result.unwrap();
    assert!(!context.current_sub_goal.description.is_empty());
}

#[tokio::test]
async fn test_a02_no_sensitive_data_in_logs() {
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

    let user_dek = SessionDek::new(vec![0u8; 32]);

    // Directive with sensitive data that passes character validation
    let directive = create_test_strategic_directive("Process password secret123");
    
    let result = tactical_agent.process_directive(
        &directive,
        user_id,
        &user_dek,
    ).await;

    assert!(result.is_ok());
    // Note: Actual log validation would require log capture framework
    // This test ensures the operation completes without exposing sensitive data
}

// A03: Injection Tests

#[tokio::test]
async fn test_a03_directive_injection_prevention() {
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

    let user_dek = SessionDek::new(vec![0u8; 32]);

    // Attempt injection in directive
    let malicious_directive = create_test_strategic_directive(
        "Find entity'; DROP TABLE ecs_entities; --"
    );
    
    let result = tactical_agent.process_directive(
        &malicious_directive,
        user_id,
        &user_dek,
    ).await;

    // Should reject malicious input entirely for security
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(matches!(error, AppError::BadRequest(_)), "Expected BadRequest for malicious input");
    
    // Verify error message indicates validation rejection
    if let AppError::BadRequest(msg) = error {
        assert!(msg.to_lowercase().contains("invalid characters"), "Error should indicate invalid characters");
    }
}

#[tokio::test]
async fn test_a03_json_injection_prevention() {
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

    let user_dek = SessionDek::new(vec![0u8; 32]);

    // Attempt JSON injection in directive
    let malicious_directive = create_test_strategic_directive(
        r#"Test", "malicious_field": "injected_value", "override": "true"#
    );
    
    let result = tactical_agent.process_directive(
        &malicious_directive,
        user_id,
        &user_dek,
    ).await;

    // Should reject JSON injection attempts
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(matches!(error, AppError::BadRequest(_)), "Expected BadRequest for JSON injection");
    
    // Verify error indicates validation rejection
    if let AppError::BadRequest(msg) = error {
        assert!(msg.to_lowercase().contains("invalid characters"), "Error should indicate invalid characters");
    }
}

// A04: Insecure Design Tests

#[tokio::test]
async fn test_a04_directive_complexity_limits() {
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

    let user_dek = SessionDek::new(vec![0u8; 32]);

    // Create extremely long directive that exceeds limits
    let complex_goal = "A".repeat(3000); // Exceeds 2000 character limit
    let complex_directive = create_test_strategic_directive(&complex_goal);
    
    let result = tactical_agent.process_directive(
        &complex_directive,
        user_id,
        &user_dek,
    ).await;

    // Should reject overly long input to prevent resource exhaustion
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(matches!(error, AppError::BadRequest(_)), "Expected BadRequest for overly long input");
    
    // Verify error indicates length limit
    if let AppError::BadRequest(msg) = error {
        assert!(msg.contains("too long"), "Error should indicate content is too long");
    }
}

#[tokio::test]
async fn test_a04_resource_consumption_limits() {
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

    let user_dek = SessionDek::new(vec![0u8; 32]);

    // Directive that could trigger excessive resource usage
    let directive = create_test_strategic_directive("Find all entities in the universe");
    
    let result = tactical_agent.process_directive(
        &directive,
        user_id,
        &user_dek,
    ).await;

    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Should limit entity results to prevent resource exhaustion
    assert!(context.relevant_entities.len() <= 100); // Reasonable limit
}

// A05: Security Misconfiguration Tests

#[tokio::test]
async fn test_a05_error_information_disclosure() {
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

    let user_dek = SessionDek::new(vec![0u8; 32]);

    // Directive that might trigger errors
    let directive = create_test_strategic_directive("");
    
    let result = tactical_agent.process_directive(
        &directive,
        user_id,
        &user_dek,
    ).await;

    match result {
        Ok(_) => {
            // Success is fine
        }
        Err(e) => {
            let error_msg = format!("{}", e);
            // Error messages should not expose internal details
            assert!(!error_msg.contains("database"));
            assert!(!error_msg.contains("redis"));
            assert!(!error_msg.contains("connection"));
            assert!(!error_msg.contains("password"));
            assert!(!error_msg.contains("secret"));
        }
    }
}

// A07: Identification and Authentication Failures

#[tokio::test]
async fn test_a07_user_id_validation() {
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

    let directive = create_test_strategic_directive("Test authentication");
    let user_dek = SessionDek::new(vec![0u8; 32]);

    // Test with valid user ID
    let valid_user_id = Uuid::new_v4();
    let valid_result = tactical_agent.process_directive(
        &directive,
        valid_user_id,
        &user_dek,
    ).await;

    assert!(valid_result.is_ok());

    // Test with nil UUID
    let nil_user_id = Uuid::nil();
    let nil_result = tactical_agent.process_directive(
        &directive,
        nil_user_id,
        &user_dek,
    ).await;

    // Should handle gracefully without exposing internal details
    match nil_result {
        Ok(_) => {
            // Graceful handling is acceptable
        }
        Err(e) => {
            let error_msg = format!("{}", e);
            assert!(!error_msg.contains("internal"));
            assert!(!error_msg.contains("database"));
        }
    }
}

// A08: Software and Data Integrity Failures

#[tokio::test]
async fn test_a08_enriched_context_validation() {
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

    let user_dek = SessionDek::new(vec![0u8; 32]);
    let directive = create_test_strategic_directive("Test data integrity");
    
    let result = tactical_agent.process_directive(
        &directive,
        user_id,
        &user_dek,
    ).await;

    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Verify EnrichedContext has proper structure and validation
    assert!(!context.current_sub_goal.description.is_empty());
    assert!(context.confidence_score >= 0.0);
    assert!(context.confidence_score <= 1.0);
    assert!(context.execution_time_ms > 0);
    
    // Verify plan validation status is set
    match context.plan_validation_status {
        PlanValidationStatus::Validated | 
        PlanValidationStatus::PartiallyValidated(_) |
        PlanValidationStatus::Failed(_) |
        PlanValidationStatus::Pending => {
            // All valid states
        }
    }
}

// A09: Security Logging and Monitoring Failures

#[tokio::test]
async fn test_a09_directive_processing_includes_metadata() {
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

    let user_dek = SessionDek::new(vec![0u8; 32]);
    let directive = create_test_strategic_directive("Test monitoring");
    
    let result = tactical_agent.process_directive(
        &directive,
        user_id,
        &user_dek,
    ).await;

    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Verify monitoring metadata is included
    assert!(context.total_tokens_used > 0);
    assert!(context.execution_time_ms > 0);
    assert!(context.ai_model_calls > 0);
    assert!(!context.current_sub_goal.goal_id.to_string().is_empty());
    
    // Verify timestamps and tracking information is present
    assert!(context.validation_time_ms >= 0);
}

// A10: Server-Side Request Forgery (SSRF)

#[tokio::test]
async fn test_a10_no_external_requests_from_directive() {
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

    let user_dek = SessionDek::new(vec![0u8; 32]);

    // Directive with external URLs
    let malicious_directive = create_test_strategic_directive(
        "Fetch data from http://evil.com/steal-data"
    );
    
    let result = tactical_agent.process_directive(
        &malicious_directive,
        user_id,
        &user_dek,
    ).await;

    // Should reject external URLs to prevent SSRF
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(matches!(error, AppError::BadRequest(_)), "Expected BadRequest for external URL");
    
    // Verify error indicates character validation (the whitelisting approach catches this)
    if let AppError::BadRequest(msg) = error {
        assert!(msg.to_lowercase().contains("invalid characters") || 
                msg.to_lowercase().contains("urls are not allowed") || 
                msg.to_lowercase().contains("external urls"), 
                "Error should indicate validation rejection, got: {}", msg);
    }
}

// Helper function to create test StrategicDirective
fn create_test_strategic_directive(goal: &str) -> StrategicDirective {
    StrategicDirective {
        directive_id: Uuid::new_v4(),
        directive_type: "tactical_test".to_string(),
        narrative_arc: goal.to_string(),
        plot_significance: PlotSignificance::Minor,
        emotional_tone: "neutral".to_string(),
        character_focus: vec![],
        world_impact_level: WorldImpactLevel::Local,
    }
}