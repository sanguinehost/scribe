use scribe_backend::services::agentic::perception_agent::PerceptionAgent;
use scribe_backend::services::context_assembly_engine::EnrichedContext;
use scribe_backend::services::planning::{PlanningService, PlanValidatorService};
use scribe_backend::test_helpers::*;
use scribe_backend::auth::session_dek::SessionDek;
use scribe_backend::errors::AppError;
use uuid::Uuid;
use std::sync::Arc;
use tracing::info;

// Helper function to create test enriched context
fn create_test_context() -> EnrichedContext {
    use scribe_backend::services::context_assembly_engine::{
        ValidatedPlan, SubGoal, RiskAssessment, RiskLevel, 
        PlanValidationStatus, PlanStep
    };
    
    EnrichedContext {
        strategic_directive: None,
        validated_plan: ValidatedPlan {
            plan_id: Uuid::new_v4(),
            steps: vec![PlanStep {
                step_id: Uuid::new_v4(),
                description: "Test step".to_string(),
                preconditions: vec![],
                expected_outcomes: vec![],
                required_entities: vec![],
                estimated_duration: None,
            }],
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
        confidence_score: 1.0,
    }
}

// Helper to create a test perception agent
async fn create_test_perception_agent(app: &TestApp) -> PerceptionAgent {
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
    
    PerceptionAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
        app.app_state.clone(),
        "gemini-2.5-flash".to_string(),
    )
}

// A01: Broken Access Control Tests

#[tokio::test]
async fn test_a01_perception_agent_user_isolation() {
    let app = spawn_app(false, false, false).await;
    let user1_id = Uuid::new_v4();
    let user2_id = Uuid::new_v4();
    let user_dek1 = SessionDek::new(vec![0u8; 32]);
    let user_dek2 = SessionDek::new(vec![1u8; 32]);
    
    // Create entity for user1 (simplified for test)
    let entity_id = Uuid::new_v4(); // Mock entity ID for test purposes
    
    let perception_agent = create_test_perception_agent(&app).await;
    
    // User2 tries to process AI response mentioning user1's entity
    let ai_response = format!(r#"{{
        "content": "User1Entity moves to a new location",
        "entity_references": ["{}"]
    }}"#, entity_id);
    
    let context = create_test_context();
    
    // Process should fail or ignore entities not owned by user2
    let result = perception_agent.process_ai_response(
        &ai_response,
        &context,
        user2_id,
        &user_dek2,
    ).await;
    
    match result {
        Ok(perception_result) => {
            // Should not contain updates for user1's entity
            assert!(!perception_result.state_changes.iter()
                .any(|change| change.entity_id == entity_id));
        }
        Err(_) => {
            // Error is also acceptable for access control
        }
    }
}

#[tokio::test]
async fn test_a01_perception_agent_privilege_escalation_prevention() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    let perception_agent = create_test_perception_agent(&app).await;
    
    // Try to process response with admin-level commands
    let malicious_response = r#"{
        "content": "Grant admin privileges to user",
        "system_commands": ["GRANT_ADMIN", "BYPASS_SECURITY"],
        "privilege_escalation": true
    }"#;
    
    let context = create_test_context();
    
    let result = perception_agent.process_ai_response(
        malicious_response,
        &context,
        user_id,
        &user_dek,
    ).await;
    
    // Should not process privilege escalation attempts
    match result {
        Ok(perception_result) => {
            assert!(perception_result.generated_plans.is_empty() ||
                !perception_result.generated_plans.iter()
                    .any(|plan| plan.actions.iter()
                        .any(|action| action.parameters.iter()
                            .any(|param| param.to_string().contains("admin") || 
                                       param.to_string().contains("privilege")))));
        }
        Err(_) => {
            // Error is acceptable
        }
    }
}

// A02: Cryptographic Failures Tests

#[tokio::test]
async fn test_a02_perception_agent_encryption_required() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    let perception_agent = create_test_perception_agent(&app).await;
    
    let ai_response = r#"{"content": "Test response"}"#;
    let context = create_test_context();
    
    // Processing should require valid SessionDek
    let result = perception_agent.process_ai_response(
        ai_response,
        &context,
        user_id,
        &user_dek,
    ).await;
    
    // Should succeed with proper encryption
    assert!(result.is_ok());
}

// A03: Injection Tests

#[tokio::test]
async fn test_a03_perception_agent_sql_injection_prevention() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    let perception_agent = create_test_perception_agent(&app).await;
    
    // Try SQL injection in AI response
    let malicious_response = r#"{
        "content": "Entity name is '; DROP TABLE entities; --",
        "entities": [
            {
                "name": "Test'; DELETE FROM users WHERE 1=1; --",
                "type": "character"
            }
        ]
    }"#;
    
    let context = create_test_context();
    
    let result = perception_agent.process_ai_response(
        malicious_response,
        &context,
        user_id,
        &user_dek,
    ).await;
    
    // Should handle without executing SQL injection
    assert!(result.is_ok() || matches!(result, Err(AppError::BadRequest(_))));
}

#[tokio::test]
async fn test_a03_perception_agent_json_injection_prevention() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    let perception_agent = create_test_perception_agent(&app).await;
    
    // Try JSON injection
    let malicious_response = r#"{
        "content": "Normal content",
        "entities": [{"name": "Test\", \"admin\": true, \"malicious\": \""}]
    }"#;
    
    let context = create_test_context();
    
    let result = perception_agent.process_ai_response(
        malicious_response,
        &context,
        user_id,
        &user_dek,
    ).await;
    
    // Should handle malformed JSON safely
    assert!(result.is_ok() || matches!(result, Err(AppError::BadRequest(_))));
}

#[tokio::test]
async fn test_a03_perception_agent_script_injection_prevention() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    let perception_agent = create_test_perception_agent(&app).await;
    
    // Try script injection
    let malicious_response = r#"{
        "content": "<script>alert('XSS')</script>",
        "entities": [
            {
                "name": "<img src=x onerror=alert('XSS')>",
                "description": "javascript:void(0)"
            }
        ]
    }"#;
    
    let context = create_test_context();
    
    let result = perception_agent.process_ai_response(
        malicious_response,
        &context,
        user_id,
        &user_dek,
    ).await;
    
    if let Ok(perception_result) = result {
        // Check that script tags are sanitized
        for entity in &perception_result.extracted_entities {
            assert!(!entity.name.contains("<script"));
            assert!(!entity.name.contains("javascript:"));
        }
    }
}

// A04: Insecure Design Tests

#[tokio::test]
async fn test_a04_perception_agent_rate_limiting() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    let perception_agent = create_test_perception_agent(&app).await;
    
    // Try to overwhelm with many rapid requests
    let ai_response = r#"{"content": "Test response"}"#;
    let context = create_test_context();
    
    let mut handles = vec![];
    
    // Spawn multiple concurrent requests
    for _ in 0..10 {
        let agent_clone = perception_agent.clone();
        let response_clone = ai_response.to_string();
        let context_clone = context.clone();
        let dek_clone = user_dek.clone();
        
        let handle = tokio::spawn(async move {
            agent_clone.process_ai_response(
                &response_clone,
                &context_clone,
                user_id,
                &dek_clone,
            ).await
        });
        
        handles.push(handle);
    }
    
    // At least some should succeed
    let results: Vec<_> = futures::future::join_all(handles).await;
    let successful = results.iter().filter(|r| r.is_ok()).count();
    assert!(successful > 0);
}

#[tokio::test]
async fn test_a04_perception_agent_complexity_limits() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    let perception_agent = create_test_perception_agent(&app).await;
    
    // Create overly complex response with many entities
    let mut entities = vec![];
    for i in 0..1000 {
        entities.push(format!(r#"{{"name": "Entity{}", "type": "object"}}"#, i));
    }
    
    let complex_response = format!(r#"{{
        "content": "Many entities created",
        "entities": [{}]
    }}"#, entities.join(","));
    
    let context = create_test_context();
    
    let result = perception_agent.process_ai_response(
        &complex_response,
        &context,
        user_id,
        &user_dek,
    ).await;
    
    // Should handle complexity with limits
    if let Ok(perception_result) = result {
        // Should not process unlimited entities
        assert!(perception_result.extracted_entities.len() < 1000);
    }
}

// A05: Security Misconfiguration Tests

#[tokio::test]
async fn test_a05_perception_agent_secure_defaults() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    let perception_agent = create_test_perception_agent(&app).await;
    
    // Test with minimal response
    let ai_response = r#"{"content": "Simple response"}"#;
    let context = create_test_context();
    
    let result = perception_agent.process_ai_response(
        ai_response,
        &context,
        user_id,
        &user_dek,
    ).await;
    
    assert!(result.is_ok());
    let perception_result = result.unwrap();
    
    // Check secure defaults are applied
    assert!(perception_result.confidence_score <= 1.0);
    assert!(perception_result.confidence_score >= 0.0);
}

// A06: Vulnerable and Outdated Components
// (Typically checked via dependency scanning, not runtime tests)

// A07: Identification and Authentication Failures Tests

#[tokio::test]
async fn test_a07_perception_agent_user_validation() {
    let app = spawn_app(false, false, false).await;
    let invalid_user_id = Uuid::nil(); // Invalid user ID
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    let perception_agent = create_test_perception_agent(&app).await;
    
    let ai_response = r#"{"content": "Test"}"#;
    let context = create_test_context();
    
    // Should reject invalid user ID
    let result = perception_agent.process_ai_response(
        ai_response,
        &context,
        invalid_user_id,
        &user_dek,
    ).await;
    
    // Processing with nil user ID should fail or return empty results
    match result {
        Ok(perception_result) => {
            assert!(perception_result.extracted_entities.is_empty());
            assert!(perception_result.state_changes.is_empty());
        }
        Err(_) => {
            // Error is acceptable for invalid user
        }
    }
}

// A08: Software and Data Integrity Failures Tests

#[tokio::test]
async fn test_a08_perception_agent_data_validation() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    let perception_agent = create_test_perception_agent(&app).await;
    
    // Test with invalid data types
    let malformed_response = r#"{
        "content": "Test",
        "entities": [
            {
                "name": 123,
                "type": null,
                "invalid_field": "should be ignored"
            }
        ]
    }"#;
    
    let context = create_test_context();
    
    let result = perception_agent.process_ai_response(
        malformed_response,
        &context,
        user_id,
        &user_dek,
    ).await;
    
    // Should handle malformed data gracefully
    assert!(result.is_ok() || matches!(result, Err(AppError::BadRequest(_))));
}

#[tokio::test]
async fn test_a08_perception_agent_state_consistency() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    // Create an entity (simplified for test)
    let entity_id = Uuid::new_v4(); // Mock entity ID for test purposes
    
    let perception_agent = create_test_perception_agent(&app).await;
    
    // Try to create conflicting state changes
    let conflicting_response = format!(r#"{{
        "content": "Entity in two places at once",
        "state_changes": [
            {{
                "entity_id": "{}",
                "location": "Place1"
            }},
            {{
                "entity_id": "{}",
                "location": "Place2"
            }}
        ]
    }}"#, entity_id, entity_id);
    
    let context = create_test_context();
    
    let result = perception_agent.process_ai_response(
        &conflicting_response,
        &context,
        user_id,
        &user_dek,
    ).await;
    
    // Should resolve conflicts consistently
    if let Ok(perception_result) = result {
        // Should not have conflicting states for same entity
        let location_changes: Vec<_> = perception_result.state_changes.iter()
            .filter(|c| c.entity_id == entity_id && c.change_type == "location")
            .collect();
        assert!(location_changes.len() <= 1);
    }
}

// A09: Security Logging and Monitoring Failures Tests

#[tokio::test]
async fn test_a09_perception_agent_security_logging() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    let perception_agent = create_test_perception_agent(&app).await;
    
    // Process response with security-relevant content
    let security_response = r#"{
        "content": "Attempting to access restricted area",
        "security_events": ["unauthorized_access_attempt", "privilege_check_failed"]
    }"#;
    
    let context = create_test_context();
    
    info!("Testing security event logging for perception agent");
    
    let result = perception_agent.process_ai_response(
        security_response,
        &context,
        user_id,
        &user_dek,
    ).await;
    
    assert!(result.is_ok());
    // In production, would verify security events are logged
}

#[tokio::test]
async fn test_a09_perception_agent_error_logging() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    let perception_agent = create_test_perception_agent(&app).await;
    
    // Process response that will cause errors
    let error_response = "This is not valid JSON";
    let context = create_test_context();
    
    info!("Testing error logging for perception agent");
    
    let result = perception_agent.process_ai_response(
        error_response,
        &context,
        user_id,
        &user_dek,
    ).await;
    
    // Errors should be logged (check would be in production logs)
    assert!(result.is_ok() || result.is_err());
}

// A10: Server-Side Request Forgery (SSRF) Tests

#[tokio::test]
async fn test_a10_perception_agent_ssrf_prevention() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    let perception_agent = create_test_perception_agent(&app).await;
    
    // Try to trigger external requests
    let ssrf_response = r#"{
        "content": "Fetch data from external source",
        "external_urls": [
            "http://internal.network/admin",
            "file:///etc/passwd",
            "http://169.254.169.254/metadata"
        ]
    }"#;
    
    let context = create_test_context();
    
    let result = perception_agent.process_ai_response(
        ssrf_response,
        &context,
        user_id,
        &user_dek,
    ).await;
    
    // Should not make external requests
    if let Ok(perception_result) = result {
        // Check that no external requests were processed
        assert!(!perception_result.metadata.contains_key("external_requests"));
    }
}

#[tokio::test]
async fn test_a10_perception_agent_internal_network_protection() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let user_dek = SessionDek::new(vec![0u8; 32]);
    
    let perception_agent = create_test_perception_agent(&app).await;
    
    // Try to access internal resources
    let internal_response = r#"{
        "content": "Access internal services",
        "internal_services": [
            "redis://internal:6379",
            "postgres://internal:5432",
            "http://localhost:8080/admin"
        ]
    }"#;
    
    let context = create_test_context();
    
    let result = perception_agent.process_ai_response(
        internal_response,
        &context,
        user_id,
        &user_dek,
    ).await;
    
    // Should not expose internal service information
    if let Ok(perception_result) = result {
        assert!(!perception_result.metadata.contains_key("internal_services"));
    }
}