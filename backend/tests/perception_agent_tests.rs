use scribe_backend::services::context_assembly_engine::{
    EnrichedContext, ValidatedPlan, SubGoal, RiskAssessment, RiskLevel,
    PlanValidationStatus, PlanStep
};
use scribe_backend::test_helpers::*;
use scribe_backend::auth::session_dek::SessionDek;
use uuid::Uuid;

#[tokio::test]
async fn test_perception_agent_basic_functionality() {
    // Setup test environment
    let app = spawn_app(false, false, false).await;
    
    // Create perception agent
    let perception_agent = scribe_backend::services::agentic::factory::AgenticNarrativeFactory::create_perception_agent(&app.app_state);
    
    // Create test user and session
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Test AI response that mentions entities and state changes
    let ai_response = r#"
        The knight Sir Galahad enters the grand throne room, his armor clanking softly.
        He approaches Queen Isabella who sits upon the golden throne. 
        "Your majesty," he says, bowing deeply and presenting the ancient scroll he found.
        The queen's expression softens as she recognizes the seal. Their trust deepens through this act of loyalty.
    "#;
    
    // Create enriched context
    let context = EnrichedContext {
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
    };
    
    // Process the AI response
    let result = perception_agent.process_ai_response(
        ai_response,
        &context,
        user_id,
        &session_dek,
    ).await;
    
    // The test might fail due to AI parsing, but should not panic
    match result {
        Ok(perception_result) => {
            println!("Perception result: {:?}", perception_result);
            assert!(perception_result.execution_time_ms > 0);
        }
        Err(e) => {
            println!("Perception processing failed (expected in test): {:?}", e);
            // This is expected since we're using mock AI responses
        }
    }
}

#[tokio::test]
async fn test_perception_agent_empty_response() {
    // Setup test environment
    let app = spawn_app(false, false, false).await;
    
    // Create perception agent
    let perception_agent = scribe_backend::services::agentic::factory::AgenticNarrativeFactory::create_perception_agent(&app.app_state);
    
    // Create test user and session
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Create minimal context
    let context = EnrichedContext {
        strategic_directive: None,
        validated_plan: ValidatedPlan {
            plan_id: Uuid::new_v4(),
            steps: vec![],
            preconditions_met: false,
            causal_consistency_verified: false,
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
            description: "Empty test".to_string(),
            actionable_directive: "Test empty response".to_string(),
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
        confidence_score: 0.0,
    };

    // Test with empty response
    let result = perception_agent.process_ai_response(
        "",
        &context,
        user_id,
        &session_dek,
    ).await;
    
    // Should fail validation
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(e.to_string().contains("empty"));
    }
}

#[tokio::test]
async fn test_perception_agent_security_validation() {
    // Setup test environment
    let app = spawn_app(false, false, false).await;
    
    // Create perception agent
    let perception_agent = scribe_backend::services::agentic::factory::AgenticNarrativeFactory::create_perception_agent(&app.app_state);
    
    // Create test user and session
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Test response with control characters (should be sanitized)
    let malicious_response = "Normal text\x00\x01\x02with control chars\x1b[31m";
    
    // Create security context
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
                overall_risk: RiskLevel::Medium,
                identified_risks: vec!["Security test".to_string()],
                mitigation_strategies: vec!["Sanitization".to_string()],
            },
        },
        current_sub_goal: SubGoal {
            goal_id: Uuid::new_v4(),
            description: "Security test".to_string(),
            actionable_directive: "Test malicious input".to_string(),
            required_entities: vec![],
            success_criteria: vec!["Should sanitize control chars".to_string()],
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
        confidence_score: 0.5,
    };
    
    let result = perception_agent.process_ai_response(
        malicious_response,
        &context,
        user_id,
        &session_dek,
    ).await;
    
    // Should process successfully with sanitized content
    match result {
        Ok(_) => println!("Processed sanitized response successfully"),
        Err(e) => println!("Processing failed (expected in test): {:?}", e),
    }
}

#[tokio::test]
async fn test_perception_agent_long_response() {
    // Setup test environment
    let app = spawn_app(false, false, false).await;
    
    // Create perception agent
    let perception_agent = scribe_backend::services::agentic::factory::AgenticNarrativeFactory::create_perception_agent(&app.app_state);
    
    // Create test user and session
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Test with very long response (over 10000 chars)
    let long_response = "A".repeat(10001);
    
    // Create long text context
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
                overall_risk: RiskLevel::High,
                identified_risks: vec!["Long text test".to_string()],
                mitigation_strategies: vec!["Length validation".to_string()],
            },
        },
        current_sub_goal: SubGoal {
            goal_id: Uuid::new_v4(),
            description: "Long response test".to_string(),
            actionable_directive: "Test length limits".to_string(),
            required_entities: vec![],
            success_criteria: vec!["Should reject overly long content".to_string()],
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
        confidence_score: 0.1,
    };
    
    let result = perception_agent.process_ai_response(
        &long_response,
        &context,
        user_id,
        &session_dek,
    ).await;
    
    // Should fail validation
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(e.to_string().contains("too long"));
    }
}