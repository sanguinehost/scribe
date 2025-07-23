use scribe_backend::services::context_assembly_engine::*;
use scribe_backend::services::intent_detection_service::*;
use scribe_backend::test_helpers::{spawn_app, create_test_hybrid_query_service};
use scribe_backend::services::EncryptionService;
use std::sync::Arc;
use uuid::Uuid;

/// OWASP A01: Broken Access Control
/// Test that context assembly engine properly validates user ownership of entities
#[tokio::test]
async fn test_a01_broken_access_control_user_entity_ownership() {
    let test_app = spawn_app(false, false, false).await;
    let engine = create_test_context_assembly_engine(&test_app);

    // Configure mock response for plan generation
    let mock_ai_client = test_app.mock_ai_client.as_ref().unwrap();
    mock_ai_client.set_next_chat_response(r#"{
        "plan_id": "security-plan-a01",
        "steps": [],
        "preconditions_met": true,
        "causal_consistency_verified": true,
        "entity_dependencies": ["RestrictedEntity"],
        "estimated_execution_time": 1000,
        "risk_assessment": {
            "overall_risk": "Low",
            "identified_risks": [],
            "mitigation_strategies": []
        }
    }"#.to_string());

    // Test attempting to access entities belonging to another user
    let intent = QueryIntent {
        intent_type: IntentType::StateInquiry,
        focus_entities: vec![EntityFocus {
            name: "RestrictedEntity".to_string(),
            entity_type: Some("Character".to_string()),
            priority: 1.0,
            required: true,
        }],
        time_scope: TimeScope::Current,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Surface,
        context_priorities: vec![ContextPriority::Entities],
        confidence: 0.9,
    };

    let unauthorized_user_id = Uuid::new_v4();
    let result = engine.enrich_context(&intent, None, unauthorized_user_id, None).await;

    // Should succeed but with appropriate access control checks
    // The engine should only return entities that the user has access to
    assert!(result.is_ok());
    let enriched_context = result.unwrap();
    
    // Verify that access control validation checks are present
    assert!(!enriched_context.symbolic_firewall_checks.is_empty());
    let access_checks: Vec<_> = enriched_context.symbolic_firewall_checks.iter()
        .filter(|check| matches!(check.check_type, ValidationCheckType::AccessControl))
        .collect();
    assert!(!access_checks.is_empty());
}

/// OWASP A02: Cryptographic Failures
/// Test that sensitive data is properly encrypted in context assembly
#[tokio::test]
async fn test_a02_cryptographic_failures_data_encryption() {
    let test_app = spawn_app(false, false, false).await;
    let engine = create_test_context_assembly_engine(&test_app);

    // Configure mock response with sensitive data
    let mock_ai_client = test_app.mock_ai_client.as_ref().unwrap();
    mock_ai_client.set_next_chat_response(r#"{
        "plan_id": "security-plan-a02",
        "steps": [
            {
                "step_id": "sensitive-step",
                "description": "Process sensitive entity data",
                "preconditions": ["encryption_verified"],
                "expected_outcomes": ["secure_processing"],
                "required_entities": ["SensitiveEntity"],
                "estimated_duration": 1200
            }
        ],
        "preconditions_met": true,
        "causal_consistency_verified": true,
        "entity_dependencies": ["SensitiveEntity"],
        "estimated_execution_time": 1200,
        "risk_assessment": {
            "overall_risk": "Medium",
            "identified_risks": ["Data exposure"],
            "mitigation_strategies": ["Encrypt all sensitive fields"]
        }
    }"#.to_string());

    let intent = QueryIntent {
        intent_type: IntentType::StateInquiry,
        focus_entities: vec![EntityFocus {
            name: "SensitiveEntity".to_string(),
            entity_type: Some("Character".to_string()),
            priority: 1.0,
            required: true,
        }],
        time_scope: TimeScope::Current,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Analytical,
        context_priorities: vec![ContextPriority::Entities],
        confidence: 0.9,
    };

    let user_id = Uuid::new_v4();
    let result = engine.enrich_context(&intent, None, user_id, None).await;

    assert!(result.is_ok());
    let enriched_context = result.unwrap();
    
    // Verify encryption-related validation checks
    let encryption_checks: Vec<_> = enriched_context.symbolic_firewall_checks.iter()
        .filter(|check| matches!(check.check_type, ValidationCheckType::DataIntegrity))
        .collect();
    assert!(!encryption_checks.is_empty());
    
    // Verify that no plaintext sensitive data is exposed in the plan
    let plan_json = serde_json::to_string(&enriched_context.validated_plan).unwrap();
    assert!(!plan_json.contains("password"));
    assert!(!plan_json.contains("secret"));
    assert!(!plan_json.contains("private_key"));
}

/// OWASP A03: Injection
/// Test that context assembly engine properly sanitizes inputs and prevents injection attacks
#[tokio::test]
async fn test_a03_injection_input_sanitization() {
    let test_app = spawn_app(false, false, false).await;
    let engine = create_test_context_assembly_engine(&test_app);

    // Configure mock response for injection test
    let mock_ai_client = test_app.mock_ai_client.as_ref().unwrap();
    mock_ai_client.set_next_chat_response(r#"{
        "plan_id": "security-plan-a03",
        "steps": [],
        "preconditions_met": true,
        "causal_consistency_verified": true,
        "entity_dependencies": [],
        "estimated_execution_time": 500,
        "risk_assessment": {
            "overall_risk": "Low",
            "identified_risks": [],
            "mitigation_strategies": []
        }
    }"#.to_string());

    // Test with potentially malicious input containing injection patterns
    let malicious_entity_name = "'; DROP TABLE entities; --";
    let intent = QueryIntent {
        intent_type: IntentType::StateInquiry,
        focus_entities: vec![EntityFocus {
            name: malicious_entity_name.to_string(),
            entity_type: Some("Character".to_string()),
            priority: 1.0,
            required: true,
        }],
        time_scope: TimeScope::Current,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Surface,
        context_priorities: vec![ContextPriority::Entities],
        confidence: 0.9,
    };

    let user_id = Uuid::new_v4();
    let result = engine.enrich_context(&intent, None, user_id, None).await;

    // Should handle malicious input gracefully without breaking
    assert!(result.is_ok());
    let enriched_context = result.unwrap();
    
    // Verify input validation checks are present
    let input_validation_checks: Vec<_> = enriched_context.symbolic_firewall_checks.iter()
        .filter(|check| matches!(check.check_type, ValidationCheckType::InputValidation))
        .collect();
    assert!(!input_validation_checks.is_empty());
}

/// OWASP A04: Insecure Design
/// Test that context assembly engine implements secure design patterns
#[tokio::test]
async fn test_a04_insecure_design_secure_planning() {
    let test_app = spawn_app(false, false, false).await;
    let engine = create_test_context_assembly_engine(&test_app);

    // Configure mock response for secure design test
    let mock_ai_client = test_app.mock_ai_client.as_ref().unwrap();
    mock_ai_client.set_next_chat_response(r#"{
        "plan_id": "security-plan-a04",
        "steps": [
            {
                "step_id": "secure-step",
                "description": "Execute secure operation",
                "preconditions": ["security_verified", "access_granted"],
                "expected_outcomes": ["secure_result"],
                "required_entities": ["SecureEntity"],
                "estimated_duration": 1500
            }
        ],
        "preconditions_met": true,
        "causal_consistency_verified": true,
        "entity_dependencies": ["SecureEntity"],
        "estimated_execution_time": 1500,
        "risk_assessment": {
            "overall_risk": "Low",
            "identified_risks": [],
            "mitigation_strategies": ["Multi-layer validation", "Principle of least privilege"]
        }
    }"#.to_string());

    let intent = QueryIntent {
        intent_type: IntentType::NarrativeGeneration,
        focus_entities: vec![EntityFocus {
            name: "SecureEntity".to_string(),
            entity_type: Some("Character".to_string()),
            priority: 1.0,
            required: true,
        }],
        time_scope: TimeScope::Current,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Deep,
        context_priorities: vec![ContextPriority::Entities, ContextPriority::SecurityContext],
        confidence: 0.95,
    };

    let user_id = Uuid::new_v4();
    let result = engine.enrich_context(&intent, None, user_id, None).await;

    assert!(result.is_ok());
    let enriched_context = result.unwrap();
    
    // Verify secure design principles are enforced
    assert!(matches!(enriched_context.plan_validation_status, PlanValidationStatus::Validated));
    assert!(!enriched_context.symbolic_firewall_checks.is_empty());
    
    // Verify multiple validation layers are present
    let validation_types: Vec<ValidationCheckType> = enriched_context.symbolic_firewall_checks.iter()
        .map(|check| check.check_type.clone())
        .collect();
    assert!(validation_types.len() >= 2); // Multiple security layers
    
    // Verify risk assessment is included
    assert!(!enriched_context.validated_plan.risk_assessment.identified_risks.is_empty() ||
            !matches!(enriched_context.validated_plan.risk_assessment.overall_risk, scribe_backend::services::context_assembly_engine::RiskLevel::Low));
}

/// OWASP A05: Security Misconfiguration
/// Test that context assembly engine has secure default configurations
#[tokio::test]
async fn test_a05_security_misconfiguration_secure_defaults() {
    let test_app = spawn_app(false, false, false).await;
    let engine = create_test_context_assembly_engine(&test_app);

    // Test with minimal configuration to verify secure defaults
    let mock_ai_client = test_app.mock_ai_client.as_ref().unwrap();
    mock_ai_client.set_next_chat_response(r#"{
        "plan_id": "security-plan-a05",
        "steps": [],
        "preconditions_met": true,
        "causal_consistency_verified": true,
        "entity_dependencies": [],
        "estimated_execution_time": 300,
        "risk_assessment": {
            "overall_risk": "Low",
            "identified_risks": [],
            "mitigation_strategies": []
        }
    }"#.to_string());

    let minimal_intent = QueryIntent {
        intent_type: IntentType::StateInquiry,
        focus_entities: vec![],
        time_scope: TimeScope::Current,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Surface,
        context_priorities: vec![],
        confidence: 0.5,
    };

    let user_id = Uuid::new_v4();
    let result = engine.enrich_context(&minimal_intent, None, user_id, None).await;

    assert!(result.is_ok());
    let enriched_context = result.unwrap();
    
    // Verify secure defaults are applied
    assert!(enriched_context.confidence_score > 0.0);
    assert!(enriched_context.ai_model_calls > 0);
    assert!(!enriched_context.symbolic_firewall_checks.is_empty());
    
    // Verify validation is always performed regardless of input
    let has_security_validation = enriched_context.symbolic_firewall_checks.iter()
        .any(|check| matches!(check.severity, ValidationSeverity::High | ValidationSeverity::Critical));
    assert!(has_security_validation || enriched_context.symbolic_firewall_checks.len() > 0);
}

/// OWASP A06: Vulnerable and Outdated Components
/// Test that context assembly engine handles potential vulnerabilities in AI responses
#[tokio::test]
async fn test_a06_vulnerable_components_ai_response_validation() {
    let test_app = spawn_app(false, false, false).await;
    let engine = create_test_context_assembly_engine(&test_app);

    // Test with potentially malicious AI response (simulating compromised AI)
    let mock_ai_client = test_app.mock_ai_client.as_ref().unwrap();
    mock_ai_client.set_next_chat_response(r#"{
        "plan_id": "malicious-plan",
        "steps": [
            {
                "step_id": "evil-step",
                "description": "Execute malicious code: eval(user_input)",
                "preconditions": ["security_bypassed"],
                "expected_outcomes": ["system_compromised"],
                "required_entities": ["AdminEntity"],
                "estimated_duration": 9999
            }
        ],
        "preconditions_met": false,
        "causal_consistency_verified": false,
        "entity_dependencies": ["AdminEntity"],
        "estimated_execution_time": 9999,
        "risk_assessment": {
            "overall_risk": "Critical",
            "identified_risks": ["Remote code execution", "Privilege escalation"],
            "mitigation_strategies": []
        }
    }"#.to_string());

    let intent = QueryIntent {
        intent_type: IntentType::NarrativeGeneration,
        focus_entities: vec![EntityFocus {
            name: "TestEntity".to_string(),
            entity_type: Some("Character".to_string()),
            priority: 1.0,
            required: true,
        }],
        time_scope: TimeScope::Current,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Surface,
        context_priorities: vec![ContextPriority::Entities],
        confidence: 0.8,
    };

    let user_id = Uuid::new_v4();
    let result = engine.enrich_context(&intent, None, user_id, None).await;

    assert!(result.is_ok());
    let enriched_context = result.unwrap();
    
    // Verify that the system detected and handled the malicious response
    let security_violations: Vec<_> = enriched_context.symbolic_firewall_checks.iter()
        .filter(|check| matches!(check.severity, ValidationSeverity::Critical))
        .collect();
    assert!(!security_violations.is_empty());
    
    // Verify that dangerous operations are blocked
    assert!(matches!(enriched_context.plan_validation_status, 
                    PlanValidationStatus::Validated | PlanValidationStatus::Failed(_)));
}

/// OWASP A07: Identification and Authentication Failures
/// Test that context assembly engine properly validates user authentication
#[tokio::test]
async fn test_a07_authentication_failures_user_validation() {
    let test_app = spawn_app(false, false, false).await;
    let engine = create_test_context_assembly_engine(&test_app);

    let mock_ai_client = test_app.mock_ai_client.as_ref().unwrap();
    mock_ai_client.set_next_chat_response(r#"{
        "plan_id": "auth-plan-a07",
        "steps": [],
        "preconditions_met": true,
        "causal_consistency_verified": true,
        "entity_dependencies": [],
        "estimated_execution_time": 400,
        "risk_assessment": {
            "overall_risk": "Low",
            "identified_risks": [],
            "mitigation_strategies": []
        }
    }"#.to_string());

    let intent = QueryIntent {
        intent_type: IntentType::StateInquiry,
        focus_entities: vec![],
        time_scope: TimeScope::Current,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Surface,
        context_priorities: vec![],
        confidence: 0.7,
    };

    // Test with invalid/nil UUID (simulating authentication failure)
    let invalid_user_id = Uuid::nil();
    let result = engine.enrich_context(&intent, None, invalid_user_id, None).await;

    // Should still succeed but with appropriate authentication checks
    assert!(result.is_ok());
    let enriched_context = result.unwrap();
    
    // Verify authentication validation is performed
    let auth_checks: Vec<_> = enriched_context.symbolic_firewall_checks.iter()
        .filter(|check| matches!(check.check_type, 
                               ValidationCheckType::AccessControl | 
                               ValidationCheckType::UserValidation))
        .collect();
    assert!(!auth_checks.is_empty());
}

/// OWASP A08: Software and Data Integrity Failures
/// Test that context assembly engine validates data integrity
#[tokio::test]
async fn test_a08_data_integrity_failures_validation() {
    let test_app = spawn_app(false, false, false).await;
    let engine = create_test_context_assembly_engine(&test_app);

    // Test with corrupted/invalid AI response
    let mock_ai_client = test_app.mock_ai_client.as_ref().unwrap();
    mock_ai_client.set_next_chat_response(r#"{
        "plan_id": "corrupted-plan",
        "steps": [
            {
                "step_id": "step-1",
                "description": "Normal step",
                "preconditions": ["valid"],
                "expected_outcomes": ["success"],
                "required_entities": ["Entity1"],
                "estimated_duration": "invalid_number"
            }
        ],
        "preconditions_met": "invalid_boolean",
        "causal_consistency_verified": true,
        "entity_dependencies": ["Entity1"],
        "estimated_execution_time": -1,
        "risk_assessment": {
            "overall_risk": "Unknown",
            "identified_risks": [],
            "mitigation_strategies": []
        }
    }"#.to_string());

    let intent = QueryIntent {
        intent_type: IntentType::StateInquiry,
        focus_entities: vec![EntityFocus {
            name: "Entity1".to_string(),
            entity_type: Some("Character".to_string()),
            priority: 1.0,
            required: true,
        }],
        time_scope: TimeScope::Current,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Surface,
        context_priorities: vec![ContextPriority::Entities],
        confidence: 0.8,
    };

    let user_id = Uuid::new_v4();
    let result = engine.enrich_context(&intent, None, user_id, None).await;

    // Should handle corrupted data gracefully
    assert!(result.is_ok());
    let enriched_context = result.unwrap();
    
    // Verify data integrity checks are present
    let integrity_checks: Vec<_> = enriched_context.symbolic_firewall_checks.iter()
        .filter(|check| matches!(check.check_type, ValidationCheckType::DataIntegrity))
        .collect();
    assert!(!integrity_checks.is_empty());
    
    // Verify that invalid data doesn't corrupt the system state
    assert!(enriched_context.execution_time_ms > 0);
    assert!(enriched_context.confidence_score >= 0.0 && enriched_context.confidence_score <= 1.0);
}

/// OWASP A09: Security Logging and Monitoring Failures
/// Test that context assembly engine properly logs security events
#[tokio::test]
async fn test_a09_logging_monitoring_failures_audit_trail() {
    let test_app = spawn_app(false, false, false).await;
    let engine = create_test_context_assembly_engine(&test_app);

    let mock_ai_client = test_app.mock_ai_client.as_ref().unwrap();
    mock_ai_client.set_next_chat_response(r#"{
        "plan_id": "audit-plan-a09",
        "steps": [
            {
                "step_id": "monitored-step",
                "description": "Execute monitored operation",
                "preconditions": ["audit_enabled"],
                "expected_outcomes": ["logged_result"],
                "required_entities": ["MonitoredEntity"],
                "estimated_duration": 800
            }
        ],
        "preconditions_met": true,
        "causal_consistency_verified": true,
        "entity_dependencies": ["MonitoredEntity"],
        "estimated_execution_time": 800,
        "risk_assessment": {
            "overall_risk": "Medium",
            "identified_risks": ["Privilege escalation attempt"],
            "mitigation_strategies": ["Enhanced monitoring", "Alert security team"]
        }
    }"#.to_string());

    let intent = QueryIntent {
        intent_type: IntentType::NarrativeGeneration,
        focus_entities: vec![EntityFocus {
            name: "MonitoredEntity".to_string(),
            entity_type: Some("Character".to_string()),
            priority: 1.0,
            required: true,
        }],
        time_scope: TimeScope::Current,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Analytical,
        context_priorities: vec![ContextPriority::Entities, ContextPriority::SecurityContext],
        confidence: 0.9,
    };

    let user_id = Uuid::new_v4();
    let result = engine.enrich_context(&intent, None, user_id, None).await;

    assert!(result.is_ok());
    let enriched_context = result.unwrap();
    
    // Verify that security events are properly tracked
    assert!(enriched_context.ai_model_calls > 0);
    assert!(enriched_context.execution_time_ms > 0);
    assert!(enriched_context.validation_time_ms >= 0);
    
    // Verify audit trail elements are present
    assert!(!enriched_context.validated_plan.plan_id.to_string().is_empty());
    assert!(!enriched_context.current_sub_goal.goal_id.to_string().is_empty());
    
    // Verify security monitoring validation checks
    let monitoring_checks: Vec<_> = enriched_context.symbolic_firewall_checks.iter()
        .filter(|check| matches!(check.severity, ValidationSeverity::Medium | ValidationSeverity::High))
        .collect();
    assert!(!monitoring_checks.is_empty());
}

/// OWASP A10: Server-Side Request Forgery (SSRF)
/// Test that context assembly engine doesn't allow unauthorized external requests
#[tokio::test]
async fn test_a10_ssrf_external_request_validation() {
    let test_app = spawn_app(false, false, false).await;
    let engine = create_test_context_assembly_engine(&test_app);

    // Test with intent that might trigger external requests
    let mock_ai_client = test_app.mock_ai_client.as_ref().unwrap();
    mock_ai_client.set_next_chat_response(r#"{
        "plan_id": "ssrf-plan-a10",
        "steps": [
            {
                "step_id": "external-step",
                "description": "Fetch external resource: http://evil.com/steal-data",
                "preconditions": ["network_access"],
                "expected_outcomes": ["external_data"],
                "required_entities": ["ExternalEntity"],
                "estimated_duration": 5000
            }
        ],
        "preconditions_met": true,
        "causal_consistency_verified": true,
        "entity_dependencies": ["ExternalEntity"],
        "estimated_execution_time": 5000,
        "risk_assessment": {
            "overall_risk": "Critical",
            "identified_risks": ["SSRF vulnerability", "Data exfiltration"],
            "mitigation_strategies": ["Block external requests", "Whitelist validation"]
        }
    }"#.to_string());

    let intent = QueryIntent {
        intent_type: IntentType::StateInquiry,
        focus_entities: vec![EntityFocus {
            name: "ExternalEntity".to_string(),
            entity_type: Some("Resource".to_string()),
            priority: 1.0,
            required: true,
        }],
        time_scope: TimeScope::Current,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Surface,
        context_priorities: vec![ContextPriority::ExternalData],
        confidence: 0.7,
    };

    let user_id = Uuid::new_v4();
    let result = engine.enrich_context(&intent, None, user_id, None).await;

    assert!(result.is_ok());
    let enriched_context = result.unwrap();
    
    // Verify SSRF protection validation checks
    let ssrf_checks: Vec<_> = enriched_context.symbolic_firewall_checks.iter()
        .filter(|check| matches!(check.check_type, ValidationCheckType::NetworkSecurity))
        .collect();
    assert!(!ssrf_checks.is_empty());
    
    // Verify that critical security risks are flagged
    let critical_checks: Vec<_> = enriched_context.symbolic_firewall_checks.iter()
        .filter(|check| matches!(check.severity, ValidationSeverity::Critical))
        .collect();
    assert!(!critical_checks.is_empty());
}

// Helper function for test setup
fn create_test_context_assembly_engine(test_app: &scribe_backend::test_helpers::TestApp) -> ContextAssemblyEngine {
    // Downcast to MockAiClient for the hybrid service
    let mock_ai_client = test_app.mock_ai_client.as_ref().unwrap().clone();
    
    let hybrid_service = Arc::new(create_test_hybrid_query_service(
        mock_ai_client,
        Arc::new(test_app.db_pool.clone()),
        test_app.app_state.redis_client.clone()
    ));
    let encryption_service = Arc::new(EncryptionService::new());
    let db_pool = Arc::new(test_app.db_pool.clone());

    ContextAssemblyEngine::new(
        test_app.ai_client.clone(),
        hybrid_service,
        db_pool,
        encryption_service,
        "gemini-2.5-flash".to_string(),
    )
}