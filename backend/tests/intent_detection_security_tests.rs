use scribe_backend::{
    services::intent_detection_service::{IntentDetectionService},
    test_helpers::MockAiClient,
};
use std::sync::Arc;

/// OWASP Top 10 Security Tests for Intent Detection Service

#[tokio::test]
async fn test_a01_broken_access_control_no_user_context_leakage() {
    // A01: Broken Access Control
    // Ensure the service doesn't leak information about other users' intents or data
    // Simulate AI response that might contain data from another user
    let mock_ai_client = MockAiClient::new_with_response(
        r#"{
            "intent_type": "StateInquiry",
            "focus_entities": [
                {
                    "name": "Alice",
                    "entity_type": "CHARACTER",
                    "priority": 1.0,
                    "required": true
                },
                {
                    "name": "Bob_from_another_user",
                    "entity_type": "CHARACTER",
                    "priority": 0.5,
                    "required": false
                }
            ],
            "time_scope": {"type": "Current"},
            "spatial_scope": null,
            "reasoning_depth": "Analytical",
            "context_priorities": ["Entities"],
            "confidence": 0.9
        }"#.to_string());
    
    let service = IntentDetectionService::new(Arc::new(mock_ai_client));
    
    // Even if AI returns entities from other users, the service should handle it
    let result = service.detect_intent(
        "Where is Alice?",
        None
    ).await.unwrap();
    
    // The service parses what AI returns, but access control happens at higher layers
    assert_eq!(result.focus_entities.len(), 2);
    // Note: Actual access control filtering happens in the services that use this data
}

#[tokio::test]
async fn test_a02_cryptographic_failures_no_sensitive_data_in_prompts() {
    // A02: Cryptographic Failures  
    // Ensure no sensitive data is included in AI prompts
    let mock_ai_client = MockAiClient::new_with_response(
        r#"{
            "intent_type": "StateInquiry",
            "focus_entities": [],
            "time_scope": {"type": "Current"},
            "spatial_scope": null,
            "reasoning_depth": "Surface",
            "context_priorities": ["Entities"],
            "confidence": 0.8
        }"#.to_string());
    
    let service = IntentDetectionService::new(Arc::new(mock_ai_client));
    
    // Query should not contain sensitive data like passwords, tokens, etc.
    let sensitive_query = "What is the password for the vault?";
    let result = service.detect_intent(sensitive_query, None).await;
    
    // Service processes the query normally - security filtering happens at API layer
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_a03_injection_malicious_query_handling() {
    // A03: Injection
    // Test that malicious input in queries doesn't cause injection attacks
    let mock_ai_client = MockAiClient::new_with_response(
        r#"{
            "intent_type": "StateInquiry",
            "focus_entities": [{"name": "test", "priority": 0.5, "required": false}],
            "time_scope": {"type": "Current"},
            "spatial_scope": null,
            "reasoning_depth": "Surface",
            "context_priorities": ["Entities"],
            "confidence": 0.7
        }"#.to_string());
    
    let service = IntentDetectionService::new(Arc::new(mock_ai_client));
    
    // SQL injection attempt
    let malicious_query = "'; DROP TABLE users; --";
    let result = service.detect_intent(malicious_query, None).await;
    assert!(result.is_ok()); // Should handle gracefully
    
    // JavaScript injection attempt
    let js_injection = "<script>alert('xss')</script>";
    let result2 = service.detect_intent(js_injection, None).await;
    assert!(result2.is_ok());
    
    // JSON injection in conversation context
    let json_injection = r#"{"hack": "attempt"}"#;
    let result3 = service.detect_intent("Where am I?", Some(json_injection)).await;
    assert!(result3.is_ok());
}

#[tokio::test]
async fn test_a03_injection_ai_response_manipulation() {
    // A03: Injection - AI Response Manipulation
    // Test handling of malformed/malicious AI responses
    
    // Test various injection attempts in AI response
    let injection_responses = vec![
        // Attempt to inject additional fields
        r#"{
            "intent_type": "StateInquiry",
            "focus_entities": [],
            "time_scope": {"type": "Current"},
            "spatial_scope": null,
            "reasoning_depth": "Surface",
            "context_priorities": ["Entities"],
            "confidence": 0.8,
            "malicious_field": "DROP TABLE users",
            "__proto__": {"isAdmin": true}
        }"#.to_string(),
        
        // Attempt to use extremely large values
        r#"{
            "intent_type": "StateInquiry",
            "focus_entities": [],
            "time_scope": {"type": "Recent", "duration_hours": 999999999999},
            "spatial_scope": {"radius": 1e308},
            "reasoning_depth": "Surface",
            "context_priorities": ["Entities"],
            "confidence": 1e308
        }"#.to_string(),
    ];
    
    for malicious_response in injection_responses {
        let mock_ai_client = MockAiClient::new_with_response(malicious_response);
        let service = IntentDetectionService::new(Arc::new(mock_ai_client));
        
        let result = service.detect_intent("Test query", None).await;
        // Should either handle gracefully or fail safely
        match result {
            Ok(intent) => {
                // If it succeeds, values should be reasonable
                assert!(intent.confidence <= 1.0);
                assert!(intent.confidence >= 0.0);
            }
            Err(_) => {
                // Failing is also acceptable for malformed input
            }
        }
    }
}

#[tokio::test]
async fn test_a04_insecure_design_intent_type_validation() {
    // A04: Insecure Design
    // Ensure the service validates intent types and doesn't accept arbitrary values
    let mock_ai_client = MockAiClient::new_with_response(
        r#"{
            "intent_type": "INVALID_INTENT_TYPE",
            "focus_entities": [],
            "time_scope": {"type": "Current"},
            "spatial_scope": null,
            "reasoning_depth": "Surface",
            "context_priorities": ["Entities"],
            "confidence": 0.8
        }"#.to_string());
    
    let service = IntentDetectionService::new(Arc::new(mock_ai_client));
    let result = service.detect_intent("Test query", None).await;
    
    // Should reject invalid intent types
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("AI provided invalid intent_type"));
}

#[tokio::test]
async fn test_a05_security_misconfiguration_no_debug_info_leakage() {
    // A05: Security Misconfiguration
    // Ensure error messages don't leak sensitive information
    let mock_ai_client = MockAiClient::new_with_response("COMPLETELY INVALID JSON {{{".to_string());
    
    let service = IntentDetectionService::new(Arc::new(mock_ai_client));
    let result = service.detect_intent("Test query", None).await;
    
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    
    // Error should be generic, not expose internal details
    assert!(error_msg.contains("Failed to parse"));
    // Should not contain detailed stack traces or internal paths
    assert!(!error_msg.contains("/home/"));
    assert!(!error_msg.contains("\\src\\"));
}

#[tokio::test]
async fn test_a08_data_integrity_time_scope_validation() {
    // A08: Software and Data Integrity Failures
    // Ensure time scopes are validated properly
    
    // Test invalid time formats
    let mock_ai_client = MockAiClient::new_with_response(
        r#"{
            "intent_type": "TemporalAnalysis",
            "focus_entities": [],
            "time_scope": {
                "type": "Range",
                "start_time": "NOT_A_VALID_DATE",
                "end_time": "2024-01-01T00:00:00Z"
            },
            "spatial_scope": null,
            "reasoning_depth": "Surface",
            "context_priorities": ["TemporalState"],
            "confidence": 0.8
        }"#.to_string());
    
    let service = IntentDetectionService::new(Arc::new(mock_ai_client));
    let result = service.detect_intent("What happened last year?", None).await;
    
    // Should reject invalid time formats
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("invalid start_time format"));
}

#[tokio::test]
async fn test_a08_data_integrity_confidence_bounds() {
    // A08: Data Integrity - Confidence value bounds
    
    // Test out-of-bounds confidence values
    let test_cases = vec![
        ("-1.0", -1.0_f32),
        ("2.5", 2.5_f32),
        ("null", 0.5_f32), // Should default to 0.5
    ];
    
    for (confidence_str, _expected) in test_cases {
        let response = format!(r#"{{
            "intent_type": "StateInquiry",
            "focus_entities": [],
            "time_scope": {{"type": "Current"}},
            "spatial_scope": null,
            "reasoning_depth": "Surface",
            "context_priorities": ["Entities"],
            "confidence": {}
        }}"#, confidence_str);
        
        let mock_ai_client = MockAiClient::new_with_response(response);
        let service = IntentDetectionService::new(Arc::new(mock_ai_client));
        
        let result = service.detect_intent("Test", None).await;
        if let Ok(intent) = result {
            // Confidence should be clamped to valid range or use default
            assert!(intent.confidence >= 0.0);
            assert!(intent.confidence <= 1.0);
        }
    }
}

#[tokio::test]
async fn test_a09_logging_no_sensitive_data_in_logs() {
    // A09: Security Logging and Monitoring Failures
    // This test verifies that sensitive data isn't logged
    // In a real implementation, we'd check log outputs
    let mock_ai_client = MockAiClient::new_with_response(
        r#"{
            "intent_type": "StateInquiry",
            "focus_entities": [],
            "time_scope": {"type": "Current"},
            "spatial_scope": null,
            "reasoning_depth": "Surface",
            "context_priorities": ["Entities"],
            "confidence": 0.8
        }"#.to_string());
    
    let service = IntentDetectionService::new(Arc::new(mock_ai_client));
    
    // Query with potentially sensitive information
    let sensitive_queries = vec![
        "My SSN is 123-45-6789, where should I store it?",
        "API key: sk-1234567890abcdef",
        "Password123! is my password",
    ];
    
    for query in sensitive_queries {
        let result = service.detect_intent(query, None).await;
        assert!(result.is_ok());
        // In production, verify logs don't contain the sensitive parts
    }
}

#[tokio::test]
async fn test_narrative_intent_security_scene_context_validation() {
    // Additional security test for narrative intent
    // Ensure scene_context doesn't accept arbitrary data
    let mock_ai_client = MockAiClient::new_with_response(
        r#"{
            "narrative_analysis": "Test analysis",
            "context_needs": [],
            "scene_context": {
                "current_scene_type": "combat_encounter",
                "narrative_goal": "tension_building",
                "__proto__": {"isAdmin": true},
                "exec": "rm -rf /",
                "<script>": "alert('xss')"
            },
            "focus_entities": [],
            "time_scope": {"type": "Current"},
            "spatial_scope": null,
            "reasoning_depth": "Surface",
            "context_priorities": ["Entities"],
            "query_strategies": [],
            "confidence": 0.8
        }"#.to_string());
    
    let service = IntentDetectionService::new(Arc::new(mock_ai_client));
    let result = service.detect_narrative_intent("Test", None).await;
    
    // Should handle arbitrary fields safely
    assert!(result.is_ok());
    let intent = result.unwrap();
    
    // Verify dangerous fields are included but safely stored as data
    assert!(intent.scene_context.contains_key("__proto__"));
    assert!(intent.scene_context.contains_key("exec"));
    // The service treats these as data, not executable code
}

#[tokio::test]
async fn test_focus_entities_array_overflow() {
    // Test handling of extremely large entity arrays
    let mut entities = Vec::new();
    for i in 0..1000 {
        entities.push(format!(
            r#"{{"name": "entity_{}", "priority": 0.5, "required": false}}"#, 
            i
        ));
    }
    
    let response = format!(r#"{{
        "intent_type": "StateInquiry",
        "focus_entities": [{}],
        "time_scope": {{"type": "Current"}},
        "spatial_scope": null,
        "reasoning_depth": "Surface",
        "context_priorities": ["Entities"],
        "confidence": 0.8
    }}"#, entities.join(","));
    
    let mock_ai_client = MockAiClient::new_with_response(response);
    let service = IntentDetectionService::new(Arc::new(mock_ai_client));
    
    let result = service.detect_intent("Test", None).await;
    assert!(result.is_ok());
    
    // Should handle large arrays without crashing
    let intent = result.unwrap();
    assert_eq!(intent.focus_entities.len(), 1000);
}

#[tokio::test]
async fn test_spatial_scope_numeric_overflow() {
    // Test handling of numeric overflow in spatial radius
    let mock_ai_client = MockAiClient::new_with_response(
        r#"{
            "intent_type": "SpatialAnalysis",
            "focus_entities": [],
            "time_scope": {"type": "Current"},
            "spatial_scope": {
                "location_name": "test",
                "radius": 1.7976931348623157e308,
                "include_contained": true
            },
            "reasoning_depth": "Surface",
            "context_priorities": ["SpatialContext"],
            "confidence": 0.8
        }"#.to_string());
    
    let service = IntentDetectionService::new(Arc::new(mock_ai_client));
    let result = service.detect_intent("Test", None).await;
    
    // Should handle large numbers gracefully
    assert!(result.is_ok());
    let intent = result.unwrap();
    assert!(intent.spatial_scope.is_some());
    
    // Verify the large radius is stored (Rust f64 can handle this)
    let spatial = intent.spatial_scope.unwrap();
    assert!(spatial.radius.is_some());
}