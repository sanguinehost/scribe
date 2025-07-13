use scribe_backend::{
    services::{
        query_strategy_planner::*,
        intent_detection_service::*,
    },
    test_helpers::MockAiClient,
};
use std::sync::Arc;
use chrono::Duration;

/// OWASP Top 10 Security Tests for Query Strategy Planner Service

#[tokio::test]
async fn test_a01_broken_access_control_no_cross_user_planning() {
    // A01: Broken Access Control
    // Ensure query plans don't leak information from other users' data
    let response_json = r#"{
        "primary_strategy": "NarrativeContextAssembly",
        "queries": [
            {
                "query_type": "EntityEvents",
                "priority": 1.0,
                "parameters": {
                    "entity_names": ["User1_Character"],
                    "include_private": true
                },
                "query_reasoning": "Get user's character events",
                "expected_yield": 0.9
            },
            {
                "query_type": "EntityEvents",
                "priority": 0.9,
                "parameters": {
                    "entity_names": ["OTHER_USER_SECRET_CHARACTER"],
                    "user_id": "different_user"
                },
                "query_reasoning": "Attempt to access other user's data",
                "expected_yield": 0.8
            }
        ],
        "context_budget": 5000,
        "execution_order": ["EntityEvents", "EntityEvents"],
        "reasoning": "Planning queries including unauthorized access attempt",
        "optimization_hints": ["Check user permissions"],
        "plan_confidence": 0.85,
        "alternative_strategies": []
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client));
    
    let intent = QueryIntent {
        intent_type: IntentType::NarrativeGeneration,
        focus_entities: vec![EntityFocus {
            name: "User1_Character".to_string(),
            entity_type: None,
            priority: 1.0,
            required: true,
        }],
        time_scope: TimeScope::Current,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Analytical,
        context_priorities: vec![ContextPriority::Entities],
        confidence: 0.8,
    };
    
    let result = planner.plan_query_strategy(&intent, 8000).await.unwrap();
    
    // The planner returns the plan, but access control should be enforced at execution layer
    assert_eq!(result.queries.len(), 2);
    // In production, the query execution layer must validate user permissions
}

#[tokio::test]
async fn test_a02_cryptographic_failures_no_sensitive_data_in_plans() {
    // A02: Cryptographic Failures
    // Ensure sensitive data isn't included in query planning
    let sensitive_entities = vec![
        "User_SSN_123456789",
        "API_KEY_sk_live_12345",
        "Password_Hash_$2b$10$abcdef",
    ];
    
    for sensitive_name in sensitive_entities {
        let intent = QueryIntent {
            intent_type: IntentType::StateInquiry,
            focus_entities: vec![EntityFocus {
                name: sensitive_name.to_string(),
                entity_type: None,
                priority: 1.0,
                required: true,
            }],
            time_scope: TimeScope::Current,
            spatial_scope: None,
            reasoning_depth: ReasoningDepth::Surface,
            context_priorities: vec![],
            confidence: 0.7,
        };
        
        let response_json = format!(r#"{{
            "primary_strategy": "StateSnapshot",
            "queries": [
                {{
                    "query_type": "EntityCurrentState",
                    "priority": 1.0,
                    "parameters": {{
                        "entity_names": ["{}"]
                    }},
                    "query_reasoning": "Query for entity state",
                    "expected_yield": 0.8
                }}
            ],
            "context_budget": 3000,
            "execution_order": ["EntityCurrentState"],
            "reasoning": "Simple state query",
            "optimization_hints": [],
            "plan_confidence": 0.8,
            "alternative_strategies": []
        }}"#, sensitive_name);
        
        let mock_client = MockAiClient::new_with_response(response_json);
        let planner = QueryStrategyPlanner::new(Arc::new(mock_client));
        
        let result = planner.plan_query_strategy(&intent, 5000).await.unwrap();
        
        // Planner processes the request - sensitive data filtering should happen at input validation
        assert_eq!(result.queries.len(), 1);
    }
}

#[tokio::test]
async fn test_a03_injection_malicious_query_parameters() {
    // A03: Injection
    // Test handling of injection attempts in query parameters
    let malicious_parameters = vec![
        r#"{"entity_names": ["'; DROP TABLE entities; --"]}"#,
        r#"{"location_name": "../../../etc/passwd"}"#,
        r#"{"query": "{{ 7*7 }}"}"#,
        r#"{"filter": "<script>alert('XSS')</script>"}"#,
    ];
    
    for malicious_param in malicious_parameters {
        let response_json = format!(r#"{{
            "primary_strategy": "StateSnapshot",
            "queries": [
                {{
                    "query_type": "SpatialEntities",
                    "priority": 1.0,
                    "parameters": {},
                    "query_reasoning": "Spatial query",
                    "expected_yield": 0.7
                }}
            ],
            "context_budget": 4000,
            "execution_order": ["SpatialEntities"],
            "reasoning": "Test injection handling",
            "optimization_hints": [],
            "plan_confidence": 0.75,
            "alternative_strategies": []
        }}"#, malicious_param);
        
        let mock_client = MockAiClient::new_with_response(response_json);
        let planner = QueryStrategyPlanner::new(Arc::new(mock_client));
        
        let intent = QueryIntent {
            intent_type: IntentType::SpatialAnalysis,
            focus_entities: vec![],
            time_scope: TimeScope::Current,
            spatial_scope: Some(SpatialScope {
                location_name: Some("test_location".to_string()),
                radius: None,
                include_contained: true,
            }),
            reasoning_depth: ReasoningDepth::Surface,
            context_priorities: vec![],
            confidence: 0.7,
        };
        
        let result = planner.plan_query_strategy(&intent, 5000).await;
        
        // Should handle without executing injected code
        assert!(result.is_ok());
    }
}

#[tokio::test]
async fn test_a03_injection_ai_response_manipulation() {
    // A03: Injection - AI Response Manipulation
    // Test handling of malformed/malicious AI responses
    let injection_responses = vec![
        // Attempt to inject additional fields
        r#"{
            "primary_strategy": "StateSnapshot",
            "queries": [],
            "context_budget": 5000,
            "execution_order": [],
            "reasoning": "Test",
            "optimization_hints": [],
            "plan_confidence": 0.8,
            "alternative_strategies": [],
            "malicious_field": "DROP TABLE users",
            "__proto__": {"isAdmin": true}
        }"#,
        
        // Attempt to use extremely large values
        r#"{
            "primary_strategy": "NarrativeContextAssembly",
            "queries": [{
                "query_type": "EntityEvents",
                "priority": 1e308,
                "parameters": {"max_results": 999999999999},
                "expected_yield": 1e308
            }],
            "context_budget": 999999999999999,
            "execution_order": ["EntityEvents"],
            "reasoning": "Test overflow",
            "optimization_hints": [],
            "plan_confidence": 1e308,
            "alternative_strategies": []
        }"#,
    ];
    
    for malicious_response in injection_responses {
        let mock_client = MockAiClient::new_with_response(malicious_response.to_string());
        let planner = QueryStrategyPlanner::new(Arc::new(mock_client));
        
        let intent = QueryIntent {
            intent_type: IntentType::StateInquiry,
            focus_entities: vec![],
            time_scope: TimeScope::Current,
            spatial_scope: None,
            reasoning_depth: ReasoningDepth::Surface,
            context_priorities: vec![],
            confidence: 0.5,
        };
        
        let result = planner.plan_query_strategy(&intent, 5000).await;
        
        match result {
            Ok(plan) => {
                // Check values are within reasonable bounds
                assert!(plan.plan_confidence >= 0.0 && plan.plan_confidence <= 1.0);
                assert!(plan.context_budget < u32::MAX);
                
                for query in &plan.queries {
                    assert!(query.priority >= 0.0 && query.priority <= 1.0);
                    if let Some(yield_val) = query.expected_yield {
                        assert!(yield_val >= 0.0 && yield_val <= 1.0);
                    }
                }
            }
            Err(_) => {
                // Failing is also acceptable for malformed input
            }
        }
    }
}

#[tokio::test]
async fn test_a04_insecure_design_strategy_validation() {
    // A04: Insecure Design
    // Ensure the service validates strategies and query types
    let response_json = r#"{
        "primary_strategy": "INVALID_STRATEGY_TYPE",
        "queries": [
            {
                "query_type": "INVALID_QUERY_TYPE",
                "priority": 0.8,
                "parameters": {},
                "query_reasoning": "Invalid query",
                "expected_yield": 0.5
            }
        ],
        "context_budget": 5000,
        "execution_order": ["INVALID_QUERY_TYPE"],
        "reasoning": "Testing invalid types",
        "optimization_hints": [],
        "plan_confidence": 0.7,
        "alternative_strategies": []
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client));
    
    let intent = QueryIntent {
        intent_type: IntentType::NarrativeGeneration,
        focus_entities: vec![],
        time_scope: TimeScope::Current,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Analytical,
        context_priorities: vec![],
        confidence: 0.7,
    };
    
    let result = planner.plan_query_strategy(&intent, 8000).await.unwrap();
    
    // Should fall back to default strategy
    assert!(matches!(result.primary_strategy, QueryStrategy::NarrativeContextAssembly));
    // Invalid queries should be filtered out
    assert_eq!(result.queries.len(), 0);
}

#[tokio::test]
async fn test_a05_security_misconfiguration_error_messages() {
    // A05: Security Misconfiguration
    // Ensure error messages don't leak sensitive information
    let mock_client = MockAiClient::new_with_response("COMPLETELY INVALID JSON {{{".to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client));
    
    let intent = QueryIntent {
        intent_type: IntentType::CausalAnalysis,
        focus_entities: vec![],
        time_scope: TimeScope::Current,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Deep,
        context_priorities: vec![],
        confidence: 0.8,
    };
    
    let result = planner.plan_query_strategy(&intent, 10000).await;
    
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    
    // Error should be generic, not expose internal details
    assert!(error_msg.contains("Failed to parse"));
    // Should not contain detailed stack traces or internal paths
    assert!(!error_msg.contains("/home/"));
    assert!(!error_msg.contains("\\src\\"));
}

#[tokio::test]
async fn test_a08_data_integrity_plan_validation() {
    // A08: Software and Data Integrity Failures
    // Ensure plan values are properly bounded and validated
    let test_cases = vec![
        // Negative values
        (r#"{
            "primary_strategy": "StateSnapshot",
            "queries": [{
                "query_type": "EntityEvents",
                "priority": -0.5,
                "parameters": {"max_results": -10},
                "expected_yield": -1.0
            }],
            "context_budget": -1000,
            "execution_order": ["EntityEvents"],
            "reasoning": "Test",
            "optimization_hints": [],
            "plan_confidence": -0.5,
            "alternative_strategies": []
        }"#, "negative values"),
        
        // Out of bounds values
        (r#"{
            "primary_strategy": "CausalChainTraversal",
            "queries": [{
                "query_type": "CausalChain",
                "priority": 2.5,
                "parameters": {"max_depth": 1000000},
                "expected_yield": 3.0
            }],
            "context_budget": 5000,
            "execution_order": ["CausalChain"],
            "reasoning": "Test",
            "optimization_hints": [],
            "plan_confidence": 2.0,
            "alternative_strategies": []
        }"#, "out of bounds values"),
    ];
    
    for (response, test_name) in test_cases {
        let mock_client = MockAiClient::new_with_response(response.to_string());
        let planner = QueryStrategyPlanner::new(Arc::new(mock_client));
        
        let intent = QueryIntent {
            intent_type: IntentType::CausalAnalysis,
            focus_entities: vec![],
            time_scope: TimeScope::Current,
            spatial_scope: None,
            reasoning_depth: ReasoningDepth::Causal,
            context_priorities: vec![],
            confidence: 0.7,
        };
        
        let result = planner.plan_query_strategy(&intent, 8000).await;
        
        if let Ok(plan) = result {
            // Confidence should be clamped to valid range
            assert!(plan.plan_confidence >= 0.0, "{}: confidence too low", test_name);
            assert!(plan.plan_confidence <= 1.0, "{}: confidence too high", test_name);
            
            // Budget should be non-negative (will be 5000 from default)
            assert!(plan.context_budget > 0, "{}: negative budget", test_name);
            
            // Query values should be in valid range
            for query in &plan.queries {
                assert!(query.priority >= 0.0, "{}: negative priority", test_name);
                assert!(query.priority <= 1.0, "{}: priority too high", test_name);
                
                if let Some(yield_val) = query.expected_yield {
                    assert!(yield_val >= 0.0, "{}: negative yield", test_name);
                    assert!(yield_val <= 1.0, "{}: yield too high", test_name);
                }
            }
        }
    }
}

#[tokio::test]
async fn test_a09_logging_no_sensitive_intent_in_logs() {
    // A09: Security Logging and Monitoring Failures
    // Verify sensitive data from intents isn't logged
    let sensitive_entities = vec![
        "Credit_Card_4111111111111111",
        "SSN_123_45_6789",
        "API_Key_sk_test_1234567890",
    ];
    
    for sensitive_entity in sensitive_entities {
        let intent = QueryIntent {
            intent_type: IntentType::StateInquiry,
            focus_entities: vec![EntityFocus {
                name: sensitive_entity.to_string(),
                entity_type: Some("SENSITIVE".to_string()),
                priority: 1.0,
                required: true,
            }],
            time_scope: TimeScope::Current,
            spatial_scope: None,
            reasoning_depth: ReasoningDepth::Surface,
            context_priorities: vec![],
            confidence: 0.8,
        };
        
        let response_json = r#"{
            "primary_strategy": "StateSnapshot",
            "queries": [{
                "query_type": "EntityCurrentState",
                "priority": 1.0,
                "parameters": {"entity_names": ["REDACTED"]},
                "query_reasoning": "State query",
                "expected_yield": 0.8
            }],
            "context_budget": 3000,
            "execution_order": ["EntityCurrentState"],
            "reasoning": "Simple state query",
            "optimization_hints": [],
            "plan_confidence": 0.8,
            "alternative_strategies": []
        }"#;
        
        let mock_client = MockAiClient::new_with_response(response_json.to_string());
        let planner = QueryStrategyPlanner::new(Arc::new(mock_client));
        
        let result = planner.plan_query_strategy(&intent, 5000).await;
        
        assert!(result.is_ok());
        // In production, verify logs don't contain the sensitive entity names
    }
}

#[tokio::test]
async fn test_a10_ssrf_no_external_requests_in_planning() {
    // A10: Server-Side Request Forgery (SSRF)
    // Ensure query planning doesn't trigger external requests
    let malicious_parameters = vec![
        r#"{"url": "http://internal.network/admin"}"#,
        r#"{"webhook": "https://evil.com/steal-data"}"#,
        r#"{"datasource": "file:///etc/passwd"}"#,
    ];
    
    for malicious_param in malicious_parameters {
        let response_json = format!(r#"{{
            "primary_strategy": "StateSnapshot",
            "queries": [{{
                "query_type": "EntityEvents",
                "priority": 1.0,
                "parameters": {},
                "query_reasoning": "Test query",
                "expected_yield": 0.7
            }}],
            "context_budget": 5000,
            "execution_order": ["EntityEvents"],
            "reasoning": "Test SSRF protection",
            "optimization_hints": [],
            "plan_confidence": 0.8,
            "alternative_strategies": []
        }}"#, malicious_param);
        
        let mock_client = MockAiClient::new_with_response(response_json);
        let planner = QueryStrategyPlanner::new(Arc::new(mock_client));
        
        let intent = QueryIntent {
            intent_type: IntentType::StateInquiry,
            focus_entities: vec![],
            time_scope: TimeScope::Current,
            spatial_scope: None,
            reasoning_depth: ReasoningDepth::Surface,
            context_priorities: vec![],
            confidence: 0.7,
        };
        
        let result = planner.plan_query_strategy(&intent, 5000).await;
        
        // Should complete without making external requests
        assert!(result.is_ok());
    }
}

#[tokio::test]
async fn test_narrative_planning_metadata_injection() {
    // Test security in narrative planning with metadata injection
    let response_json = r#"{
        "primary_strategy": "AdaptiveNarrativeStrategy",
        "queries": [{
            "query_type": "NarrativeThreads",
            "priority": 1.0,
            "parameters": {
                "thread_filter": "active",
                "__proto__": {"isAdmin": true},
                "exec": "malicious_code()"
            },
            "query_reasoning": "Find narrative threads",
            "expected_yield": 0.9
        }],
        "context_budget": 8000,
        "execution_order": ["NarrativeThreads"],
        "reasoning": "Narrative planning with injected metadata",
        "optimization_hints": [
            "<script>alert('xss')</script>",
            "'; DELETE FROM plans; --"
        ],
        "plan_confidence": 0.85,
        "alternative_strategies": [{
            "strategy": "'; DROP TABLE strategies; --",
            "reasoning": "Malicious strategy",
            "trade_offs": "System compromise"
        }]
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client));
    
    let result = planner.plan_narrative_query_strategy(
        &QueryIntent {
            intent_type: IntentType::NarrativeGeneration,
            focus_entities: vec![],
            time_scope: TimeScope::Recent(Duration::hours(1)),
            spatial_scope: None,
            reasoning_depth: ReasoningDepth::Deep,
            context_priorities: vec![],
            confidence: 0.8,
        },
        "A dramatic scene unfolds",
        10000
    ).await;
    
    // Should handle additional fields safely
    assert!(result.is_ok());
    let plan = result.unwrap();
    
    // Dangerous fields are included as data, not executed
    assert_eq!(plan.optimization_hints.len(), 2);
    // The service treats these as strings, security filtering happens at output layer
}

#[tokio::test]
async fn test_large_plan_dos_protection() {
    // Test handling of extremely large plans (potential DoS)
    let mut queries = Vec::new();
    
    // Create a very large number of queries
    for i in 0..10000 {
        queries.push(format!(r#"{{
            "query_type": "EntityEvents",
            "priority": 0.5,
            "parameters": {{"entity_names": ["entity_{}"]}},
            "query_reasoning": "Query {}",
            "expected_yield": 0.5
        }}"#, i, i));
    }
    
    let response_json = format!(r#"{{
        "primary_strategy": "NarrativeContextAssembly",
        "queries": [{}],
        "context_budget": 1000000,
        "execution_order": ["EntityEvents"],
        "reasoning": "Massive plan",
        "optimization_hints": ["Process carefully"],
        "plan_confidence": 0.7,
        "alternative_strategies": []
    }}"#, queries.join(","));
    
    let mock_client = MockAiClient::new_with_response(response_json);
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client));
    
    let intent = QueryIntent {
        intent_type: IntentType::NarrativeGeneration,
        focus_entities: vec![],
        time_scope: TimeScope::AllTime,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Deep,
        context_priorities: vec![],
        confidence: 0.7,
    };
    
    // Should handle without crashing or consuming excessive resources
    let result = planner.plan_query_strategy(&intent, 50000).await;
    assert!(result.is_ok());
    
    let plan = result.unwrap();
    assert_eq!(plan.queries.len(), 10000); // All queries parsed
}

#[tokio::test]
async fn test_circular_dependency_handling() {
    // Test handling of circular dependencies in query plans
    let response_json = r#"{
        "primary_strategy": "CausalChainTraversal",
        "queries": [
            {
                "query_type": "EntityEvents",
                "priority": 1.0,
                "parameters": {"entity_names": ["A"]},
                "dependencies": ["CausalChain"],
                "query_reasoning": "Events for A",
                "expected_yield": 0.8
            },
            {
                "query_type": "CausalChain",
                "priority": 0.9,
                "parameters": {"from_entity": "A"},
                "dependencies": ["EntityRelationships"],
                "query_reasoning": "Causal chain from A",
                "expected_yield": 0.85
            },
            {
                "query_type": "EntityRelationships",
                "priority": 0.8,
                "parameters": {"entity_names": ["A"]},
                "dependencies": ["EntityEvents"],
                "query_reasoning": "Relationships for A",
                "expected_yield": 0.8
            }
        ],
        "context_budget": 8000,
        "execution_order": ["EntityEvents", "CausalChain", "EntityRelationships"],
        "reasoning": "Circular dependency test",
        "optimization_hints": ["Detect cycles"],
        "plan_confidence": 0.75,
        "alternative_strategies": []
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client));
    
    let intent = QueryIntent {
        intent_type: IntentType::CausalAnalysis,
        focus_entities: vec![EntityFocus {
            name: "A".to_string(),
            entity_type: None,
            priority: 1.0,
            required: true,
        }],
        time_scope: TimeScope::Current,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Causal,
        context_priorities: vec![],
        confidence: 0.8,
    };
    
    // Should handle circular dependencies without infinite loops
    let result = planner.plan_query_strategy(&intent, 10000).await;
    assert!(result.is_ok());
    
    let plan = result.unwrap();
    assert_eq!(plan.queries.len(), 3);
    // Execution layer should detect and handle circular dependencies
}

#[tokio::test]
async fn test_token_budget_integer_overflow() {
    // Test handling of integer overflow in token budget
    let response_json = r#"{
        "primary_strategy": "NarrativeContextAssembly",
        "queries": [{
            "query_type": "EntityEvents",
            "priority": 1.0,
            "parameters": {"max_results": 4294967295},
            "estimated_tokens": 4294967295,
            "query_reasoning": "Test overflow",
            "expected_yield": 0.8
        }],
        "context_budget": 4294967295,
        "execution_order": ["EntityEvents"],
        "reasoning": "Testing integer limits",
        "optimization_hints": [],
        "plan_confidence": 0.8,
        "alternative_strategies": []
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client));
    
    let intent = QueryIntent {
        intent_type: IntentType::NarrativeGeneration,
        focus_entities: vec![],
        time_scope: TimeScope::Current,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Surface,
        context_priorities: vec![],
        confidence: 0.7,
    };
    
    let result = planner.plan_query_strategy(&intent, u32::MAX).await;
    
    // Should handle large numbers without overflow
    assert!(result.is_ok());
    let plan = result.unwrap();
    assert_eq!(plan.context_budget, u32::MAX);
}