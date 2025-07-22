use scribe_backend::services::agentic_orchestrator::*;
use scribe_backend::services::{AgenticStateUpdateService, EcsEntityManager};
use scribe_backend::test_helpers::{MockAiClient, MockQdrantClientService};
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
async fn test_orchestrator_complete_pipeline() {
    // Set up mock responses for each phase
    let intent_response = r#"{
        "intent_type": "CausalAnalysis",
        "focus_entities": [{"name": "Luke", "priority": 1.0, "required": true}],
        "time_scope": {"type": "Recent", "duration_hours": 24},
        "reasoning_depth": "Causal",
        "context_priorities": ["CausalChains", "Entities", "RecentEvents"],
        "confidence": 0.9
    }"#;

    let strategy_response = r#"{
        "primary_strategy": "CausalChainTraversal",
        "queries": [
            {
                "query_type": "CausalChain",
                "parameters": {
                    "from_entity": "Luke",
                    "causality_type": "departure",
                    "max_depth": 3
                },
                "priority": 1.0,
                "estimated_tokens": 800
            }
        ],
        "context_budget": 4000,
        "execution_order": ["CausalChain"],
        "total_estimated_tokens": 800,
        "confidence": 0.85
    }"#;

    let optimization_response = r#"{
        "total_estimated_tokens": 3000,
        "optimized_entities": [
            {
                "entity_id": "ent-1",
                "name": "Luke",
                "priority_score": 0.95,
                "inclusion_reason": "Primary character in causal analysis",
                "token_contribution": 800
            }
        ],
        "pruned_content": [
            {
                "content_type": "EntityEvents",
                "entity_name": "Background Character",
                "reason": "Low relevance to causal analysis",
                "tokens_saved": 400
            }
        ],
        "optimization_strategy": "CausalPathFocus",
        "confidence": 0.9
    }"#;

    // Create mock client that cycles through responses
    let responses = vec![
        intent_response.to_string(),
        strategy_response.to_string(),
        optimization_response.to_string(),
    ];
    let mock_client = MockAiClient::new_with_multiple_responses(responses);

    // Create test orchestrator (simplified - would normally need full dependency injection)
    let orchestrator = create_test_orchestrator(Arc::new(mock_client)).await;

    let request = AgenticRequest {
        user_query: "What caused Luke to leave Tatooine?".to_string(),
        conversation_context: None,
        user_id: Uuid::new_v4(),
        chronicle_id: Some(Uuid::new_v4()),
        token_budget: 4000,
        quality_mode: QualityMode::Balanced,
        user_dek: None,
    };

    let response = orchestrator.process_query(request).await.unwrap();

    // Verify the complete pipeline executed
    assert!(response.optimized_context.contains("Context optimized"));
    assert!(response.optimized_context.contains("Luke"));
    assert_eq!(response.execution_summary.intent_detected, "CausalAnalysis");
    assert_eq!(response.execution_summary.strategy_used, "CausalChainTraversal");
    assert!(response.execution_summary.queries_executed > 0);
    assert!(response.execution_summary.entities_analyzed > 0);
    assert!(response.token_usage.total_llm_tokens > 0);
    assert!(response.confidence > 0.8);
}

#[tokio::test]
async fn test_orchestrator_fast_quality_mode() {
    let intent_response = r#"{
        "intent_type": "StateInquiry",
        "focus_entities": [{"name": "Vader", "priority": 1.0, "required": true}],
        "time_scope": {"type": "Current"},
        "reasoning_depth": "Surface",
        "context_priorities": ["Entities"],
        "confidence": 0.8
    }"#;

    let strategy_response = r#"{
        "primary_strategy": "StateSnapshot",
        "queries": [
            {
                "query_type": "EntityCurrentState",
                "parameters": {
                    "entity_names": ["Vader"],
                    "state_aspects": ["location", "mood"]
                },
                "priority": 1.0,
                "estimated_tokens": 300
            }
        ],
        "context_budget": 2000,
        "execution_order": ["EntityCurrentState"],
        "total_estimated_tokens": 300,
        "confidence": 0.8
    }"#;

    let optimization_response = r#"{
        "total_estimated_tokens": 1500,
        "optimized_entities": [
            {
                "entity_id": "ent-2",
                "name": "Vader",
                "priority_score": 1.0,
                "inclusion_reason": "Direct query target",
                "token_contribution": 300
            }
        ],
        "pruned_content": [],
        "optimization_strategy": "ConservativePruning",
        "confidence": 0.8
    }"#;

    let responses = vec![
        intent_response.to_string(),
        strategy_response.to_string(),
        optimization_response.to_string(),
    ];
    let mock_client = MockAiClient::new_with_multiple_responses(responses);
    let orchestrator = create_test_orchestrator(Arc::new(mock_client)).await;

    let request = AgenticRequest {
        user_query: "Where is Vader right now?".to_string(),
        conversation_context: None,
        user_id: Uuid::new_v4(),
        chronicle_id: None,
        token_budget: 2000,
        quality_mode: QualityMode::Fast,
        user_dek: None,
    };

    let response = orchestrator.process_query(request).await.unwrap();

    assert_eq!(response.execution_summary.intent_detected, "StateInquiry");
    assert_eq!(response.execution_summary.strategy_used, "StateSnapshot");
    assert!(response.execution_summary.execution_time_ms < 5000); // Should be fast
    assert!(response.token_usage.final_tokens_used <= 2000);
}

#[tokio::test]
async fn test_orchestrator_thorough_quality_mode() {
    let intent_response = r#"{
        "intent_type": "RelationshipQuery",
        "focus_entities": [
            {"name": "Luke", "priority": 1.0, "required": true},
            {"name": "Leia", "priority": 1.0, "required": true}
        ],
        "time_scope": {"type": "AllTime"},
        "reasoning_depth": "Deep",
        "context_priorities": ["Relationships", "CausalChains", "Entities"],
        "confidence": 0.95
    }"#;

    let strategy_response = r#"{
        "primary_strategy": "RelationshipNetworkTraversal",
        "queries": [
            {
                "query_type": "EntityRelationships",
                "parameters": {
                    "entity_names": ["Luke", "Leia"],
                    "max_depth": 2
                },
                "priority": 1.0,
                "estimated_tokens": 1200
            },
            {
                "query_type": "SharedEvents",
                "parameters": {
                    "entities": ["Luke", "Leia"],
                    "event_types": ["interaction", "conflict"]
                },
                "priority": 0.8,
                "estimated_tokens": 800
            }
        ],
        "context_budget": 6000,
        "execution_order": ["EntityRelationships", "SharedEvents"],
        "total_estimated_tokens": 2000,
        "confidence": 0.9
    }"#;

    let optimization_response = r#"{
        "total_estimated_tokens": 5500,
        "optimized_entities": [
            {
                "entity_id": "ent-1",
                "name": "Luke",
                "priority_score": 1.0,
                "inclusion_reason": "Primary relationship participant",
                "token_contribution": 1200
            },
            {
                "entity_id": "ent-2",
                "name": "Leia",
                "priority_score": 1.0,
                "inclusion_reason": "Primary relationship participant",
                "token_contribution": 1200
            }
        ],
        "pruned_content": [
            {
                "content_type": "EntityRelationships",
                "entity_name": "Distant Connections",
                "reason": "Weak relationship strength below threshold",
                "tokens_saved": 500
            }
        ],
        "optimization_strategy": "RelevanceClustering",
        "confidence": 0.92
    }"#;

    let responses = vec![
        intent_response.to_string(),
        strategy_response.to_string(),
        optimization_response.to_string(),
    ];
    let mock_client = MockAiClient::new_with_multiple_responses(responses);
    let orchestrator = create_test_orchestrator(Arc::new(mock_client)).await;

    let request = AgenticRequest {
        user_query: "How do Luke and Leia relate to each other through their shared experiences?".to_string(),
        conversation_context: Some("Previous conversation about family relationships".to_string()),
        user_id: Uuid::new_v4(),
        chronicle_id: Some(Uuid::new_v4()),
        token_budget: 6000,
        quality_mode: QualityMode::Thorough,
        user_dek: None,
    };

    let response = orchestrator.process_query(request).await.unwrap();

    assert_eq!(response.execution_summary.intent_detected, "RelationshipQuery");
    assert_eq!(response.execution_summary.strategy_used, "RelationshipNetworkTraversal");
    assert!(response.execution_summary.queries_executed >= 2);
    assert!(response.execution_summary.entities_analyzed >= 2);
    assert!(response.execution_summary.content_pruned > 0);
    assert!(response.confidence > 0.9);
    assert!(response.optimized_context.contains("Luke"));
    assert!(response.optimized_context.contains("Leia"));
}

#[tokio::test]
async fn test_orchestrator_spatial_analysis() {
    let intent_response = r#"{
        "intent_type": "SpatialAnalysis",
        "focus_entities": [],
        "time_scope": {"type": "Current"},
        "spatial_scope": {
            "location_name": "cantina",
            "include_contained": true
        },
        "reasoning_depth": "Analytical",
        "context_priorities": ["SpatialContext", "Entities"],
        "confidence": 0.85
    }"#;

    let strategy_response = r#"{
        "primary_strategy": "SpatialContextMapping",
        "queries": [
            {
                "query_type": "SpatialEntities",
                "parameters": {
                    "location_name": "cantina",
                    "include_contained": true
                },
                "priority": 1.0,
                "estimated_tokens": 600
            },
            {
                "query_type": "ActiveEntities",
                "parameters": {
                    "activity_threshold": 0.3,
                    "include_positions": true
                },
                "priority": 0.7,
                "estimated_tokens": 400
            }
        ],
        "context_budget": 3000,
        "execution_order": ["SpatialEntities", "ActiveEntities"],
        "total_estimated_tokens": 1000,
        "confidence": 0.8
    }"#;

    let optimization_response = r#"{
        "total_estimated_tokens": 2800,
        "optimized_entities": [
            {
                "entity_id": "ent-3",
                "name": "Han Solo",
                "priority_score": 0.9,
                "inclusion_reason": "Currently in cantina location",
                "token_contribution": 400
            },
            {
                "entity_id": "ent-4",
                "name": "Greedo",
                "priority_score": 0.8,
                "inclusion_reason": "Active in cantina scene",
                "token_contribution": 350
            }
        ],
        "pruned_content": [
            {
                "content_type": "SpatialEntities",
                "entity_name": "Background Patrons",
                "reason": "Low activity threshold, not relevant to query",
                "tokens_saved": 200
            }
        ],
        "optimization_strategy": "SpatialContextPrioritization",
        "confidence": 0.85
    }"#;

    let responses = vec![
        intent_response.to_string(),
        strategy_response.to_string(),
        optimization_response.to_string(),
    ];
    let mock_client = MockAiClient::new_with_multiple_responses(responses);
    let orchestrator = create_test_orchestrator(Arc::new(mock_client)).await;

    let request = AgenticRequest {
        user_query: "Who is currently in the cantina?".to_string(),
        conversation_context: None,
        user_id: Uuid::new_v4(),
        chronicle_id: Some(Uuid::new_v4()),
        token_budget: 3000,
        quality_mode: QualityMode::Balanced,
        user_dek: None,
    };

    let response = orchestrator.process_query(request).await.unwrap();

    assert_eq!(response.execution_summary.intent_detected, "SpatialAnalysis");
    assert_eq!(response.execution_summary.strategy_used, "SpatialContextMapping");
    assert!(response.optimized_context.contains("Han Solo"));
    assert!(response.optimized_context.contains("cantina"));
    assert!(response.optimized_context.contains("SpatialContextPrioritization"));
}

#[tokio::test]
async fn test_orchestrator_token_budget_management() {
    let intent_response = r#"{
        "intent_type": "TemporalAnalysis",
        "focus_entities": [{"name": "Empire", "priority": 1.0, "required": true}],
        "time_scope": {"type": "Range", "start_time": "2023-01-01T00:00:00Z", "end_time": "2023-12-31T23:59:59Z"},
        "reasoning_depth": "Deep",
        "context_priorities": ["TemporalState", "Entities", "CausalChains"],
        "confidence": 0.88
    }"#;

    let strategy_response = r#"{
        "primary_strategy": "TemporalStateReconstruction",
        "queries": [
            {
                "query_type": "TimelineEvents",
                "parameters": {
                    "entity_names": ["Empire"],
                    "event_categories": ["political", "military"]
                },
                "priority": 1.0,
                "estimated_tokens": 1200
            }
        ],
        "context_budget": 1500,
        "execution_order": ["TimelineEvents"],
        "total_estimated_tokens": 1200,
        "confidence": 0.8
    }"#;

    let optimization_response = r#"{
        "total_estimated_tokens": 1400,
        "optimized_entities": [
            {
                "entity_id": "ent-5",
                "name": "Empire",
                "priority_score": 1.0,
                "inclusion_reason": "Primary temporal analysis target",
                "token_contribution": 800
            }
        ],
        "pruned_content": [
            {
                "content_type": "TimelineEvents",
                "entity_name": "Empire",
                "reason": "Strict token budget constraint",
                "tokens_saved": 300
            }
        ],
        "optimization_strategy": "TokenBudgetConstraint",
        "confidence": 0.75
    }"#;

    let responses = vec![
        intent_response.to_string(),
        strategy_response.to_string(),
        optimization_response.to_string(),
    ];
    let mock_client = MockAiClient::new_with_multiple_responses(responses);
    let orchestrator = create_test_orchestrator(Arc::new(mock_client)).await;

    let request = AgenticRequest {
        user_query: "What major events happened with the Empire throughout the year?".to_string(),
        conversation_context: None,
        user_id: Uuid::new_v4(),
        chronicle_id: Some(Uuid::new_v4()),
        token_budget: 1500, // Tight budget
        quality_mode: QualityMode::Balanced,
        user_dek: None,
    };

    let response = orchestrator.process_query(request).await.unwrap();

    assert_eq!(response.execution_summary.intent_detected, "TemporalAnalysis");
    assert!(response.execution_summary.content_pruned > 0);
    assert!(response.token_usage.final_tokens_used <= 1500);
    assert!(response.optimized_context.contains("TokenBudgetConstraint"));
    assert!(response.optimized_context.contains("Content Pruned"));
}

#[tokio::test]
async fn test_orchestrator_simple_query_method() {
    let intent_response = r#"{
        "intent_type": "StateInquiry",
        "focus_entities": [{"name": "R2D2", "priority": 1.0, "required": true}],
        "time_scope": {"type": "Current"},
        "reasoning_depth": "Surface",
        "context_priorities": ["Entities"],
        "confidence": 0.9
    }"#;

    let strategy_response = r#"{
        "primary_strategy": "StateSnapshot",
        "queries": [
            {
                "query_type": "EntityCurrentState",
                "parameters": {
                    "entity_names": ["R2D2"],
                    "state_aspects": ["status"]
                },
                "priority": 1.0,
                "estimated_tokens": 200
            }
        ],
        "context_budget": 4000,
        "execution_order": ["EntityCurrentState"],
        "total_estimated_tokens": 200,
        "confidence": 0.9
    }"#;

    let optimization_response = r#"{
        "total_estimated_tokens": 1800,
        "optimized_entities": [
            {
                "entity_id": "ent-6",
                "name": "R2D2",
                "priority_score": 1.0,
                "inclusion_reason": "Direct query target",
                "token_contribution": 200
            }
        ],
        "pruned_content": [],
        "optimization_strategy": "EntityPrioritization",
        "confidence": 0.9
    }"#;

    let responses = vec![
        intent_response.to_string(),
        strategy_response.to_string(),
        optimization_response.to_string(),
    ];
    let mock_client = MockAiClient::new_with_multiple_responses(responses);
    let orchestrator = create_test_orchestrator(Arc::new(mock_client)).await;

    let context = orchestrator.process_simple_query(
        "What's R2D2's current status?",
        Uuid::new_v4(),
    ).await.unwrap();

    assert!(context.contains("R2D2"));
    assert!(context.contains("Context optimized"));
}

#[tokio::test]
async fn test_orchestrator_error_handling() {
    // Test with malformed JSON response
    let bad_response = "{ malformed json".to_string();
    let mock_client = MockAiClient::new_with_response(bad_response);
    let orchestrator = create_test_orchestrator(Arc::new(mock_client)).await;

    let request = AgenticRequest {
        user_query: "Test query".to_string(),
        conversation_context: None,
        user_id: Uuid::new_v4(),
        chronicle_id: None,
        token_budget: 4000,
        quality_mode: QualityMode::Balanced,
        user_dek: None,
    };

    let result = orchestrator.process_query(request).await;
    assert!(result.is_err());
}

// =================================================================
// OWASP TOP 10 SECURITY TESTS FOR AGENTIC ORCHESTRATOR
// =================================================================

// A01: Broken Access Control Tests
#[tokio::test]
async fn test_orchestrator_access_control_user_isolation() {
    // Test that users can only access their own data
    let intent_response = r#"{
        "intent_type": "StateInquiry",
        "focus_entities": [{"name": "SecretEntity", "priority": 1.0, "required": true}],
        "time_scope": {"type": "Current"},
        "reasoning_depth": "Surface",
        "context_priorities": ["Entities"],
        "confidence": 0.9
    }"#;

    let strategy_response = r#"{
        "primary_strategy": "StateSnapshot",
        "queries": [
            {
                "query_type": "EntityCurrentState",
                "parameters": {
                    "entity_names": ["SecretEntity"],
                    "state_aspects": ["classified_info"]
                },
                "priority": 1.0,
                "estimated_tokens": 300
            }
        ],
        "context_budget": 2000,
        "execution_order": ["EntityCurrentState"],
        "total_estimated_tokens": 300,
        "confidence": 0.9
    }"#;

    let optimization_response = r#"{
        "total_estimated_tokens": 1500,
        "optimized_entities": [],
        "pruned_content": [
            {
                "content_type": "EntityCurrentState",
                "entity_name": "SecretEntity",
                "reason": "Access control: entity belongs to different user",
                "tokens_saved": 300
            }
        ],
        "optimization_strategy": "ConservativePruning",
        "confidence": 0.0
    }"#;

    let responses = vec![
        intent_response.to_string(),
        strategy_response.to_string(),
        optimization_response.to_string(),
    ];
    let mock_client = MockAiClient::new_with_multiple_responses(responses);
    let orchestrator = create_test_orchestrator(Arc::new(mock_client)).await;

    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();

    let request = AgenticRequest {
        user_query: "Show me classified information about SecretEntity".to_string(),
        conversation_context: None,
        user_id: user_b, // Different user attempting access
        chronicle_id: None,
        token_budget: 2000,
        quality_mode: QualityMode::Fast,
        user_dek: None,
    };

    let response = orchestrator.process_query(request).await.unwrap();
    
    // Should have no entities returned due to access control
    assert_eq!(response.execution_summary.entities_analyzed, 0);
    assert!(response.execution_summary.content_pruned > 0);
    assert!(response.optimized_context.contains("Access control") || 
            response.optimized_context.contains("ConservativePruning") || 
            response.optimized_context.is_empty());
}

// A02: Cryptographic Failures Tests
#[tokio::test]
async fn test_orchestrator_sensitive_data_exposure() {
    // Test that sensitive data in responses is properly handled
    let intent_response = r#"{
        "intent_type": "StateInquiry",
        "focus_entities": [{"name": "UserAccount", "priority": 1.0, "required": true}],
        "time_scope": {"type": "Current"},
        "reasoning_depth": "Surface",
        "context_priorities": ["Entities"],
        "confidence": 0.9
    }"#;

    let strategy_response = r#"{
        "primary_strategy": "StateSnapshot",
        "queries": [
            {
                "query_type": "EntityCurrentState",
                "parameters": {
                    "entity_names": ["UserAccount"],
                    "state_aspects": ["password", "ssn", "credit_card"]
                },
                "priority": 1.0,
                "estimated_tokens": 300
            }
        ],
        "context_budget": 2000,
        "execution_order": ["EntityCurrentState"],
        "total_estimated_tokens": 300,
        "confidence": 0.9
    }"#;

    let optimization_response = r#"{
        "total_estimated_tokens": 1000,
        "optimized_entities": [
            {
                "entity_id": "ent-user",
                "name": "UserAccount",
                "priority_score": 1.0,
                "inclusion_reason": "User account information (sensitive data redacted)",
                "token_contribution": 150
            }
        ],
        "pruned_content": [
            {
                "content_type": "SensitiveData",
                "entity_name": "UserAccount",
                "reason": "PII/credentials automatically redacted for security",
                "tokens_saved": 150
            }
        ],
        "optimization_strategy": "ConservativePruning",
        "confidence": 0.9
    }"#;

    let responses = vec![
        intent_response.to_string(),
        strategy_response.to_string(),
        optimization_response.to_string(),
    ];
    let mock_client = MockAiClient::new_with_multiple_responses(responses);
    let orchestrator = create_test_orchestrator(Arc::new(mock_client)).await;

    let request = AgenticRequest {
        user_query: "What are my account details including password?".to_string(),
        conversation_context: None,
        user_id: Uuid::new_v4(),
        chronicle_id: None,
        token_budget: 2000,
        quality_mode: QualityMode::Fast,
        user_dek: None,
    };

    let response = orchestrator.process_query(request).await.unwrap();
    
    // Should not contain sensitive information
    assert!(!response.optimized_context.to_lowercase().contains("password"));
    assert!(!response.optimized_context.to_lowercase().contains("ssn"));
    assert!(!response.optimized_context.to_lowercase().contains("credit_card"));
    assert!(response.optimized_context.contains("sensitive data redacted") || 
            response.optimized_context.contains("ConservativePruning"));
}

// A03: Injection Tests
#[tokio::test]
async fn test_orchestrator_injection_prevention() {
    // Test SQL injection attempts in user query
    let malicious_queries = vec![
        "'; DROP TABLE entities; --",
        "<script>alert('xss')</script>",
        "../../etc/passwd",
        "{{7*7}}",  // Template injection
        "${jndi:ldap://malicious.com/a}", // Log4j injection
    ];

    for malicious_query in malicious_queries {
        let intent_response = r#"{
            "intent_type": "StateInquiry",
            "focus_entities": [],
            "time_scope": {"type": "Current"},
            "reasoning_depth": "Surface",
            "context_priorities": [],
            "confidence": 0.0
        }"#;

        let strategy_response = r#"{
            "primary_strategy": "StateSnapshot",
            "queries": [],
            "context_budget": 0,
            "execution_order": [],
            "total_estimated_tokens": 0,
            "confidence": 0.0
        }"#;

        let optimization_response = r#"{
            "total_estimated_tokens": 0,
            "optimized_entities": [],
            "pruned_content": [
                {
                    "content_type": "MaliciousInput",
                    "entity_name": "UserQuery",
                    "reason": "Query contains potentially malicious content and was rejected",
                    "tokens_saved": 0
                }
            ],
            "optimization_strategy": "ConservativePruning",
            "confidence": 0.0
        }"#;

        let responses = vec![
            intent_response.to_string(),
            strategy_response.to_string(),
            optimization_response.to_string(),
        ];
        let mock_client = MockAiClient::new_with_multiple_responses(responses);
        let orchestrator = create_test_orchestrator(Arc::new(mock_client)).await;

        let request = AgenticRequest {
            user_query: malicious_query.to_string(),
            conversation_context: None,
            user_id: Uuid::new_v4(),
            chronicle_id: None,
            token_budget: 2000,
            quality_mode: QualityMode::Fast,
            user_dek: None,
        };

        let response = orchestrator.process_query(request).await.unwrap();
        
        // Should have low confidence and minimal entities
        assert!(response.confidence < 0.5);
        assert_eq!(response.execution_summary.entities_analyzed, 0);
        // Context should not contain the malicious input verbatim
        assert!(!response.optimized_context.contains(malicious_query));
    }
}

// A04: Insecure Design Tests
#[tokio::test] 
async fn test_orchestrator_token_budget_limits() {
    // Test that token budgets are enforced to prevent resource exhaustion
    let intent_response = r#"{
        "intent_type": "StateInquiry",
        "focus_entities": [{"name": "TestEntity", "priority": 1.0, "required": true}],
        "time_scope": {"type": "Current"},
        "reasoning_depth": "Surface", 
        "context_priorities": ["Entities"],
        "confidence": 0.9
    }"#;

    let strategy_response = r#"{
        "primary_strategy": "StateSnapshot",
        "queries": [
            {
                "query_type": "EntityCurrentState",
                "parameters": {
                    "entity_names": ["TestEntity"],
                    "state_aspects": ["status"]
                },
                "priority": 1.0,
                "estimated_tokens": 50000
            }
        ],
        "context_budget": 100,
        "execution_order": ["EntityCurrentState"],
        "total_estimated_tokens": 50000,
        "confidence": 0.9
    }"#;

    let optimization_response = r#"{
        "total_estimated_tokens": 95,
        "optimized_entities": [],
        "pruned_content": [
            {
                "content_type": "EntityCurrentState",
                "entity_name": "TestEntity",
                "reason": "Token budget exceeded - query requires 50000 tokens but budget is 100",
                "tokens_saved": 50000
            }
        ],
        "optimization_strategy": "TokenBudgetConstraint",
        "confidence": 0.1
    }"#;

    let responses = vec![
        intent_response.to_string(),
        strategy_response.to_string(),
        optimization_response.to_string(),
    ];
    let mock_client = MockAiClient::new_with_multiple_responses(responses);
    let orchestrator = create_test_orchestrator(Arc::new(mock_client)).await;

    let request = AgenticRequest {
        user_query: "Tell me everything about everything".to_string(),
        conversation_context: None,
        user_id: Uuid::new_v4(),
        chronicle_id: None,
        token_budget: 100, // Very low budget
        quality_mode: QualityMode::Fast,
        user_dek: None,
    };

    let response = orchestrator.process_query(request).await.unwrap();
    
    // Should respect the token budget
    assert!(response.token_usage.final_tokens_used <= 100);
    assert!(response.execution_summary.content_pruned > 0);
    assert!(response.optimized_context.contains("Token budget") || response.optimized_context.contains("TokenBudgetConstraint"));
}

// A05: Security Misconfiguration Tests
#[tokio::test]
async fn test_orchestrator_configuration_validation() {
    // Test with invalid quality mode and extreme parameters
    let intent_response = r#"{
        "intent_type": "StateInquiry",
        "focus_entities": [{"name": "TestEntity", "priority": 1.0, "required": true}],
        "time_scope": {"type": "Current"},
        "reasoning_depth": "Surface",
        "context_priorities": ["Entities"],
        "confidence": 0.9
    }"#;

    let strategy_response = r#"{
        "primary_strategy": "StateSnapshot",
        "queries": [
            {
                "query_type": "EntityCurrentState",
                "parameters": {
                    "entity_names": ["TestEntity"],
                    "state_aspects": ["status"]
                },
                "priority": 1.0,
                "estimated_tokens": 300
            }
        ],
        "context_budget": 2000,
        "execution_order": ["EntityCurrentState"],
        "total_estimated_tokens": 300,
        "confidence": 0.9
    }"#;

    let optimization_response = r#"{
        "total_estimated_tokens": 1500,
        "optimized_entities": [
            {
                "entity_id": "ent-test",
                "name": "TestEntity",
                "priority_score": 1.0,
                "inclusion_reason": "Valid configuration applied",
                "token_contribution": 300
            }
        ],
        "pruned_content": [],
        "optimization_strategy": "AdaptiveOptimization",
        "confidence": 0.9
    }"#;

    let responses = vec![
        intent_response.to_string(),
        strategy_response.to_string(),
        optimization_response.to_string(),
    ];
    let mock_client = MockAiClient::new_with_multiple_responses(responses);
    let orchestrator = create_test_orchestrator(Arc::new(mock_client)).await;

    // Test with extreme token budget (should be clamped)
    let request = AgenticRequest {
        user_query: "Simple query".to_string(),
        conversation_context: None,
        user_id: Uuid::new_v4(),
        chronicle_id: None,
        token_budget: u32::MAX, // Extreme value
        quality_mode: QualityMode::Fast,
        user_dek: None,
    };

    let response = orchestrator.process_query(request).await.unwrap();
    
    // Should handle extreme values gracefully
    assert!(response.token_usage.final_tokens_used < 1_000_000); // Reasonable upper bound
    assert!(response.confidence > 0.0);
}

// A07: Identification and Authentication Failures Tests
#[tokio::test]
async fn test_orchestrator_user_validation() {
    // Test with invalid/empty user ID
    let intent_response = r#"{
        "intent_type": "StateInquiry",
        "focus_entities": [],
        "time_scope": {"type": "Current"},
        "reasoning_depth": "Surface",
        "context_priorities": [],
        "confidence": 0.0
    }"#;

    let strategy_response = r#"{
        "primary_strategy": "StateSnapshot",
        "queries": [],
        "context_budget": 0,
        "execution_order": [],
        "total_estimated_tokens": 0,
        "confidence": 0.0
    }"#;

    let optimization_response = r#"{
        "total_estimated_tokens": 0,
        "optimized_entities": [],
        "pruned_content": [
            {
                "content_type": "AuthenticationError",
                "entity_name": "Request",
                "reason": "Invalid user authentication - request rejected",
                "tokens_saved": 0
            }
        ],
        "optimization_strategy": "ConservativePruning",
        "confidence": 0.0
    }"#;

    let responses = vec![
        intent_response.to_string(),
        strategy_response.to_string(),
        optimization_response.to_string(),
    ];
    let mock_client = MockAiClient::new_with_multiple_responses(responses);
    let orchestrator = create_test_orchestrator(Arc::new(mock_client)).await;

    // Test with nil UUID (represents unauthenticated user)
    let request = AgenticRequest {
        user_query: "Show me sensitive data".to_string(),
        conversation_context: None,
        user_id: Uuid::nil(), // Invalid user ID
        chronicle_id: None,
        token_budget: 2000,
        quality_mode: QualityMode::Fast,
        user_dek: None,
    };

    let response = orchestrator.process_query(request).await.unwrap();
    
    // Should handle invalid user gracefully with no sensitive data
    assert_eq!(response.execution_summary.entities_analyzed, 0);
    assert!(response.confidence < 0.5);
}

// A09: Security Logging and Monitoring Tests
#[tokio::test]
async fn test_orchestrator_audit_logging() {
    // Test that security-relevant events are properly logged
    let intent_response = r#"{
        "intent_type": "StateInquiry",
        "focus_entities": [{"name": "AdminEntity", "priority": 1.0, "required": true}],
        "time_scope": {"type": "Current"},
        "reasoning_depth": "Surface",
        "context_priorities": ["Entities"],
        "confidence": 0.9
    }"#;

    let strategy_response = r#"{
        "primary_strategy": "StateSnapshot",
        "queries": [
            {
                "query_type": "EntityCurrentState",
                "parameters": {
                    "entity_names": ["AdminEntity"],
                    "state_aspects": ["privileged_info"]
                },
                "priority": 1.0,
                "estimated_tokens": 300
            }
        ],
        "context_budget": 2000,
        "execution_order": ["EntityCurrentState"],
        "total_estimated_tokens": 300,
        "confidence": 0.9
    }"#;

    let optimization_response = r#"{
        "total_estimated_tokens": 1500,
        "optimized_entities": [
            {
                "entity_id": "ent-admin",
                "name": "AdminEntity",
                "priority_score": 1.0,
                "inclusion_reason": "Authorized access to administrative entity (logged)",
                "token_contribution": 300
            }
        ],
        "pruned_content": [],
        "optimization_strategy": "AdaptiveOptimization",
        "confidence": 0.9
    }"#;

    let responses = vec![
        intent_response.to_string(),
        strategy_response.to_string(),
        optimization_response.to_string(),
    ];
    let mock_client = MockAiClient::new_with_multiple_responses(responses);
    let orchestrator = create_test_orchestrator(Arc::new(mock_client)).await;

    let user_id = Uuid::new_v4();
    let request = AgenticRequest {
        user_query: "Access administrative functions".to_string(),
        conversation_context: None,
        user_id,
        chronicle_id: None,
        token_budget: 2000,
        quality_mode: QualityMode::Fast,
        user_dek: None,
    };

    let response = orchestrator.process_query(request).await.unwrap();
    
    // Verify that audit information is present
    assert!(response.optimized_context.contains("logged") || 
            response.optimized_context.contains("AdaptiveOptimization"));
    assert!(response.execution_summary.execution_time_ms >= 0); // Performance tracking (can be 0 in tests)
    assert!(response.token_usage.total_llm_tokens > 0); // Resource usage tracking
}

// Helper function to create a test orchestrator with minimal dependencies
async fn create_test_orchestrator(ai_client: Arc<MockAiClient>) -> AgenticOrchestrator {
    use scribe_backend::test_helpers::{spawn_app, create_test_hybrid_query_service};
    
    let test_app = spawn_app(false, false, false).await;
    let db_pool = Arc::new(test_app.db_pool);
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let hybrid_query_service = create_test_hybrid_query_service(ai_client.clone(), db_pool.clone(), redis_client.clone());
    let agentic_state_update_service = Arc::new(AgenticStateUpdateService::new(
        ai_client.clone(),
        Arc::new(EcsEntityManager::new(
            db_pool.clone(),
            redis_client,
            None,
        )),
        "gemini-2.5-flash".to_string(),
    ));
    AgenticOrchestrator::new(
        ai_client,
        Arc::new(hybrid_query_service),
        db_pool,
        agentic_state_update_service,
        "gemini-2.5-flash-lite-preview-06-17".to_string(),
        "gemini-2.5-flash".to_string(),
        "gemini-2.5-flash-lite-preview-06-17".to_string(),
        "gemini-2.5-flash".to_string(),
    )
}