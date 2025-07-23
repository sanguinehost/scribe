// backend/tests/agentic_orchestrator_e2e_integration_tests.rs
// 
// Comprehensive end-to-end integration tests for the complete AgenticOrchestrator pipeline
// Tests the full flow: User Query → Intent Detection → Strategy Planning → Context Assembly → Optimization → Final Result

use std::sync::Arc;
use scribe_backend::{
    services::agentic_orchestrator::{AgenticOrchestrator, AgenticRequest, QualityMode},
    services::{AgenticStateUpdateService, EcsEntityManager},
    test_helpers::{spawn_app, MockAiClient, create_test_hybrid_query_service, TestDataGuard, db, MockQdrantClientService},
    errors::AppError,
    services::chronicle_service::ChronicleService,
    models::chronicle::CreateChronicleRequest,
};

#[tokio::test]
async fn test_orchestrator_simple_query_end_to_end() {
    let test_app = spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    
    // Create AI client with predefined responses for the full pipeline
    let ai_client = Arc::new(MockAiClient::new_with_multiple_responses(vec![
        // Mock intent detection response
        r#"{
            "intent_type": "StateInquiry",
            "focus_entities": [{"name": "Luke", "priority": 1.0, "required": true}],
            "time_scope": {"type": "Current"},
            "reasoning_depth": "Surface",
            "context_priorities": ["Entities", "RecentEvents"],
            "confidence": 0.85
        }"#.to_string(),
        // Mock strategy planning response
        r#"{
            "primary_strategy": "StateSnapshot",
            "queries": [
                {
                    "query_type": "EntityCurrentState",
                    "parameters": {
                        "entity_names": ["Luke"],
                        "chronicle_id": "test-chronicle"
                    },
                    "priority": 1.0,
                    "estimated_tokens": 500
                },
                {
                    "query_type": "RecentEvents",
                    "parameters": {
                        "time_scope": "Recent",
                        "max_events": 10,
                        "chronicle_id": "test-chronicle"
                    },
                    "priority": 0.8,
                    "estimated_tokens": 600
                }
            ],
            "context_budget": 4000,
            "execution_order": ["EntityCurrentState", "RecentEvents"],
            "reasoning": "Simple state inquiry for Luke requires current state and recent activity context",
            "confidence": 0.8
        }"#.to_string(),
        // Mock context optimization response
        r#"{
            "total_estimated_tokens": 2500,
            "optimized_entities": [
                {
                    "entity_id": "ent-luke-1",
                    "name": "Luke",
                    "priority_score": 0.95,
                    "inclusion_reason": "Primary character mentioned in query",
                    "token_contribution": 800
                }
            ],
            "pruned_content": [
                {
                    "content_type": "Minor Events",
                    "entity_name": "Background",
                    "reason": "Low relevance to query focus",
                    "tokens_saved": 300
                }
            ],
            "optimization_strategy": "EntityPrioritization",
            "confidence": 0.88
        }"#.to_string(),
    ]));
    
    // Create orchestrator using test helper
    let db_pool = Arc::new(pool.clone());
    let hybrid_query_service = create_test_hybrid_query_service(ai_client.clone(), db_pool.clone(), Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()));
    
    let _test_qdrant_service = MockQdrantClientService::new();
    let agentic_state_update_service = Arc::new(AgenticStateUpdateService::new(
        ai_client.clone(),
        Arc::new(EcsEntityManager::new(
            db_pool.clone(),
            Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
            None,
        )),
        "gemini-2.5-flash".to_string(),
    ));
    let orchestrator = AgenticOrchestrator::new(
        ai_client.clone(),
        Arc::new(hybrid_query_service),
        db_pool,
        agentic_state_update_service,
        "gemini-2.5-flash-lite-preview-06-17".to_string(),
        "gemini-2.5-flash".to_string(),
        "gemini-2.5-flash-lite-preview-06-17".to_string(),
        "gemini-2.5-flash".to_string(),
    );
    
    // Test simple query processing
    let mut guard = TestDataGuard::new(pool.clone());
    let user = db::create_test_user(&pool, "test_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    guard.add_user(user_id);
    let query = "Tell me about Luke's recent activities";
    
    let result = orchestrator.process_simple_query(query, user_id).await;
    
    assert!(result.is_ok(), "Simple query should succeed: {:?}", result.err());
    let context = result.unwrap();
    
    // Verify the result contains expected elements
    assert!(!context.is_empty(), "Context should not be empty");
    assert!(context.contains("Luke"), "Context should mention Luke");
    assert!(context.contains("Relevant Entities"), "Context should have entities section");
}

#[tokio::test]
async fn test_orchestrator_complex_query_with_chronicle() {
    let test_app = spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    
    let ai_client = Arc::new(MockAiClient::new_with_multiple_responses(vec![
        // Mock intent detection response
        r#"{
            "intent_type": "CausalAnalysis",
            "focus_entities": [
                {"name": "Luke", "priority": 1.0, "required": true},
                {"name": "Vader", "priority": 0.9, "required": false}
            ],
            "time_scope": {"type": "AllTime"},
            "reasoning_depth": "Causal",
            "context_priorities": ["CausalChains", "Entities", "TemporalState"],
            "confidence": 0.92
        }"#.to_string(),
        // Mock strategy planning response
        r#"{
            "primary_strategy": "CausalChainTraversal",
            "queries": [
                {
                    "query_type": "CausalChain",
                    "parameters": {
                        "from_entity": "Luke",
                        "causality_type": "departure",
                        "max_depth": 3,
                        "chronicle_id": "test-chronicle"
                    },
                    "priority": 1.0,
                    "estimated_tokens": 1200
                },
                {
                    "query_type": "TimelineEvents",
                    "parameters": {
                        "entity_names": ["Luke", "Vader"],
                        "event_categories": ["conflict", "departure"],
                        "chronicle_id": "test-chronicle"
                    },
                    "priority": 0.9,
                    "estimated_tokens": 1000
                },
                {
                    "query_type": "SharedEvents",
                    "parameters": {
                        "entities": ["Luke", "Vader"],
                        "chronicle_id": "test-chronicle"
                    },
                    "priority": 0.7,
                    "estimated_tokens": 800
                }
            ],
            "context_budget": 4000,
            "execution_order": ["CausalChain", "TimelineEvents", "SharedEvents"],
            "reasoning": "Complex causal analysis requires deep traversal of causal chains and timeline reconstruction",
            "confidence": 0.88
        }"#.to_string(),
        // Mock context optimization response
        r#"{
            "total_estimated_tokens": 3800,
            "optimized_entities": [
                {
                    "entity_id": "ent-luke-1",
                    "name": "Luke",
                    "priority_score": 0.98,
                    "inclusion_reason": "Primary subject of causal analysis",
                    "token_contribution": 1200
                },
                {
                    "entity_id": "ent-vader-1",
                    "name": "Vader",
                    "priority_score": 0.85,
                    "inclusion_reason": "Key causal factor in Luke's departure",
                    "token_contribution": 800
                }
            ],
            "pruned_content": [
                {
                    "content_type": "Background Events",
                    "entity_name": "Various",
                    "reason": "Not directly causal to main narrative",
                    "tokens_saved": 200
                }
            ],
            "optimization_strategy": "CausalPathFocus",
            "confidence": 0.91
        }"#.to_string(),
    ]));
    
    // Create full orchestrator
    let db_pool = Arc::new(pool.clone());
    let hybrid_query_service = create_test_hybrid_query_service(ai_client.clone(), db_pool.clone(), Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()));
    
    let _test_qdrant_service = MockQdrantClientService::new();
    let agentic_state_update_service = Arc::new(AgenticStateUpdateService::new(
        ai_client.clone(),
        Arc::new(EcsEntityManager::new(
            db_pool.clone(),
            Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
            None,
        )),
        "gemini-2.5-flash".to_string(),
    ));
    let orchestrator = AgenticOrchestrator::new(
        ai_client.clone(),
        Arc::new(hybrid_query_service),
        db_pool,
        agentic_state_update_service,
        "gemini-2.5-flash-lite-preview-06-17".to_string(),
        "gemini-2.5-flash".to_string(),
        "gemini-2.5-flash-lite-preview-06-17".to_string(),
        "gemini-2.5-flash".to_string(),
    );
    
    // Create user and chronicle
    let mut guard = TestDataGuard::new(pool.clone());
    let user = db::create_test_user(&pool, "test_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    guard.add_user(user_id);
    let chronicle_service = Arc::new(ChronicleService::new(pool.clone()));
    let create_chronicle_request = CreateChronicleRequest {
        name: "Test Chronicle".to_string(),
        description: Some("Test chronicle for integration tests".to_string()),
    };
    let chronicle_id = chronicle_service.create_chronicle(user_id, create_chronicle_request).await.unwrap().id;
    
    // Create complex request
    let request = AgenticRequest {
        user_query: "Why did Luke leave and how did his relationship with Vader influence this decision?".to_string(),
        conversation_context: Some("Previous discussion about family dynamics in the story".to_string()),
        user_id,
        chronicle_id: Some(chronicle_id),
        token_budget: 4000,
        quality_mode: QualityMode::Thorough,
        user_dek: None,
    };
    
    let result = orchestrator.process_query(request).await;
    
    assert!(result.is_ok(), "Complex query should succeed: {:?}", result.err());
    let response = result.unwrap();
    
    // Verify response structure
    assert!(response.confidence > 0.0, "Response should have confidence score");
    assert!(response.token_usage.total_llm_tokens > 0, "Should record token usage");
    assert!(response.execution_summary.queries_executed > 0, "Should execute queries");
    assert!(!response.optimized_context.is_empty(), "Should have optimized context");
    
    // Verify content quality
    assert!(response.optimized_context.contains("Luke"), "Context should mention Luke");
    assert!(response.optimized_context.contains("Vader"), "Context should mention Vader");
    assert!(response.optimized_context.contains("Relevant Entities"), "Should have entities section");
    assert!(response.optimized_context.contains("Context Data"), "Should have context data section");
}

#[tokio::test]
async fn test_orchestrator_error_handling_and_recovery() {
    let test_app = spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    
    let ai_client = Arc::new(MockAiClient::new_with_multiple_responses(vec![
        "invalid json response".to_string(), // This will cause parsing to fail
    ]));
    
    let db_pool = Arc::new(pool.clone());
    let hybrid_query_service = create_test_hybrid_query_service(ai_client.clone(), db_pool.clone(), Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()));
    
    let _test_qdrant_service = MockQdrantClientService::new();
    let agentic_state_update_service = Arc::new(AgenticStateUpdateService::new(
        ai_client.clone(),
        Arc::new(EcsEntityManager::new(
            db_pool.clone(),
            Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
            None,
        )),
        "gemini-2.5-flash".to_string(),
    ));
    let orchestrator = AgenticOrchestrator::new(
        ai_client.clone(),
        Arc::new(hybrid_query_service),
        db_pool,
        agentic_state_update_service,
        "gemini-2.5-flash-lite-preview-06-17".to_string(),
        "gemini-2.5-flash".to_string(),
        "gemini-2.5-flash-lite-preview-06-17".to_string(),
        "gemini-2.5-flash".to_string(),
    );
    
    let mut guard = TestDataGuard::new(pool.clone());
    let user = db::create_test_user(&pool, "test_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    guard.add_user(user_id);
    
    // Test error handling with invalid AI response
    let result = orchestrator.process_simple_query("Test query", user_id).await;
    
    assert!(result.is_err(), "Should handle invalid AI response gracefully");
    
    // Verify error type
    match result.err().unwrap() {
        AppError::SerializationError(_) => {
            // Expected error type - invalid JSON causes serialization error
        },
        AppError::LlmClientError(_) => {
            // Also acceptable error type
        },
        other => panic!("Expected SerializationError or LlmClientError, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_orchestrator_metrics_collection() {
    let test_app = spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    
    let ai_client = Arc::new(MockAiClient::new_with_multiple_responses(vec![
        // Mock intent detection response
        r#"{
            "intent_type": "StateInquiry",
            "focus_entities": [{"name": "Test", "priority": 1.0, "required": true}],
            "time_scope": {"type": "Current"},
            "reasoning_depth": "Surface",
            "context_priorities": ["Entities"],
            "confidence": 0.8
        }"#.to_string(),
        // Mock strategy planning response
        r#"{
            "primary_strategy": "StateSnapshot",
            "queries": [
                {
                    "query_type": "EntityCurrentState",
                    "parameters": {"entity_names": ["Test"]},
                    "priority": 1.0,
                    "estimated_tokens": 400
                }
            ],
            "context_budget": 4000,
            "execution_order": ["EntityCurrentState"],
            "reasoning": "Simple state inquiry for test entity requires current state snapshot",
            "confidence": 0.8
        }"#.to_string(),
        // Mock context optimization response
        r#"{
            "total_estimated_tokens": 1000,
            "optimized_entities": [
                {
                    "entity_id": "ent-test-1",
                    "name": "Test",
                    "priority_score": 0.9,
                    "inclusion_reason": "Primary entity",
                    "token_contribution": 400
                }
            ],
            "pruned_content": [],
            "optimization_strategy": "EntityPrioritization",
            "confidence": 0.85
        }"#.to_string(),
    ]));
    
    let db_pool = Arc::new(pool.clone());
    let hybrid_query_service = create_test_hybrid_query_service(ai_client.clone(), db_pool.clone(), Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()));
    
    let _test_qdrant_service = MockQdrantClientService::new();
    let agentic_state_update_service = Arc::new(AgenticStateUpdateService::new(
        ai_client.clone(),
        Arc::new(EcsEntityManager::new(
            db_pool.clone(),
            Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
            None,
        )),
        "gemini-2.5-flash".to_string(),
    ));
    let orchestrator = AgenticOrchestrator::new(
        ai_client.clone(),
        Arc::new(hybrid_query_service),
        db_pool,
        agentic_state_update_service,
        "gemini-2.5-flash-lite-preview-06-17".to_string(),
        "gemini-2.5-flash".to_string(),
        "gemini-2.5-flash-lite-preview-06-17".to_string(),
        "gemini-2.5-flash".to_string(),
    );
    
    let mut guard = TestDataGuard::new(pool.clone());
    let user = db::create_test_user(&pool, "test_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    guard.add_user(user_id);
    
    // Process a query to generate metrics
    let result = orchestrator.process_simple_query("Test metrics collection", user_id).await;
    assert!(result.is_ok(), "Query should succeed for metrics test");
    
    // Check metrics collection
    let metrics = orchestrator.get_metrics().await;
    assert!(metrics.processing_stats.total_requests > 0, "Should record at least one request");
    
    // Test metrics aggregation
    let aggregation_result = orchestrator.aggregate_metrics().await;
    assert!(aggregation_result.is_ok(), "Metrics aggregation should succeed");
    
    // Test token optimization insights
    let _insights = orchestrator.get_token_optimization_insights().await;
    // Just verify the call succeeds - insights might have recommendations depending on data
    // Just verify the call succeeds - insights will have some recommendations
}

#[tokio::test]
async fn test_orchestrator_quality_modes() {
    let test_app = spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    
    // Set up responses that vary by quality mode (9 responses total: 3 per mode × 3 modes)
    let mut responses = Vec::new();
    for _ in 0..3 { // 3 quality modes
        responses.push(r#"{
            "intent_type": "StateInquiry",
            "focus_entities": [{"name": "Test", "priority": 1.0, "required": true}],
            "time_scope": {"type": "Current"},
            "reasoning_depth": "Surface",
            "context_priorities": ["Entities"],
            "confidence": 0.8
        }"#.to_string());
        
        responses.push(r#"{
            "primary_strategy": "StateSnapshot",
            "queries": [
                {
                    "query_type": "EntityCurrentState",
                    "parameters": {"entity_names": ["Test"]},
                    "priority": 1.0,
                    "estimated_tokens": 400
                }
            ],
            "context_budget": 4000,
            "execution_order": ["EntityCurrentState"],
            "reasoning": "Quality mode state analysis requires comprehensive entity context",
            "confidence": 0.8
        }"#.to_string());
        
        responses.push(r#"{
            "total_estimated_tokens": 1000,
            "optimized_entities": [
                {
                    "entity_id": "ent-test-1",
                    "name": "Test",
                    "priority_score": 0.9,
                    "inclusion_reason": "Primary entity",
                    "token_contribution": 400
                }
            ],
            "pruned_content": [],
            "optimization_strategy": "EntityPrioritization",
            "confidence": 0.85
        }"#.to_string());
    }
    
    let ai_client = Arc::new(MockAiClient::new_with_multiple_responses(responses));
    
    let db_pool = Arc::new(pool.clone());
    let hybrid_query_service = create_test_hybrid_query_service(ai_client.clone(), db_pool.clone(), Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()));
    
    let _test_qdrant_service = MockQdrantClientService::new();
    let agentic_state_update_service = Arc::new(AgenticStateUpdateService::new(
        ai_client.clone(),
        Arc::new(EcsEntityManager::new(
            db_pool.clone(),
            Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
            None,
        )),
        "gemini-2.5-flash".to_string(),
    ));
    let orchestrator = AgenticOrchestrator::new(
        ai_client.clone(),
        Arc::new(hybrid_query_service),
        db_pool,
        agentic_state_update_service,
        "gemini-2.5-flash-lite-preview-06-17".to_string(),
        "gemini-2.5-flash".to_string(),
        "gemini-2.5-flash-lite-preview-06-17".to_string(),
        "gemini-2.5-flash".to_string(),
    );
    
    let mut guard = TestDataGuard::new(pool.clone());
    let user = db::create_test_user(&pool, "test_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    guard.add_user(user_id);
    let base_query = "Analyze the character development".to_string();
    
    // Test all quality modes
    let quality_modes = vec![
        QualityMode::Fast,
        QualityMode::Balanced,
        QualityMode::Thorough,
    ];
    
    for quality_mode in quality_modes {
        let request = AgenticRequest {
            user_query: base_query.clone(),
            conversation_context: None,
            user_id,
            chronicle_id: None,
            token_budget: 4000,
            quality_mode: quality_mode.clone(),
            user_dek: None,
        };
        
        let result = orchestrator.process_query(request).await;
        assert!(result.is_ok(), "Query should succeed for quality mode: {:?}", quality_mode);
        
        let response = result.unwrap();
        assert!(response.confidence > 0.0, "Should have confidence for quality mode: {:?}", quality_mode);
        assert!(!response.optimized_context.is_empty(), "Should have context for quality mode: {:?}", quality_mode);
    }
}

#[tokio::test]
async fn test_orchestrator_token_budget_constraints() {
    let test_app = spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    
    let ai_client = Arc::new(MockAiClient::new_with_multiple_responses(vec![
        // Mock intent detection response
        r#"{
            "intent_type": "StateInquiry",
            "focus_entities": [{"name": "Test", "priority": 1.0, "required": true}],
            "time_scope": {"type": "Current"},
            "reasoning_depth": "Surface",
            "context_priorities": ["Entities"],
            "confidence": 0.8
        }"#.to_string(),
        // Mock strategy planning response
        r#"{
            "primary_strategy": "StateSnapshot",
            "queries": [
                {
                    "query_type": "EntityCurrentState",
                    "parameters": {"entity_names": ["Test"]},
                    "priority": 1.0,
                    "estimated_tokens": 2000
                }
            ],
            "context_budget": 1000,
            "execution_order": ["EntityCurrentState"],
            "reasoning": "Budget-constrained state inquiry requires minimal essential context",
            "confidence": 0.8
        }"#.to_string(),
        // Mock context optimization response
        r#"{
            "total_estimated_tokens": 800,
            "optimized_entities": [
                {
                    "entity_id": "ent-test-1",
                    "name": "Test",
                    "priority_score": 0.9,
                    "inclusion_reason": "Primary entity (reduced due to budget)",
                    "token_contribution": 300
                }
            ],
            "pruned_content": [
                {
                    "content_type": "Extended Details",
                    "entity_name": "Test",
                    "reason": "Token budget constraint",
                    "tokens_saved": 1200
                }
            ],
            "optimization_strategy": "TokenBudgetConstraint",
            "confidence": 0.75
        }"#.to_string(),
    ]));
    
    let db_pool = Arc::new(pool.clone());
    let hybrid_query_service = create_test_hybrid_query_service(ai_client.clone(), db_pool.clone(), Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()));
    
    let _test_qdrant_service = MockQdrantClientService::new();
    let agentic_state_update_service = Arc::new(AgenticStateUpdateService::new(
        ai_client.clone(),
        Arc::new(EcsEntityManager::new(
            db_pool.clone(),
            Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
            None,
        )),
        "gemini-2.5-flash".to_string(),
    ));
    let orchestrator = AgenticOrchestrator::new(
        ai_client.clone(),
        Arc::new(hybrid_query_service),
        db_pool,
        agentic_state_update_service,
        "gemini-2.5-flash-lite-preview-06-17".to_string(),
        "gemini-2.5-flash".to_string(),
        "gemini-2.5-flash-lite-preview-06-17".to_string(),
        "gemini-2.5-flash".to_string(),
    );
    
    let mut guard = TestDataGuard::new(pool.clone());
    let user = db::create_test_user(&pool, "test_user".to_string(), "password123".to_string()).await.unwrap();
    let user_id = user.id;
    guard.add_user(user_id);
    
    // Test with very low token budget
    let request = AgenticRequest {
        user_query: "Detailed analysis of character".to_string(),
        conversation_context: None,
        user_id,
        chronicle_id: None,
        token_budget: 1000, // Very low budget
        quality_mode: QualityMode::Balanced,
        user_dek: None,
    };
    
    let result = orchestrator.process_query(request).await;
    assert!(result.is_ok(), "Query should succeed even with low token budget");
    
    let response = result.unwrap();
    
    // Verify budget constraints were respected
    assert!(response.token_usage.final_tokens_used <= 1000, "Should respect token budget");
    assert!(response.execution_summary.content_pruned > 0, "Should prune content for budget");
    assert!(!response.optimized_context.is_empty(), "Should still provide some context");
}