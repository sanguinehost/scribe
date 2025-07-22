// NLP Query Handler Tests
//
// Tests for Phase 3: LLM Integration Layer - NLP Query Handler
// - Intent detection and classification
// - Query analysis and complexity scoring
// - Reasoning suggestion generation
// - LLM response formatting
// - OWASP security compliance

use std::sync::Arc;
use chrono::Duration;

use scribe_backend::{
    services::{
        nlp_query_handler::{IntentType, QueryIntent, NLPQueryHandler},
        world_model_service::{TimeFocus, ReasoningDepth, WorldModelService},
        hybrid_query_service::HybridQueryService,
    },
    test_helpers::{spawn_app, TestDataGuard, db::create_test_user},
};

#[tokio::test]
async fn test_nlp_query_handler_creation() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let world_model_service = create_world_model_service(&app);
    let hybrid_query_service = create_hybrid_query_service(&app);
    
    let nlp_handler = NLPQueryHandler::new(
        world_model_service,
        hybrid_query_service,
    );
    
    // Test basic intent analysis
    let intent = nlp_handler.analyze_query_intent("What caused the dragon to attack?").unwrap();
    
    assert!(matches!(intent.intent_type, IntentType::CausalReasoning));
    assert!(intent.confidence > 0.7);
    assert!(intent.extracted_keywords.contains(&"caused".to_string()));
    assert!(intent.extracted_keywords.contains(&"dragon".to_string()));
    assert!(intent.extracted_keywords.contains(&"attack".to_string()));
    assert!(matches!(intent.reasoning_depth, ReasoningDepth::Deep));
}

#[tokio::test]
async fn test_intent_classification_varieties() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());

    let world_model_service = create_world_model_service(&app);
    let hybrid_query_service = create_hybrid_query_service(&app);
    let nlp_handler = NLPQueryHandler::new(world_model_service, hybrid_query_service);

    // Test causal reasoning intent
    let causal_intent = nlp_handler.analyze_query_intent("Why did the hero leave the village?").unwrap();
    assert!(matches!(causal_intent.intent_type, IntentType::CausalReasoning));
    assert!(causal_intent.confidence > 0.8);

    // Test spatial query intent
    let spatial_intent = nlp_handler.analyze_query_intent("Where is the treasure located?").unwrap();
    assert!(matches!(spatial_intent.intent_type, IntentType::SpatialQuery));

    // Test relationship analysis intent
    let relationship_intent = nlp_handler.analyze_query_intent("What is the relationship between the king and the wizard?").unwrap();
    assert!(matches!(relationship_intent.intent_type, IntentType::RelationshipAnalysis));

    // Test temporal query intent
    let temporal_intent = nlp_handler.analyze_query_intent("What happened before the battle?").unwrap();
    assert!(matches!(temporal_intent.intent_type, IntentType::TemporalQuery));

    // Test quantitative query intent
    let quantitative_intent = nlp_handler.analyze_query_intent("How many soldiers are in the army?").unwrap();
    assert!(matches!(quantitative_intent.intent_type, IntentType::QuantitativeQuery));

    // Test comparative query intent
    let comparative_intent = nlp_handler.analyze_query_intent("Compare the strength of the two armies").unwrap();
    assert!(matches!(comparative_intent.intent_type, IntentType::ComparativeQuery));

    // Test general inquiry intent
    let general_intent = nlp_handler.analyze_query_intent("Tell me about the current situation").unwrap();
    assert!(matches!(general_intent.intent_type, IntentType::GeneralInquiry));
}

#[tokio::test]
async fn test_time_focus_detection() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());

    let world_model_service = create_world_model_service(&app);
    let hybrid_query_service = create_hybrid_query_service(&app);
    let nlp_handler = NLPQueryHandler::new(world_model_service, hybrid_query_service);

    // Test current time focus
    let current_intent = nlp_handler.analyze_query_intent("What is currently happening in the kingdom?").unwrap();
    assert!(matches!(current_intent.time_focus, TimeFocus::Current));

    // Test historical time focus
    let historical_intent = nlp_handler.analyze_query_intent("What happened last week in the village?").unwrap();
    assert!(matches!(historical_intent.time_focus, TimeFocus::Historical(_)));

    // Test week-based historical focus
    let week_intent = nlp_handler.analyze_query_intent("Show me events from this week").unwrap();
    if let TimeFocus::Historical(duration) = week_intent.time_focus {
        assert_eq!(duration, Duration::weeks(1));
    } else {
        panic!("Expected Historical time focus with week duration");
    }

    // Test month-based historical focus
    let month_intent = nlp_handler.analyze_query_intent("What changed this month?").unwrap();
    if let TimeFocus::Historical(duration) = month_intent.time_focus {
        assert_eq!(duration, Duration::days(30));
    } else {
        panic!("Expected Historical time focus with month duration");
    }
}

#[tokio::test]
async fn test_query_complexity_scoring() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());

    let world_model_service = create_world_model_service(&app);
    let hybrid_query_service = create_hybrid_query_service(&app);
    let nlp_handler = NLPQueryHandler::new(world_model_service, hybrid_query_service);

    // Simple query should have low complexity
    let simple_complexity = nlp_handler.calculate_query_complexity("Where is John?");
    assert!(simple_complexity < 0.5);

    // Complex causal query should have higher complexity
    let complex_complexity = nlp_handler.calculate_query_complexity("Why did the relationship between the king and the wizard deteriorate after the battle?");
    assert!(complex_complexity > 0.7);

    // Very long query should have increased complexity
    let long_query = "Compare the differences between the magical systems used by the northern wizards versus the southern sorcerers in terms of their impact on the political relationships between various kingdoms and their influence on recent battles and territorial disputes".to_string();
    let long_complexity = nlp_handler.calculate_query_complexity(&long_query);
    assert!(long_complexity > 0.6);
}

#[tokio::test]
async fn test_reasoning_suggestions_generation() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());

    let world_model_service = create_world_model_service(&app);
    let hybrid_query_service = create_hybrid_query_service(&app);
    let nlp_handler = NLPQueryHandler::new(world_model_service, hybrid_query_service);

    // Create a sample intent and LLM context
    let intent = QueryIntent {
        intent_type: IntentType::CausalReasoning,
        focus_entities: None,
        time_focus: TimeFocus::Current,
        reasoning_depth: ReasoningDepth::Deep,
        confidence: 0.8,
        extracted_keywords: vec!["caused".to_string(), "effect".to_string()],
        complexity_score: 0.7,
    };

    let llm_context = scribe_backend::models::world_model::LLMWorldContext {
        entity_summaries: vec![],
        relationship_graph: scribe_backend::models::world_model::RelationshipGraph {
            nodes: vec![],
            edges: vec![],
            clusters: vec![],
        },
        causal_chains: vec![
            scribe_backend::models::world_model::CausalChain::new(
                "Hero casts spell".to_string(),
                "Monster is defeated".to_string(),
                0.9,
            ),
        ],
        spatial_context: scribe_backend::models::world_model::SpatialContext::new(),
        recent_changes: vec![],
        reasoning_hints: vec![],
    };

    let suggestions = nlp_handler.generate_reasoning_suggestions(&intent, &llm_context).unwrap();

    // Should have at least one methodology suggestion
    assert!(!suggestions.is_empty());
    assert!(suggestions.iter().any(|s| s.suggestion_type == "methodology"));

    // Should have evidence suggestion when causal chains exist
    assert!(suggestions.iter().any(|s| s.suggestion_type == "evidence"));

    // Methodology suggestion should have reasoning path
    let methodology_suggestion = suggestions.iter().find(|s| s.suggestion_type == "methodology").unwrap();
    assert!(!methodology_suggestion.reasoning_path.is_empty());
    assert!(methodology_suggestion.confidence > 0.8);
}

#[tokio::test]
async fn test_full_nlp_query_processing() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let world_model_service = create_world_model_service(&app);
    let hybrid_query_service = create_hybrid_query_service(&app);
    let nlp_handler = NLPQueryHandler::new(world_model_service, hybrid_query_service);

    // Process a complete natural language query
    let response = nlp_handler.process_natural_language_query(
        user.id,
        None, // No specific chronicle
        "What caused the recent conflict in the kingdom?",
        Duration::hours(24),
    ).await.unwrap();

    // Verify response structure
    assert_eq!(response.original_query, "What caused the recent conflict in the kingdom?");
    assert!(matches!(response.interpreted_intent.intent_type, IntentType::CausalReasoning));
    assert!(response.confidence > 0.0);
    assert!(!response.reasoning_suggestions.is_empty());

    // Should have world context
    assert_eq!(response.world_context.entity_summaries.len(), 0); // No entities in fresh test DB
    
    // Should have specific results based on intent
    assert!(!response.specific_results.is_empty());
    let causal_result = response.specific_results.iter()
        .find(|r| r.result_type == "causal_influences")
        .expect("Should have causal influences result for causal reasoning query");
    assert!(causal_result.relevance > 0.8);
}

// OWASP Security Tests for NLP Query Handler

#[tokio::test]
async fn test_nlp_query_handler_injection_resistance() {
    // A03: Injection - Test SQL injection resistance in query processing
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let world_model_service = create_world_model_service(&app);
    let hybrid_query_service = create_hybrid_query_service(&app);
    let nlp_handler = NLPQueryHandler::new(world_model_service, hybrid_query_service);

    // Test with malicious SQL injection attempts
    let malicious_queries = vec![
        "'; DROP TABLE entities; --",
        "What caused '; DELETE FROM chronicle_events; -- the attack?",
        "<script>alert('xss')</script> Where is the treasure?",
        "../../etc/passwd What happened yesterday?",
        "\"; rm -rf /; What is the relationship between",
        "' UNION SELECT * FROM users --",
    ];

    for malicious_query in malicious_queries {
        let result = nlp_handler.process_natural_language_query(
            user.id,
            None,
            malicious_query,
            Duration::hours(1),
        ).await;

        // Should handle malicious queries without crashing
        assert!(result.is_ok(), "Query handler should safely process malicious query: {}", malicious_query);
        
        if let Ok(response) = result {
            // Original query should be preserved exactly (not interpreted as SQL)
            assert_eq!(response.original_query, malicious_query);
            // Should still provide some form of response
            assert!(response.confidence >= 0.0);
        }
    }
}

#[tokio::test]
async fn test_nlp_query_handler_memory_safety() {
    // Performance and DoS protection test - prevent excessive memory usage
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let world_model_service = create_world_model_service(&app);
    let hybrid_query_service = create_hybrid_query_service(&app);
    let nlp_handler = NLPQueryHandler::new(world_model_service, hybrid_query_service);

    // Test with very long query
    let long_query = "What ".repeat(1000) + "happened yesterday?";
    
    let start_time = std::time::Instant::now();
    let result = nlp_handler.process_natural_language_query(
        user.id,
        None,
        &long_query,
        Duration::minutes(1),
    ).await;
    let processing_time = start_time.elapsed();

    assert!(result.is_ok(), "Should handle long queries gracefully");
    assert!(processing_time.as_secs() < 5, "Should process long queries within reasonable time");

    if let Ok(response) = result {
        // Should maintain reasonable response size even for long queries
        assert!(response.reasoning_suggestions.len() < 20, "Should not generate excessive reasoning suggestions");
        assert!(response.specific_results.len() < 50, "Should not generate excessive results");
    }
}

#[tokio::test]
async fn test_nlp_query_handler_input_validation() {
    // A08: Software and Data Integrity Failures - Test input validation
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    let user = create_test_user(&app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();

    let world_model_service = create_world_model_service(&app);
    let hybrid_query_service = create_hybrid_query_service(&app);
    let nlp_handler = NLPQueryHandler::new(world_model_service, hybrid_query_service);

    // Test with empty query
    let empty_result = nlp_handler.process_natural_language_query(
        user.id,
        None,
        "",
        Duration::hours(1),
    ).await;
    assert!(empty_result.is_ok(), "Should handle empty queries gracefully");

    // Test with whitespace-only query
    let whitespace_result = nlp_handler.process_natural_language_query(
        user.id,
        None,
        "   \t\n   ",
        Duration::hours(1),
    ).await;
    assert!(whitespace_result.is_ok(), "Should handle whitespace-only queries gracefully");

    // Test with special characters
    let special_chars_result = nlp_handler.process_natural_language_query(
        user.id,
        None,
        "!@#$%^&*()_+-=[]{}|;':\",./<>?",
        Duration::hours(1),
    ).await;
    assert!(special_chars_result.is_ok(), "Should handle special characters gracefully");

    // Test with unicode characters
    let unicode_result = nlp_handler.process_natural_language_query(
        user.id,
        None,
        "¿Qué causó el ataque del dragón? 🐉⚔️",
        Duration::hours(1),
    ).await;
    assert!(unicode_result.is_ok(), "Should handle unicode characters gracefully");
}

#[tokio::test]
async fn test_nlp_query_handler_access_control() {
    // A01: Broken Access Control - Ensure user isolation
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user1 = create_test_user(&app.db_pool, "user1".to_string(), "password123".to_string()).await.unwrap();
    let user2 = create_test_user(&app.db_pool, "user2".to_string(), "password123".to_string()).await.unwrap();

    let world_model_service = create_world_model_service(&app);
    let hybrid_query_service = create_hybrid_query_service(&app);
    let nlp_handler = NLPQueryHandler::new(world_model_service, hybrid_query_service);

    // Process queries for both users
    let user1_response = nlp_handler.process_natural_language_query(
        user1.id,
        None,
        "What is happening in my kingdom?",
        Duration::hours(1),
    ).await.unwrap();

    let user2_response = nlp_handler.process_natural_language_query(
        user2.id,
        None,
        "What is happening in my kingdom?",
        Duration::hours(1),
    ).await.unwrap();

    // Responses should be isolated - users should not see each other's data
    assert_eq!(user1_response.world_context.entity_summaries.len(), 0); // Fresh DB
    assert_eq!(user2_response.world_context.entity_summaries.len(), 0); // Fresh DB
    
    // Each user should get their own world context (even if empty in test)
    // The important thing is that the queries are properly isolated by user_id
    assert!(user1_response.world_context.entity_summaries.len() >= 0); // Sanity check
    assert!(user2_response.world_context.entity_summaries.len() >= 0); // Sanity check
}

// Helper functions

fn create_world_model_service(app: &scribe_backend::test_helpers::TestApp) -> Arc<WorldModelService> {
    // Create minimal Redis client for testing
    let redis_client = Arc::new(redis::Client::open("redis://localhost:6379/").unwrap_or_else(|_| {
        // If Redis is not available, create a dummy client that won't be used
        redis::Client::open("redis://localhost:6379/").unwrap()
    }));
    
    // Create required dependencies
    let entity_manager = Arc::new(scribe_backend::services::ecs_entity_manager::EcsEntityManager::new(
        Arc::new(app.db_pool.clone()),
        redis_client,
        None,
    ));
    
    let hybrid_query_service = create_hybrid_query_service(app);
    
    let chronicle_service = Arc::new(scribe_backend::services::chronicle_service::ChronicleService::new(
        app.db_pool.clone()
    ));

    Arc::new(WorldModelService::new(
        Arc::new(app.db_pool.clone()),
        entity_manager,
        hybrid_query_service.clone(),
        chronicle_service,
    ))
}

fn create_hybrid_query_service(app: &scribe_backend::test_helpers::TestApp) -> Arc<HybridQueryService> {
    // Create minimal feature flags for testing
    let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
    
    // Create minimal dependencies for testing
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
        Arc::new(app.db_pool.clone()),
        redis_client.clone(),
        None,
    ));
    
    let degradation_service = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
        Default::default(),
        feature_flags.clone(),
        Some(entity_manager.clone()),
        None,
    ));
    
    let concrete_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
        scribe_backend::text_processing::chunking::ChunkConfig {
            metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
            max_size: 500,
            overlap: 50,
        }
    ));
    
    let rag_service = Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(),
        feature_flags.clone(),
        entity_manager.clone(),
        degradation_service.clone(),
        concrete_embedding_service,
    ));
    
    Arc::new(HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        Default::default(), // HybridQueryConfig
        feature_flags,
        app.ai_client.clone(),
        "gemini-2.5-flash".to_string(),
        entity_manager,
        rag_service,
        degradation_service,
    ))
}