use scribe_backend::services::context_optimization_service::*;
use scribe_backend::services::context_assembly_engine::*;
use scribe_backend::services::query_strategy_planner::QueryStrategy;
use scribe_backend::test_helpers::MockAiClient;
use std::sync::Arc;
use std::collections::HashMap;
use uuid::Uuid;

#[tokio::test]
async fn test_prioritize_entities_high_relevance() {
    let response_json = r#"{
        "total_estimated_tokens": 3000,
        "optimized_entities": [
            {
                "entity_id": "ent-1",
                "name": "Luke",
                "priority_score": 0.95,
                "inclusion_reason": "Primary character in user query",
                "token_contribution": 800
            },
            {
                "entity_id": "ent-2", 
                "name": "Vader",
                "priority_score": 0.85,
                "inclusion_reason": "Key relationship with Luke",
                "token_contribution": 600
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
        "optimization_strategy": "EntityPrioritization",
        "confidence": 0.9
    }"#;

    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let service = ContextOptimizationService::new(Arc::new(mock_client));

    // Create test context
    let context = create_test_assembled_context();
    
    let optimization = service.optimize_context(&context, 4000, "What caused Luke to leave?").await.unwrap();
    
    assert_eq!(optimization.total_estimated_tokens, 3000);
    assert_eq!(optimization.optimized_entities.len(), 2);
    assert_eq!(optimization.optimized_entities[0].name, "Luke");
    assert_eq!(optimization.optimized_entities[0].priority_score, 0.95);
    assert_eq!(optimization.pruned_content.len(), 1);
    assert!(matches!(optimization.optimization_strategy, OptimizationStrategy::EntityPrioritization));
    assert!(optimization.confidence > 0.8);
}

#[tokio::test]
async fn test_temporal_filtering_strategy() {
    let response_json = r#"{
        "total_estimated_tokens": 2500,
        "optimized_entities": [
            {
                "entity_id": "ent-1",
                "name": "Luke",
                "priority_score": 1.0,
                "inclusion_reason": "Recent activity relevant to query timeframe",
                "token_contribution": 900
            }
        ],
        "pruned_content": [
            {
                "content_type": "TimelineEvents",
                "entity_name": "Luke",
                "reason": "Events older than 30 days, not relevant to recent query",
                "tokens_saved": 800
            }
        ],
        "optimization_strategy": "TemporalFiltering",
        "confidence": 0.85
    }"#;

    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let service = ContextOptimizationService::new(Arc::new(mock_client));

    let context = create_test_assembled_context();
    
    let optimization = service.optimize_context(&context, 3000, "What has Luke been doing recently?").await.unwrap();
    
    assert!(matches!(optimization.optimization_strategy, OptimizationStrategy::TemporalFiltering));
    assert_eq!(optimization.total_estimated_tokens, 2500);
    assert!(optimization.pruned_content.iter().any(|p| p.reason.contains("older than 30 days")));
}

#[tokio::test]
async fn test_relevance_clustering_strategy() {
    let response_json = r#"{
        "total_estimated_tokens": 3500,
        "optimized_entities": [
            {
                "entity_id": "ent-1",
                "name": "Luke",
                "priority_score": 0.95,
                "inclusion_reason": "Core entity in relationship cluster",
                "token_contribution": 1000
            },
            {
                "entity_id": "ent-2",
                "name": "Obi-Wan", 
                "priority_score": 0.90,
                "inclusion_reason": "Strong relationship with Luke",
                "token_contribution": 800
            }
        ],
        "pruned_content": [
            {
                "content_type": "EntityRelationships",
                "entity_name": "Minor Character",
                "reason": "Weak connection to core relationship cluster",
                "tokens_saved": 600
            }
        ],
        "optimization_strategy": "RelevanceClustering",
        "confidence": 0.88
    }"#;

    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let service = ContextOptimizationService::new(Arc::new(mock_client));

    let context = create_test_assembled_context();
    
    let optimization = service.optimize_context(&context, 4000, "How do Luke and Obi-Wan relate?").await.unwrap();
    
    assert!(matches!(optimization.optimization_strategy, OptimizationStrategy::RelevanceClustering));
    assert_eq!(optimization.optimized_entities.len(), 2);
    assert!(optimization.optimized_entities.iter().any(|e| e.name == "Luke"));
    assert!(optimization.optimized_entities.iter().any(|e| e.name == "Obi-Wan"));
}

#[tokio::test]
async fn test_causal_path_focus_strategy() {
    let response_json = r#"{
        "total_estimated_tokens": 2800,
        "optimized_entities": [
            {
                "entity_id": "ent-1",
                "name": "Luke",
                "priority_score": 1.0,
                "inclusion_reason": "Start of causal chain",
                "token_contribution": 1200
            }
        ],
        "pruned_content": [
            {
                "content_type": "SpatialEntities",
                "entity_name": "Unrelated Location",
                "reason": "Not part of causal path analysis",
                "tokens_saved": 500
            }
        ],
        "optimization_strategy": "CausalPathFocus",
        "confidence": 0.92
    }"#;

    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let service = ContextOptimizationService::new(Arc::new(mock_client));

    let context = create_test_assembled_context();
    
    let optimization = service.optimize_context(&context, 3000, "What caused Luke to make his decision?").await.unwrap();
    
    assert!(matches!(optimization.optimization_strategy, OptimizationStrategy::CausalPathFocus));
    assert_eq!(optimization.total_estimated_tokens, 2800);
    assert!(optimization.pruned_content.iter().any(|p| p.reason.contains("Not part of causal path")));
}

#[tokio::test]
async fn test_token_budget_constraints() {
    let response_json = r#"{
        "total_estimated_tokens": 1500,
        "optimized_entities": [
            {
                "entity_id": "ent-1",
                "name": "Luke",
                "priority_score": 1.0,
                "inclusion_reason": "Essential entity within budget constraints",
                "token_contribution": 800
            }
        ],
        "pruned_content": [
            {
                "content_type": "EntityEvents",
                "entity_name": "Secondary Character",
                "reason": "Exceeds token budget limit",
                "tokens_saved": 700
            },
            {
                "content_type": "SpatialEntities",
                "entity_name": "Multiple Locations",
                "reason": "Budget constraint optimization",
                "tokens_saved": 600
            }
        ],
        "optimization_strategy": "TokenBudgetConstraint",
        "confidence": 0.75
    }"#;

    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let service = ContextOptimizationService::new(Arc::new(mock_client));

    let context = create_test_assembled_context();
    
    // Test with strict budget constraint
    let optimization = service.optimize_context(&context, 1500, "Tell me about Luke").await.unwrap();
    
    assert!(matches!(optimization.optimization_strategy, OptimizationStrategy::TokenBudgetConstraint));
    assert!(optimization.total_estimated_tokens <= 1500);
    assert!(optimization.pruned_content.len() >= 2);
    assert!(optimization.pruned_content.iter().any(|p| p.reason.contains("budget")));
}

#[tokio::test]
async fn test_optimization_with_different_query_strategies() {
    let response_json = r#"{
        "total_estimated_tokens": 3200,
        "optimized_entities": [
            {
                "entity_id": "ent-1",
                "name": "Luke",
                "priority_score": 0.9,
                "inclusion_reason": "Spatial analysis focus",
                "token_contribution": 1000
            }
        ],
        "pruned_content": [],
        "optimization_strategy": "SpatialContextPrioritization",
        "confidence": 0.8
    }"#;

    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let service = ContextOptimizationService::new(Arc::new(mock_client));

    // Test with SpatialContextMapping strategy
    let mut context = create_test_assembled_context();
    context.strategy_used = QueryStrategy::SpatialContextMapping;
    
    let optimization = service.optimize_context(&context, 4000, "Who is in the cantina?").await.unwrap();
    
    assert!(matches!(optimization.optimization_strategy, OptimizationStrategy::SpatialContextPrioritization));
    assert_eq!(optimization.optimized_entities[0].inclusion_reason, "Spatial analysis focus");
}

#[tokio::test]
async fn test_low_confidence_optimization() {
    let response_json = r#"{
        "total_estimated_tokens": 3800,
        "optimized_entities": [
            {
                "entity_id": "ent-1",
                "name": "Luke",
                "priority_score": 0.6,
                "inclusion_reason": "Conservative inclusion due to uncertainty",
                "token_contribution": 1200
            },
            {
                "entity_id": "ent-2",
                "name": "Vader",
                "priority_score": 0.5,
                "inclusion_reason": "Included due to low confidence threshold",
                "token_contribution": 800
            }
        ],
        "pruned_content": [
            {
                "content_type": "EntityEvents",
                "entity_name": "Minor Character",
                "reason": "Low confidence in relevance",
                "tokens_saved": 300
            }
        ],
        "optimization_strategy": "ConservativePruning",
        "confidence": 0.4
    }"#;

    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let service = ContextOptimizationService::new(Arc::new(mock_client));

    let context = create_test_assembled_context();
    
    let optimization = service.optimize_context(&context, 4000, "Complex ambiguous query").await.unwrap();
    
    assert!(optimization.confidence < 0.5);
    assert!(matches!(optimization.optimization_strategy, OptimizationStrategy::ConservativePruning));
    // With low confidence, should include more entities to be safe
    assert!(optimization.optimized_entities.len() >= 2);
}

#[tokio::test]
async fn test_optimization_result_structure() {
    let response_json = r#"{
        "total_estimated_tokens": 2500,
        "optimized_entities": [
            {
                "entity_id": "ent-1",
                "name": "Luke",
                "priority_score": 0.95,
                "inclusion_reason": "Primary entity",
                "token_contribution": 800
            }
        ],
        "pruned_content": [
            {
                "content_type": "EntityEvents",
                "entity_name": "Background",
                "reason": "Low relevance",
                "tokens_saved": 400
            }
        ],
        "optimization_strategy": "EntityPrioritization",
        "confidence": 0.85
    }"#;

    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let service = ContextOptimizationService::new(Arc::new(mock_client));

    let context = create_test_assembled_context();
    
    let optimization = service.optimize_context(&context, 3000, "Test query").await.unwrap();
    
    // Verify structure completeness
    assert!(optimization.total_estimated_tokens > 0);
    assert!(!optimization.optimized_entities.is_empty());
    assert!(!optimization.optimized_entities[0].entity_id.is_empty());
    assert!(!optimization.optimized_entities[0].name.is_empty());
    assert!(optimization.optimized_entities[0].priority_score >= 0.0);
    assert!(optimization.optimized_entities[0].priority_score <= 1.0);
    assert!(!optimization.optimized_entities[0].inclusion_reason.is_empty());
    assert!(optimization.optimized_entities[0].token_contribution > 0);
    
    if !optimization.pruned_content.is_empty() {
        assert!(!optimization.pruned_content[0].content_type.is_empty());
        assert!(!optimization.pruned_content[0].reason.is_empty());
        assert!(optimization.pruned_content[0].tokens_saved > 0);
    }
    
    assert!(optimization.confidence >= 0.0);
    assert!(optimization.confidence <= 1.0);
}

// Helper function to create test context
fn create_test_assembled_context() -> AssembledContext {
    let results = vec![
        QueryExecutionResult::EntityEvents(EntityEventsResult {
            entities: {
                let mut map = HashMap::new();
                map.insert("Luke".to_string(), Vec::new());
                map.insert("Vader".to_string(), Vec::new());
                map
            },
            time_scope: "Recent".to_string(),
            total_events: 5,
            tokens_used: 1200,
        }),
        QueryExecutionResult::SpatialEntities(SpatialEntitiesResult {
            location_name: "cantina".to_string(),
            entities: Vec::new(),
            include_contained: true,
            tokens_used: 800,
        }),
        QueryExecutionResult::CausalChain(CausalChainResult {
            from_entity: "Luke".to_string(),
            causality_type: "departure".to_string(),
            causal_chain: Vec::new(),
            max_depth: 3,
            tokens_used: 1000,
        }),
    ];
    
    AssembledContext {
        strategy_used: QueryStrategy::CausalChainTraversal,
        results,
        total_tokens_used: 3000,
        execution_time_ms: 200,
        success_rate: 1.0,
    }
}