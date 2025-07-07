use scribe_backend::services::context_assembly_engine::*;
use scribe_backend::services::query_strategy_planner::*;
use std::collections::HashMap;
use uuid::Uuid;

#[tokio::test]
async fn test_entity_events_query_parameter_parsing() {
    // Test the parameter parsing logic of queries without complex dependencies
    let mut parameters = HashMap::new();
    parameters.insert("entity_names".to_string(), serde_json::json!(["Luke"]));
    parameters.insert("time_scope".to_string(), serde_json::json!("Recent"));
    parameters.insert("max_events".to_string(), serde_json::json!(10));

    let query = PlannedQuery {
        query_type: PlannedQueryType::EntityEvents,
        priority: 1.0,
        parameters,
        estimated_tokens: Some(1000),
        dependencies: vec![],
    };

    // Verify parameter parsing by checking the PlannedQuery structure
    assert_eq!(query.priority, 1.0);
    assert_eq!(query.estimated_tokens, Some(1000));
    assert!(query.dependencies.is_empty());
    
    // Test parameter extraction
    let entity_names = query.parameters.get("entity_names")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap();
    
    assert_eq!(entity_names, vec!["Luke"]);
    
    let time_scope = query.parameters.get("time_scope")
        .and_then(|v| v.as_str())
        .unwrap();
    
    assert_eq!(time_scope, "Recent");
    
    let max_events = query.parameters.get("max_events")
        .and_then(|v| v.as_u64())
        .unwrap() as usize;
    
    assert_eq!(max_events, 10);
}

#[tokio::test]
async fn test_spatial_entities_query_parameter_parsing() {
    let mut parameters = HashMap::new();
    parameters.insert("location_name".to_string(), serde_json::json!("cantina"));
    parameters.insert("include_contained".to_string(), serde_json::json!(true));

    let query = PlannedQuery {
        query_type: PlannedQueryType::SpatialEntities,
        priority: 1.0,
        parameters,
        estimated_tokens: Some(800),
        dependencies: vec![],
    };

    let location_name = query.parameters.get("location_name")
        .and_then(|v| v.as_str())
        .unwrap();
    
    assert_eq!(location_name, "cantina");
    
    let include_contained = query.parameters.get("include_contained")
        .and_then(|v| v.as_bool())
        .unwrap();
    
    assert!(include_contained);
}

#[tokio::test]
async fn test_causal_chain_query_parameter_parsing() {
    let mut parameters = HashMap::new();
    parameters.insert("from_entity".to_string(), serde_json::json!("Luke"));
    parameters.insert("causality_type".to_string(), serde_json::json!("departure"));
    parameters.insert("max_depth".to_string(), serde_json::json!(3));

    let query = PlannedQuery {
        query_type: PlannedQueryType::CausalChain,
        priority: 0.9,
        parameters,
        estimated_tokens: Some(1500),
        dependencies: vec![],
    };

    let from_entity = query.parameters.get("from_entity")
        .and_then(|v| v.as_str())
        .unwrap();
    
    assert_eq!(from_entity, "Luke");
    
    let causality_type = query.parameters.get("causality_type")
        .and_then(|v| v.as_str())
        .unwrap();
    
    assert_eq!(causality_type, "departure");
    
    let max_depth = query.parameters.get("max_depth")
        .and_then(|v| v.as_u64())
        .unwrap() as u32;
    
    assert_eq!(max_depth, 3);
}

#[tokio::test]
async fn test_query_execution_plan_structure() {
    // Test the creation and structure of execution plans
    let mut entity_events_params = HashMap::new();
    entity_events_params.insert("entity_names".to_string(), serde_json::json!(["Luke"]));
    entity_events_params.insert("max_events".to_string(), serde_json::json!(10));

    let mut causal_chain_params = HashMap::new();
    causal_chain_params.insert("from_entity".to_string(), serde_json::json!("Luke"));
    causal_chain_params.insert("max_depth".to_string(), serde_json::json!(3));

    let plan = QueryExecutionPlan {
        primary_strategy: QueryStrategy::CausalChainTraversal,
        queries: vec![
            PlannedQuery {
                query_type: PlannedQueryType::EntityEvents,
                priority: 1.0,
                parameters: entity_events_params,
                estimated_tokens: Some(1000),
                dependencies: vec![],
            },
            PlannedQuery {
                query_type: PlannedQueryType::CausalChain,
                priority: 0.9,
                parameters: causal_chain_params,
                estimated_tokens: Some(1500),
                dependencies: vec!["EntityEvents".to_string()],
            },
        ],
        context_budget: 8000,
        execution_order: vec!["EntityEvents".to_string(), "CausalChain".to_string()],
        reasoning: "Test causal analysis execution".to_string(),
    };

    assert_eq!(plan.primary_strategy, QueryStrategy::CausalChainTraversal);
    assert_eq!(plan.queries.len(), 2);
    assert_eq!(plan.context_budget, 8000);
    assert_eq!(plan.execution_order.len(), 2);
    assert!(plan.execution_order.contains(&"EntityEvents".to_string()));
    assert!(plan.execution_order.contains(&"CausalChain".to_string()));
    
    // Verify first query has no dependencies
    assert!(plan.queries[0].dependencies.is_empty());
    
    // Verify second query has EntityEvents dependency
    assert_eq!(plan.queries[1].dependencies, vec!["EntityEvents".to_string()]);
}

#[tokio::test]
async fn test_query_execution_result_token_tracking() {
    // Test token tracking in results
    let events_result = QueryExecutionResult::EntityEvents(EntityEventsResult {
        entities: HashMap::new(),
        time_scope: "Recent".to_string(),
        total_events: 0,
        tokens_used: 1000,
    });
    
    // Verify token tracking
    let tokens = match events_result {
        QueryExecutionResult::EntityEvents(ref result) => result.tokens_used,
        _ => panic!("Wrong result type"),
    };
    
    assert_eq!(tokens, 1000);
    
    let spatial_result = QueryExecutionResult::SpatialEntities(SpatialEntitiesResult {
        location_name: "cantina".to_string(),
        entities: vec![],
        include_contained: true,
        tokens_used: 800,
    });
    
    let tokens = match spatial_result {
        QueryExecutionResult::SpatialEntities(ref result) => result.tokens_used,
        _ => panic!("Wrong result type"),
    };
    
    assert_eq!(tokens, 800);
}

#[tokio::test]
async fn test_assembled_context_structure() {
    // Test the structure of assembled context results
    let results = vec![
        QueryExecutionResult::EntityEvents(EntityEventsResult {
            entities: HashMap::new(),
            time_scope: "Recent".to_string(),
            total_events: 0,
            tokens_used: 1000,
        }),
        QueryExecutionResult::CausalChain(CausalChainResult {
            from_entity: "Luke".to_string(),
            causality_type: "departure".to_string(),
            causal_chain: vec![],
            max_depth: 3,
            tokens_used: 1500,
        }),
    ];
    
    let context = AssembledContext {
        strategy_used: QueryStrategy::CausalChainTraversal,
        results,
        total_tokens_used: 2500,
        execution_time_ms: 150,
        success_rate: 1.0,
    };
    
    assert_eq!(context.strategy_used, QueryStrategy::CausalChainTraversal);
    assert_eq!(context.results.len(), 2);
    assert_eq!(context.total_tokens_used, 2500);
    assert_eq!(context.execution_time_ms, 150);
    assert_eq!(context.success_rate, 1.0);
    
    // Verify result types
    assert!(matches!(context.results[0], QueryExecutionResult::EntityEvents(_)));
    assert!(matches!(context.results[1], QueryExecutionResult::CausalChain(_)));
}

#[tokio::test]
async fn test_query_strategy_enum_variants() {
    // Test all query strategy variants exist
    let strategies = vec![
        QueryStrategy::CausalChainTraversal,
        QueryStrategy::SpatialContextMapping,
        QueryStrategy::RelationshipNetworkTraversal,
        QueryStrategy::TemporalStateReconstruction,
        QueryStrategy::CausalProjection,
        QueryStrategy::NarrativeContextAssembly,
        QueryStrategy::StateSnapshot,
        QueryStrategy::ComparativeAnalysis,
    ];
    
    assert_eq!(strategies.len(), 8);
    
    // Test that each strategy can be cloned and compared
    for strategy in strategies {
        let cloned = strategy.clone();
        assert_eq!(strategy, cloned);
    }
}

#[tokio::test] 
async fn test_planned_query_type_variants() {
    // Test all planned query type variants exist
    let query_types = vec![
        PlannedQueryType::EntityEvents,
        PlannedQueryType::EntityCurrentState,
        PlannedQueryType::EntityStates,
        PlannedQueryType::ActiveEntities,
        PlannedQueryType::EntityRelationships,
        PlannedQueryType::SharedEvents,
        PlannedQueryType::CausalChain,
        PlannedQueryType::CausalFactors,
        PlannedQueryType::SpatialEntities,
        PlannedQueryType::TimelineEvents,
        PlannedQueryType::StateTransitions,
        PlannedQueryType::RecentEvents,
        PlannedQueryType::HistoricalParallels,
        PlannedQueryType::NarrativeThreads,
    ];
    
    assert_eq!(query_types.len(), 14);
    
    // Test that each query type can be compared
    for query_type in query_types {
        let cloned = query_type.clone();
        assert_eq!(query_type, cloned);
    }
}