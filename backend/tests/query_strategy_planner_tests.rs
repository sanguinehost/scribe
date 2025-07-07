use scribe_backend::services::query_strategy_planner::*;
use scribe_backend::services::intent_detection_service::*;
use scribe_backend::test_helpers::MockAiClient;
use scribe_backend::errors::AppError;
use std::sync::Arc;
use chrono::Duration;

#[tokio::test]
async fn test_causal_analysis_strategy() {
    let response_json = r#"{
        "primary_strategy": "CausalChainTraversal",
        "queries": [
            {
                "query_type": "EntityEvents",
                "priority": 1.0,
                "parameters": {
                    "entity_names": ["Luke"],
                    "time_scope": "Recent",
                    "max_events": 20
                }
            },
            {
                "query_type": "CausalChain", 
                "priority": 0.9,
                "parameters": {
                    "from_entity": "Luke",
                    "causality_type": "departure",
                    "max_depth": 3
                }
            }
        ],
        "context_budget": 8000,
        "execution_order": ["EntityEvents", "CausalChain"],
        "reasoning": "For causal analysis about Luke leaving, we need his recent events and causal chain"
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client));
    
    let intent = QueryIntent {
        intent_type: IntentType::CausalAnalysis,
        focus_entities: vec![EntityFocus {
            name: "Luke".to_string(),
            entity_type: None,
            priority: 1.0,
            required: true,
        }],
        time_scope: TimeScope::Recent(Duration::hours(24)),
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Causal,
        context_priorities: vec![ContextPriority::CausalChains, ContextPriority::Entities],
        confidence: 0.9,
    };
    
    let strategy = planner.plan_query_strategy(&intent, 10000).await.unwrap();
    
    assert!(matches!(strategy.primary_strategy, QueryStrategy::CausalChainTraversal));
    assert_eq!(strategy.queries.len(), 2);
    assert_eq!(strategy.context_budget, 8000);
    assert!(strategy.queries.iter().any(|q| matches!(q.query_type, PlannedQueryType::EntityEvents)));
    assert!(strategy.queries.iter().any(|q| matches!(q.query_type, PlannedQueryType::CausalChain)));
}

#[tokio::test]
async fn test_spatial_analysis_strategy() {
    let response_json = r#"{
        "primary_strategy": "SpatialContextMapping",
        "queries": [
            {
                "query_type": "SpatialEntities",
                "priority": 1.0,
                "parameters": {
                    "location_name": "cantina",
                    "include_contained": true,
                    "include_adjacent": false
                }
            },
            {
                "query_type": "EntityStates",
                "priority": 0.8,
                "parameters": {
                    "scope": "spatial_results",
                    "state_types": ["position", "activity"]
                }
            }
        ],
        "context_budget": 6000,
        "execution_order": ["SpatialEntities", "EntityStates"],
        "reasoning": "For spatial analysis, find entities in location then get their current states"
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client));
    
    let intent = QueryIntent {
        intent_type: IntentType::SpatialAnalysis,
        focus_entities: vec![],
        time_scope: TimeScope::Current,
        spatial_scope: Some(SpatialScope {
            location_name: Some("cantina".to_string()),
            radius: None,
            include_contained: true,
        }),
        reasoning_depth: ReasoningDepth::Surface,
        context_priorities: vec![ContextPriority::SpatialContext, ContextPriority::Entities],
        confidence: 0.85,
    };
    
    let strategy = planner.plan_query_strategy(&intent, 8000).await.unwrap();
    
    assert!(matches!(strategy.primary_strategy, QueryStrategy::SpatialContextMapping));
    assert_eq!(strategy.queries.len(), 2);
    assert_eq!(strategy.context_budget, 6000);
}

#[tokio::test]
async fn test_relationship_query_strategy() {
    let response_json = r#"{
        "primary_strategy": "RelationshipNetworkTraversal",
        "queries": [
            {
                "query_type": "EntityRelationships",
                "priority": 1.0,
                "parameters": {
                    "entity_names": ["Vader", "Obi-Wan"],
                    "relationship_types": ["trust", "hostility", "history"],
                    "max_depth": 2
                }
            },
            {
                "query_type": "SharedEvents",
                "priority": 0.9,
                "parameters": {
                    "entities": ["Vader", "Obi-Wan"],
                    "event_types": ["interaction", "conflict"],
                    "time_scope": "AllTime"
                }
            }
        ],
        "context_budget": 9000,
        "execution_order": ["EntityRelationships", "SharedEvents"],
        "reasoning": "For relationship analysis, get direct relationships then shared history"
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client));
    
    let intent = QueryIntent {
        intent_type: IntentType::RelationshipQuery,
        focus_entities: vec![
            EntityFocus {
                name: "Vader".to_string(),
                entity_type: None,
                priority: 1.0,
                required: true,
            },
            EntityFocus {
                name: "Obi-Wan".to_string(),
                entity_type: None,
                priority: 1.0,
                required: true,
            },
        ],
        time_scope: TimeScope::AllTime,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Analytical,
        context_priorities: vec![ContextPriority::Relationships, ContextPriority::Entities],
        confidence: 0.92,
    };
    
    let strategy = planner.plan_query_strategy(&intent, 10000).await.unwrap();
    
    assert!(matches!(strategy.primary_strategy, QueryStrategy::RelationshipNetworkTraversal));
    assert_eq!(strategy.queries.len(), 2);
    assert!(strategy.queries.iter().any(|q| matches!(q.query_type, PlannedQueryType::EntityRelationships)));
    assert!(strategy.queries.iter().any(|q| matches!(q.query_type, PlannedQueryType::SharedEvents)));
}

#[tokio::test]
async fn test_temporal_analysis_strategy() {
    let response_json = r#"{
        "primary_strategy": "TemporalStateReconstruction",
        "queries": [
            {
                "query_type": "TimelineEvents",
                "priority": 1.0,
                "parameters": {
                    "entity_names": ["Empire"],
                    "start_time": "2023-01-01T00:00:00Z",
                    "end_time": "2023-12-31T23:59:59Z",
                    "event_categories": ["political", "military", "economic"]
                }
            },
            {
                "query_type": "StateTransitions",
                "priority": 0.8,
                "parameters": {
                    "entity": "Empire",
                    "transition_types": ["power", "territory", "influence"],
                    "time_window": "2023"
                }
            }
        ],
        "context_budget": 7500,
        "execution_order": ["TimelineEvents", "StateTransitions"],
        "reasoning": "For temporal analysis, get chronological events then state changes"
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client));
    
    let intent = QueryIntent {
        intent_type: IntentType::TemporalAnalysis,
        focus_entities: vec![EntityFocus {
            name: "Empire".to_string(),
            entity_type: None,
            priority: 0.8,
            required: false,
        }],
        time_scope: TimeScope::Range(
            chrono::DateTime::parse_from_rfc3339("2023-01-01T00:00:00Z").unwrap().with_timezone(&chrono::Utc),
            chrono::DateTime::parse_from_rfc3339("2023-12-31T23:59:59Z").unwrap().with_timezone(&chrono::Utc),
        ),
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Deep,
        context_priorities: vec![ContextPriority::TemporalState, ContextPriority::RecentEvents],
        confidence: 0.88,
    };
    
    let strategy = planner.plan_query_strategy(&intent, 10000).await.unwrap();
    
    assert!(matches!(strategy.primary_strategy, QueryStrategy::TemporalStateReconstruction));
    assert_eq!(strategy.context_budget, 7500);
    assert!(strategy.queries.iter().any(|q| matches!(q.query_type, PlannedQueryType::TimelineEvents)));
}

#[tokio::test]
async fn test_predictive_query_strategy() {
    let response_json = r#"{
        "primary_strategy": "CausalProjection",
        "queries": [
            {
                "query_type": "EntityCurrentState",
                "priority": 1.0,
                "parameters": {
                    "entity_names": ["Rebellion"],
                    "state_aspects": ["strength", "resources", "morale", "position"]
                }
            },
            {
                "query_type": "CausalFactors",
                "priority": 0.9,
                "parameters": {
                    "scenario": "attack_death_star",
                    "entity": "Rebellion",
                    "factor_types": ["military", "strategic", "environmental"]
                }
            },
            {
                "query_type": "HistoricalParallels",
                "priority": 0.7,
                "parameters": {
                    "scenario_type": "rebel_attack",
                    "target_type": "superweapon",
                    "outcome_focus": true
                }
            }
        ],
        "context_budget": 9500,
        "execution_order": ["EntityCurrentState", "CausalFactors", "HistoricalParallels"],
        "reasoning": "For prediction, need current state, causal factors, and historical precedents"
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client));
    
    let intent = QueryIntent {
        intent_type: IntentType::PredictiveQuery,
        focus_entities: vec![EntityFocus {
            name: "Rebellion".to_string(),
            entity_type: None,
            priority: 0.9,
            required: true,
        }],
        time_scope: TimeScope::Current,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Deep,
        context_priorities: vec![ContextPriority::CausalChains, ContextPriority::Relationships],
        confidence: 0.75,
    };
    
    let strategy = planner.plan_query_strategy(&intent, 10000).await.unwrap();
    
    assert!(matches!(strategy.primary_strategy, QueryStrategy::CausalProjection));
    assert_eq!(strategy.queries.len(), 3);
    assert!(strategy.queries.iter().any(|q| matches!(q.query_type, PlannedQueryType::EntityCurrentState)));
    assert!(strategy.queries.iter().any(|q| matches!(q.query_type, PlannedQueryType::CausalFactors)));
}

#[tokio::test]
async fn test_narrative_generation_strategy() {
    let response_json = r#"{
        "primary_strategy": "NarrativeContextAssembly",
        "queries": [
            {
                "query_type": "RecentEvents",
                "priority": 1.0,
                "parameters": {
                    "time_scope": "last_24_hours",
                    "event_types": ["action", "dialogue", "state_change"],
                    "max_events": 15
                }
            },
            {
                "query_type": "ActiveEntities",
                "priority": 0.9,
                "parameters": {
                    "activity_threshold": 0.1,
                    "include_positions": true,
                    "include_states": true
                }
            },
            {
                "query_type": "NarrativeThreads",
                "priority": 0.8,
                "parameters": {
                    "thread_types": ["conflict", "relationship", "mystery"],
                    "status": "active",
                    "max_threads": 5
                }
            }
        ],
        "context_budget": 8500,
        "execution_order": ["RecentEvents", "ActiveEntities", "NarrativeThreads"],
        "reasoning": "For narrative generation, need recent events, active entities, and ongoing threads"
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client));
    
    let intent = QueryIntent {
        intent_type: IntentType::NarrativeGeneration,
        focus_entities: vec![],
        time_scope: TimeScope::Current,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Analytical,
        context_priorities: vec![ContextPriority::Entities, ContextPriority::RecentEvents],
        confidence: 0.95,
    };
    
    let strategy = planner.plan_query_strategy(&intent, 10000).await.unwrap();
    
    assert!(matches!(strategy.primary_strategy, QueryStrategy::NarrativeContextAssembly));
    assert_eq!(strategy.queries.len(), 3);
    assert!(strategy.queries.iter().any(|q| matches!(q.query_type, PlannedQueryType::RecentEvents)));
    assert!(strategy.queries.iter().any(|q| matches!(q.query_type, PlannedQueryType::ActiveEntities)));
}

#[tokio::test]
async fn test_token_budget_constraint() {
    let response_json = r#"{
        "primary_strategy": "CausalChainTraversal",
        "queries": [
            {
                "query_type": "EntityEvents",
                "priority": 1.0,
                "parameters": {
                    "entity_names": ["Luke"],
                    "time_scope": "Recent",
                    "max_events": 5
                }
            }
        ],
        "context_budget": 2000,
        "execution_order": ["EntityEvents"],
        "reasoning": "Limited token budget requires minimal query set"
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client));
    
    let intent = QueryIntent {
        intent_type: IntentType::CausalAnalysis,
        focus_entities: vec![EntityFocus {
            name: "Luke".to_string(),
            entity_type: None,
            priority: 1.0,
            required: true,
        }],
        time_scope: TimeScope::Recent(Duration::hours(24)),
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Causal,
        context_priorities: vec![ContextPriority::CausalChains],
        confidence: 0.9,
    };
    
    // Small token budget should result in fewer queries
    let strategy = planner.plan_query_strategy(&intent, 3000).await.unwrap();
    
    assert_eq!(strategy.context_budget, 2000);
    assert_eq!(strategy.queries.len(), 1);
}

#[tokio::test]
async fn test_invalid_json_response() {
    let mock_client = MockAiClient::new_with_response("Invalid JSON response".to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client));
    
    let intent = QueryIntent {
        intent_type: IntentType::StateInquiry,
        focus_entities: vec![],
        time_scope: TimeScope::Current,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Surface,
        context_priorities: vec![ContextPriority::Entities],
        confidence: 0.8,
    };
    
    let result = planner.plan_query_strategy(&intent, 5000).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Failed to parse strategy response"));
}