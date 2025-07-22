use scribe_backend::services::query_strategy_planner::*;
use scribe_backend::services::intent_detection_service::*;
use scribe_backend::test_helpers::MockAiClient;
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
                },
                "estimated_tokens": 300,
                "dependencies": [],
                "query_reasoning": "Need Luke's recent events to understand the context of his departure",
                "expected_yield": 0.9
            },
            {
                "query_type": "CausalChain", 
                "priority": 0.9,
                "parameters": {
                    "from_entity": "Luke",
                    "causality_type": "departure",
                    "max_depth": 3
                },
                "estimated_tokens": 400,
                "dependencies": ["EntityEvents"],
                "query_reasoning": "Trace the causal chain that led to Luke's departure",
                "expected_yield": 0.85
            }
        ],
        "context_budget": 8000,
        "execution_order": ["EntityEvents", "CausalChain"],
        "reasoning": "For causal analysis about Luke leaving, we need his recent events and causal chain. Starting with events provides context for the causal analysis.",
        "optimization_hints": [
            "Focus on events with high causal significance",
            "Prioritize direct causal relationships over indirect ones"
        ],
        "plan_confidence": 0.92,
        "alternative_strategies": [
            {
                "strategy": "TemporalStateReconstruction",
                "reasoning": "Could rebuild the timeline leading to departure",
                "trade_offs": "More comprehensive but higher token cost"
            }
        ]
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client), "test-model".to_string());
    
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
    
    // Test new Flash features
    assert_eq!(strategy.plan_confidence, 0.92);
    assert_eq!(strategy.optimization_hints.len(), 2);
    assert_eq!(strategy.alternative_strategies.len(), 1);
    assert!(strategy.queries[0].query_reasoning.is_some());
    assert!(strategy.queries[0].expected_yield.is_some());
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
                },
                "query_reasoning": "Map all entities present in the cantina location",
                "expected_yield": 0.95
            },
            {
                "query_type": "EntityStates",
                "priority": 0.8,
                "parameters": {
                    "scope": "spatial_results",
                    "state_types": ["position", "activity"]
                },
                "dependencies": ["SpatialEntities"],
                "query_reasoning": "Get current states of entities found in the spatial query",
                "expected_yield": 0.8
            }
        ],
        "context_budget": 6000,
        "execution_order": ["SpatialEntities", "EntityStates"],
        "reasoning": "For spatial analysis, find entities in location then get their current states to understand the scene dynamics",
        "optimization_hints": [
            "Cache spatial results for follow-up queries",
            "Focus on active entities over static ones"
        ],
        "plan_confidence": 0.88,
        "alternative_strategies": []
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client), "test-model".to_string());
    
    let intent = QueryIntent {
        intent_type: IntentType::SpatialAnalysis,
        focus_entities: vec![],
        time_scope: TimeScope::Current,
        spatial_scope: Some(SpatialScope {
            location_name: Some("cantina".to_string()),
            radius: None,
            include_contained: true,
        }),
        reasoning_depth: ReasoningDepth::Analytical,
        context_priorities: vec![ContextPriority::SpatialContext, ContextPriority::Entities],
        confidence: 0.85,
    };
    
    let strategy = planner.plan_query_strategy(&intent, 8000).await.unwrap();
    
    assert!(matches!(strategy.primary_strategy, QueryStrategy::SpatialContextMapping));
    assert_eq!(strategy.queries.len(), 2);
    assert!(strategy.queries[0].parameters.get("location_name").is_some());
    assert!(strategy.queries[1].dependencies.contains(&"SpatialEntities".to_string()));
}

#[tokio::test]
async fn test_narrative_generation_strategy() {
    let response_json = r#"{
        "primary_strategy": "NarrativeContextAssembly",
        "queries": [
            {
                "query_type": "ActiveEntities",
                "priority": 1.0,
                "parameters": {
                    "activity_threshold": 0.5,
                    "include_states": true
                },
                "query_reasoning": "Identify all active participants in the current narrative",
                "expected_yield": 0.9
            },
            {
                "query_type": "RecentEvents",
                "priority": 0.95,
                "parameters": {
                    "time_window": "1h",
                    "event_categories": ["action", "dialogue", "movement"]
                },
                "query_reasoning": "Gather immediate narrative context",
                "expected_yield": 0.95
            },
            {
                "query_type": "EntityRelationships",
                "priority": 0.85,
                "parameters": {
                    "entity_names": [],
                    "max_depth": 2
                },
                "dependencies": ["ActiveEntities"],
                "query_reasoning": "Understand social dynamics between active characters",
                "expected_yield": 0.8
            },
            {
                "query_type": "NarrativeThreads",
                "priority": 0.8,
                "parameters": {
                    "thread_count": 3,
                    "include_potential": true
                },
                "dependencies": ["RecentEvents", "EntityRelationships"],
                "query_reasoning": "Identify ongoing narrative threads to continue",
                "expected_yield": 0.85
            }
        ],
        "context_budget": 12000,
        "execution_order": ["ActiveEntities", "RecentEvents", "EntityRelationships", "NarrativeThreads"],
        "reasoning": "For narrative generation, we need a comprehensive view of active elements, recent events, relationships, and ongoing threads to create coherent story continuation",
        "optimization_hints": [
            "Prioritize emotionally charged events",
            "Focus on unresolved narrative tensions",
            "Consider character arcs when selecting context"
        ],
        "plan_confidence": 0.91,
        "alternative_strategies": [
            {
                "strategy": "EmergentPatternDiscovery",
                "reasoning": "Could discover hidden narrative patterns",
                "trade_offs": "More creative but less predictable results"
            },
            {
                "strategy": "AdaptiveNarrativeStrategy",
                "reasoning": "AI-driven flexible approach based on context",
                "trade_offs": "Highly adaptive but requires more AI processing"
            }
        ]
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client), "test-model".to_string());
    
    let intent = QueryIntent {
        intent_type: IntentType::NarrativeGeneration,
        focus_entities: vec![],
        time_scope: TimeScope::Recent(Duration::hours(1)),
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Deep,
        context_priorities: vec![
            ContextPriority::RecentEvents,
            ContextPriority::Relationships,
            ContextPriority::Entities,
        ],
        confidence: 0.88,
    };
    
    let strategy = planner.plan_query_strategy(&intent, 15000).await.unwrap();
    
    assert!(matches!(strategy.primary_strategy, QueryStrategy::NarrativeContextAssembly));
    assert_eq!(strategy.queries.len(), 4);
    assert_eq!(strategy.execution_order.len(), 4);
    assert!(strategy.queries.iter().any(|q| matches!(q.query_type, PlannedQueryType::NarrativeThreads)));
    assert_eq!(strategy.alternative_strategies.len(), 2);
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
                    "entity_names": ["Alice", "Bob"],
                    "relationship_types": ["trust", "loyalty", "conflict"],
                    "max_depth": 3
                },
                "query_reasoning": "Map the relationship network around the focus entities",
                "expected_yield": 0.95
            },
            {
                "query_type": "SharedEvents",
                "priority": 0.9,
                "parameters": {
                    "entity_names": ["Alice", "Bob"],
                    "time_scope": "30d",
                    "event_significance": 0.5
                },
                "query_reasoning": "Find shared experiences that shaped their relationship",
                "expected_yield": 0.85
            }
        ],
        "context_budget": 7000,
        "execution_order": ["EntityRelationships", "SharedEvents"],
        "reasoning": "For understanding relationships, we need both the relationship structure and the shared history that created it",
        "optimization_hints": [
            "Weight relationships by recency and strength",
            "Focus on trust-related dynamics per the query"
        ],
        "plan_confidence": 0.89,
        "alternative_strategies": []
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client), "test-model".to_string());
    
    let intent = QueryIntent {
        intent_type: IntentType::RelationshipQuery,
        focus_entities: vec![
            EntityFocus {
                name: "Alice".to_string(),
                entity_type: Some("CHARACTER".to_string()),
                priority: 1.0,
                required: true,
            },
            EntityFocus {
                name: "Bob".to_string(),
                entity_type: Some("CHARACTER".to_string()),
                priority: 1.0,
                required: true,
            },
        ],
        time_scope: TimeScope::Recent(Duration::days(30)),
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Analytical,
        context_priorities: vec![ContextPriority::Relationships, ContextPriority::RecentEvents],
        confidence: 0.87,
    };
    
    let strategy = planner.plan_query_strategy(&intent, 8000).await.unwrap();
    
    assert!(matches!(strategy.primary_strategy, QueryStrategy::RelationshipNetworkTraversal));
    assert!(strategy.queries.iter().any(|q| matches!(q.query_type, PlannedQueryType::EntityRelationships)));
    assert!(strategy.queries.iter().any(|q| matches!(q.query_type, PlannedQueryType::SharedEvents)));
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
                    "entity_names": ["Empire"],
                    "include_components": ["military", "political", "economic"]
                },
                "query_reasoning": "Understand current state as baseline for prediction",
                "expected_yield": 0.9
            },
            {
                "query_type": "CausalFactors",
                "priority": 0.95,
                "parameters": {
                    "entity_names": ["Empire"],
                    "factor_types": ["internal", "external"],
                    "time_window": "7d"
                },
                "query_reasoning": "Identify forces that could drive future changes",
                "expected_yield": 0.88
            },
            {
                "query_type": "HistoricalParallels",
                "priority": 0.85,
                "parameters": {
                    "current_situation": "empire_expansion",
                    "similarity_threshold": 0.7,
                    "max_results": 5
                },
                "dependencies": ["EntityCurrentState", "CausalFactors"],
                "query_reasoning": "Find similar historical patterns to predict outcomes",
                "expected_yield": 0.82
            }
        ],
        "context_budget": 9000,
        "execution_order": ["EntityCurrentState", "CausalFactors", "HistoricalParallels"],
        "reasoning": "Predictive analysis requires current state, driving factors, and historical patterns to project future possibilities",
        "optimization_hints": [
            "Weight recent causal factors more heavily",
            "Look for accelerating trends in the data"
        ],
        "plan_confidence": 0.86,
        "alternative_strategies": [
            {
                "strategy": "TemporalStateReconstruction",
                "reasoning": "Could analyze state evolution patterns",
                "trade_offs": "More detailed but computationally intensive"
            }
        ]
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client), "test-model".to_string());
    
    let intent = QueryIntent {
        intent_type: IntentType::PredictiveQuery,
        focus_entities: vec![EntityFocus {
            name: "Empire".to_string(),
            entity_type: Some("FACTION".to_string()),
            priority: 1.0,
            required: true,
        }],
        time_scope: TimeScope::Recent(Duration::days(7)),
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Deep,
        context_priorities: vec![ContextPriority::CausalChains, ContextPriority::TemporalState],
        confidence: 0.82,
    };
    
    let strategy = planner.plan_query_strategy(&intent, 10000).await.unwrap();
    
    assert!(matches!(strategy.primary_strategy, QueryStrategy::CausalProjection));
    assert_eq!(strategy.queries.len(), 3);
    assert!(strategy.queries.iter().any(|q| matches!(q.query_type, PlannedQueryType::HistoricalParallels)));
}

#[tokio::test]
async fn test_adaptive_narrative_strategy() {
    let response_json = r#"{
        "primary_strategy": "AdaptiveNarrativeStrategy",
        "queries": [
            {
                "query_type": "ActiveEntities",
                "priority": 1.0,
                "parameters": {
                    "activity_threshold": 0.3,
                    "narrative_relevance": true
                },
                "query_reasoning": "AI-driven selection of narratively important entities",
                "expected_yield": 0.92
            },
            {
                "query_type": "NarrativeThreads",
                "priority": 0.95,
                "parameters": {
                    "ai_guided": true,
                    "emotional_weight": 0.8
                },
                "query_reasoning": "AI identifies most emotionally resonant narrative threads",
                "expected_yield": 0.9
            },
            {
                "query_type": "EmergentPatterns",
                "priority": 0.85,
                "parameters": {
                    "pattern_types": ["character_arcs", "thematic_cycles", "conflict_escalation"]
                },
                "dependencies": ["ActiveEntities", "NarrativeThreads"],
                "query_reasoning": "Discover hidden narrative patterns for richer storytelling",
                "expected_yield": 0.8
            }
        ],
        "context_budget": 10000,
        "execution_order": ["ActiveEntities", "NarrativeThreads", "EmergentPatterns"],
        "reasoning": "AI-adaptive strategy dynamically adjusts to narrative needs, finding the most compelling story elements through pattern recognition",
        "optimization_hints": [
            "Let AI guide entity selection based on narrative potential",
            "Emphasize emotional and thematic coherence",
            "Adapt query parameters based on initial results"
        ],
        "plan_confidence": 0.93,
        "alternative_strategies": []
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client), "test-model".to_string());
    
    let result = planner.plan_narrative_query_strategy(
        &QueryIntent {
            intent_type: IntentType::NarrativeGeneration,
            focus_entities: vec![],
            time_scope: TimeScope::Recent(Duration::hours(2)),
            spatial_scope: None,
            reasoning_depth: ReasoningDepth::Deep,
            context_priorities: vec![ContextPriority::RecentEvents, ContextPriority::Relationships],
            confidence: 0.9,
        },
        "A tense confrontation is about to unfold in the throne room",
        12000
    ).await.unwrap();
    
    assert!(matches!(result.primary_strategy, QueryStrategy::AdaptiveNarrativeStrategy));
    assert_eq!(result.plan_confidence, 0.93);
    assert_eq!(result.optimization_hints.len(), 3);
}

#[tokio::test]
async fn test_small_token_budget_optimization() {
    let response_json = r#"{
        "primary_strategy": "ContextualRelevanceOptimization",
        "queries": [
            {
                "query_type": "EntityCurrentState",
                "priority": 1.0,
                "parameters": {
                    "entity_names": ["protagonist"],
                    "minimal_mode": true
                },
                "query_reasoning": "Essential protagonist state with minimal tokens",
                "expected_yield": 0.85
            },
            {
                "query_type": "RecentEvents",
                "priority": 0.9,
                "parameters": {
                    "time_window": "30m",
                    "max_events": 5,
                    "high_impact_only": true
                },
                "query_reasoning": "Only the most critical recent events",
                "expected_yield": 0.8
            }
        ],
        "context_budget": 2500,
        "execution_order": ["EntityCurrentState", "RecentEvents"],
        "reasoning": "With severe token constraints, focus only on absolutely essential narrative elements - protagonist state and highest-impact recent events",
        "optimization_hints": [
            "Aggressively prune low-relevance content",
            "Focus on action-driving information only"
        ],
        "plan_confidence": 0.78,
        "alternative_strategies": []
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client), "test-model".to_string());
    
    let intent = QueryIntent {
        intent_type: IntentType::StateInquiry,
        focus_entities: vec![EntityFocus {
            name: "protagonist".to_string(),
            entity_type: None,
            priority: 1.0,
            required: true,
        }],
        time_scope: TimeScope::Recent(Duration::minutes(30)),
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Surface,
        context_priorities: vec![ContextPriority::Entities],
        confidence: 0.8,
    };
    
    let strategy = planner.plan_query_strategy(&intent, 3000).await.unwrap();
    
    assert!(matches!(strategy.primary_strategy, QueryStrategy::ContextualRelevanceOptimization));
    assert!(strategy.queries.len() <= 3); // Should have few queries for small budget
    assert!(strategy.context_budget <= 3000);
}

#[tokio::test]
async fn test_chronicle_focused_strategy() {
    let response_json = r#"{
        "primary_strategy": "ChronicleNarrativeMapping",
        "queries": [
            {
                "query_type": "ChronicleEvents",
                "priority": 1.0,
                "parameters": {
                    "chronicle_ids": ["war_chronicle"],
                    "event_types": ["battle", "treaty", "betrayal"]
                },
                "query_reasoning": "Extract key events from relevant chronicles",
                "expected_yield": 0.9
            },
            {
                "query_type": "ChronicleThemes",
                "priority": 0.85,
                "parameters": {
                    "chronicle_ids": ["war_chronicle"],
                    "theme_depth": "deep"
                },
                "query_reasoning": "Understand thematic elements for narrative consistency",
                "expected_yield": 0.82
            },
            {
                "query_type": "RelatedChronicles",
                "priority": 0.75,
                "parameters": {
                    "base_chronicle": "war_chronicle",
                    "relationship_types": ["causes", "parallels", "consequences"]
                },
                "dependencies": ["ChronicleEvents"],
                "query_reasoning": "Find connected chronicles for broader context",
                "expected_yield": 0.78
            }
        ],
        "context_budget": 8500,
        "execution_order": ["ChronicleEvents", "ChronicleThemes", "RelatedChronicles"],
        "reasoning": "Chronicle-based strategy leverages historical records to provide rich narrative context and thematic consistency",
        "optimization_hints": [
            "Prioritize chronicles with direct relevance to current events",
            "Extract thematic patterns for narrative coherence"
        ],
        "plan_confidence": 0.87,
        "alternative_strategies": []
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client), "test-model".to_string());
    
    let intent = QueryIntent {
        intent_type: IntentType::TemporalAnalysis,
        focus_entities: vec![],
        time_scope: TimeScope::AllTime,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Deep,
        context_priorities: vec![ContextPriority::TemporalState, ContextPriority::CausalChains],
        confidence: 0.85,
    };
    
    let strategy = planner.plan_query_strategy(&intent, 10000).await.unwrap();
    
    assert!(matches!(strategy.primary_strategy, QueryStrategy::ChronicleNarrativeMapping));
    assert!(strategy.queries.iter().any(|q| matches!(q.query_type, PlannedQueryType::ChronicleEvents)));
    assert!(strategy.queries.iter().any(|q| matches!(q.query_type, PlannedQueryType::ChronicleThemes)));
}

#[tokio::test]
async fn test_validation_of_confidence_bounds() {
    // Test that confidence values are properly clamped
    let response_json = r#"{
        "primary_strategy": "StateSnapshot",
        "queries": [
            {
                "query_type": "EntityCurrentState",
                "priority": 2.5,
                "parameters": {"entity_names": ["test"]},
                "expected_yield": -0.5
            }
        ],
        "context_budget": 5000,
        "execution_order": ["EntityCurrentState"],
        "reasoning": "Test",
        "optimization_hints": [],
        "plan_confidence": 1.5,
        "alternative_strategies": []
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client), "test-model".to_string());
    
    let intent = QueryIntent {
        intent_type: IntentType::StateInquiry,
        focus_entities: vec![],
        time_scope: TimeScope::Current,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Surface,
        context_priorities: vec![],
        confidence: 0.5,
    };
    
    let strategy = planner.plan_query_strategy(&intent, 5000).await.unwrap();
    
    // Values should be clamped to valid ranges
    assert!(strategy.plan_confidence >= 0.0 && strategy.plan_confidence <= 1.0);
    assert!(strategy.queries[0].priority >= 0.0 && strategy.queries[0].priority <= 1.0);
    if let Some(yield_val) = strategy.queries[0].expected_yield {
        assert!(yield_val >= 0.0 && yield_val <= 1.0);
    }
}

#[tokio::test]
async fn test_error_handling_invalid_json() {
    let mock_client = MockAiClient::new_with_response("This is not valid JSON!".to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client), "test-model".to_string());
    
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
    
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("Failed to parse Flash strategy response"));
}

#[tokio::test]
async fn test_fallback_strategy_on_unknown() {
    let response_json = r#"{
        "primary_strategy": "UnknownStrategy",
        "queries": [],
        "context_budget": 5000,
        "execution_order": [],
        "reasoning": "Test fallback",
        "optimization_hints": [],
        "plan_confidence": 0.5,
        "alternative_strategies": []
    }"#;
    
    let mock_client = MockAiClient::new_with_response(response_json.to_string());
    let planner = QueryStrategyPlanner::new(Arc::new(mock_client), "test-model".to_string());
    
    let intent = QueryIntent {
        intent_type: IntentType::NarrativeGeneration,
        focus_entities: vec![],
        time_scope: TimeScope::Current,
        spatial_scope: None,
        reasoning_depth: ReasoningDepth::Surface,
        context_priorities: vec![],
        confidence: 0.5,
    };
    
    let strategy = planner.plan_query_strategy(&intent, 5000).await.unwrap();
    
    // Should fall back to NarrativeContextAssembly
    assert!(matches!(strategy.primary_strategy, QueryStrategy::NarrativeContextAssembly));
}