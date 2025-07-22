use scribe_backend::{
    services::{
        context_optimization_service::{
            ContextOptimizationService, OptimizationStrategy
        },
        context_assembly_engine::{
            AssembledContext, QueryExecutionResult, EntitySummary, ActiveEntitiesResult,
        },
        query_strategy_planner::QueryStrategy,
    },
    test_helpers::MockAiClient,
};
use std::sync::Arc;
use uuid::Uuid;

/// Create test assembled context
fn create_test_context() -> AssembledContext {
    let mut entity_summaries = vec![
        EntitySummary {
            entity_id: Uuid::new_v4(),
            name: "Luke Skywalker".to_string(),
            entity_type: "CHARACTER".to_string(),
            current_location: Some("Tatooine".to_string()),
            activity_level: 0.9,
            relevance_score: 1.0,
        },
        EntitySummary {
            entity_id: Uuid::new_v4(),
            name: "Death Star".to_string(),
            entity_type: "LOCATION".to_string(),
            current_location: None,
            activity_level: 0.8,
            relevance_score: 0.95,
        },
        EntitySummary {
            entity_id: Uuid::new_v4(),
            name: "Random Stormtrooper #42".to_string(),
            entity_type: "CHARACTER".to_string(),
            current_location: Some("Death Star".to_string()),
            activity_level: 0.2,
            relevance_score: 0.3,
        },
    ];

    // Add more entities for testing token budget constraints
    for i in 0..10 {
        entity_summaries.push(EntitySummary {
            entity_id: Uuid::new_v4(),
            name: format!("Background Character {}", i),
            entity_type: "CHARACTER".to_string(),
            current_location: None,
            activity_level: 0.1,
            relevance_score: 0.1,
        });
    }

    let active_entities_result = ActiveEntitiesResult {
        entities: entity_summaries,
        activity_threshold: 0.5,
        include_positions: true,
        include_states: false,
        tokens_used: 500,
    };

    AssembledContext {
        strategy_used: QueryStrategy::NarrativeContextAssembly,
        results: vec![QueryExecutionResult::ActiveEntities(active_entities_result)],
        total_tokens_used: 500,
        execution_time_ms: 150,
        success_rate: 100.0,
    }
}

#[tokio::test]
async fn test_optimize_context_entity_prioritization() {
    let luke_id = Uuid::new_v4();
    let mock_response = format!(r#"{{
        "optimization_reasoning": "Prioritizing Core entities (Luke Skywalker, Death Star) as they are central to the narrative. Pruning background characters to save tokens.",
        "optimization_strategy": "EntityPrioritization",
        "total_estimated_tokens": 850,
        "optimized_entities": [
            {{
                "entity_id": "{}",
                "name": "Luke Skywalker",
                "priority_score": 1.0,
                "inclusion_reason": "Protagonist - essential to narrative",
                "token_contribution": 250,
                "narrative_relevance": 1.0
            }},
            {{
                "entity_id": "death-star-id",
                "name": "Death Star",
                "priority_score": 0.95,
                "inclusion_reason": "Major plot location",
                "token_contribution": 200,
                "narrative_relevance": 0.9
            }}
        ],
        "pruned_content": [
            {{
                "content_type": "entity",
                "entity_name": "Random Stormtrooper #42",
                "reason": "Background character with no narrative significance",
                "tokens_saved": 150,
                "pruning_confidence": 0.95
            }}
        ],
        "suggested_refinements": [
            "Consider adding key relationships if they exist",
            "May want to include recent events for temporal context"
        ],
        "confidence": 0.92
    }}"#, luke_id);

    let mock_ai_client = MockAiClient::new_with_response(mock_response);
    let service = ContextOptimizationService::new(Arc::new(mock_ai_client), "gemini-2.5-flash".to_string());

    let context = create_test_context();
    let result = service.optimize_context(&context, None, Some(1000)).await.unwrap();

    assert_eq!(result.optimization_strategy, OptimizationStrategy::EntityPrioritization);
    assert_eq!(result.total_estimated_tokens, 850);
    assert_eq!(result.optimized_entities.len(), 2);
    assert_eq!(result.optimized_entities[0].name, "Luke Skywalker");
    assert_eq!(result.optimized_entities[0].priority_score, 1.0);
    assert_eq!(result.optimized_entities[0].narrative_relevance, 1.0);
    assert_eq!(result.pruned_content.len(), 1);
    assert_eq!(result.pruned_content[0].entity_name, "Random Stormtrooper #42");
    assert_eq!(result.confidence, 0.92);
    assert_eq!(result.suggested_refinements.len(), 2);
}

#[tokio::test]
async fn test_optimize_context_token_budget_constraint() {
    let mock_response = r#"{
        "optimization_reasoning": "Strict token budget of 500 requires aggressive pruning. Keeping only the most essential narrative elements.",
        "optimization_strategy": "TokenBudgetConstraint",
        "total_estimated_tokens": 480,
        "optimized_entities": [
            {
                "entity_id": "luke-id",
                "name": "Luke Skywalker",
                "priority_score": 1.0,
                "inclusion_reason": "Cannot remove protagonist",
                "token_contribution": 250,
                "narrative_relevance": 1.0
            }
        ],
        "pruned_content": [
            {
                "content_type": "entity",
                "entity_name": "Death Star",
                "reason": "Large token footprint - deferred to save space",
                "tokens_saved": 200,
                "pruning_confidence": 0.7
            },
            {
                "content_type": "entity",
                "entity_name": "Background Characters",
                "reason": "Non-essential for current context",
                "tokens_saved": 800,
                "pruning_confidence": 0.95
            }
        ],
        "suggested_refinements": [
            "Consider summary representations for pruned content",
            "Token budget may be too restrictive for narrative coherence"
        ],
        "confidence": 0.75
    }"#.to_string();

    let mock_ai_client = MockAiClient::new_with_response(mock_response);
    let service = ContextOptimizationService::new(Arc::new(mock_ai_client), "gemini-2.5-flash".to_string());

    let context = create_test_context();
    let result = service.optimize_context(&context, None, Some(500)).await.unwrap();

    assert_eq!(result.optimization_strategy, OptimizationStrategy::TokenBudgetConstraint);
    assert_eq!(result.total_estimated_tokens, 480);
    assert!(result.total_estimated_tokens <= 500);
    assert_eq!(result.optimized_entities.len(), 1);
    assert_eq!(result.pruned_content.len(), 2);
    assert_eq!(result.confidence, 0.75);
}

#[tokio::test]
async fn test_optimize_for_narrative_combat_scene() {
    let mock_response = r#"{
        "optimization_reasoning": "Combat scene requires immediate tactical information and character capabilities. Pruning distant relationships and old events while preserving action-relevant data.",
        "optimization_strategy": "ActionPotential",
        "total_estimated_tokens": 1200,
        "optimized_entities": [
            {
                "entity_id": "protagonist-id",
                "name": "Hero",
                "priority_score": 1.0,
                "inclusion_reason": "Active combatant - need abilities and status",
                "token_contribution": 300,
                "narrative_relevance": 1.0
            },
            {
                "entity_id": "enemy-id",
                "name": "Dark Knight",
                "priority_score": 0.95,
                "inclusion_reason": "Primary threat - need combat capabilities",
                "token_contribution": 280,
                "narrative_relevance": 0.95
            },
            {
                "entity_id": "arena-id",
                "name": "Combat Arena",
                "priority_score": 0.85,
                "inclusion_reason": "Environmental factors affect combat",
                "token_contribution": 200,
                "narrative_relevance": 0.8
            }
        ],
        "pruned_content": [
            {
                "content_type": "relationship",
                "entity_name": "Childhood friendship",
                "reason": "Not relevant to immediate combat",
                "tokens_saved": 150,
                "pruning_confidence": 0.9
            }
        ],
        "suggested_refinements": [
            "Include weapon/equipment details if available",
            "Recent combat events would provide tactical context"
        ],
        "confidence": 0.88
    }"#.to_string();

    let mock_ai_client = MockAiClient::new_with_response(mock_response);
    let service = ContextOptimizationService::new(Arc::new(mock_ai_client), "gemini-2.5-flash".to_string());

    let context = create_test_context();
    let result = service.optimize_for_narrative(
        &context,
        "The hero draws their sword and faces the dark knight in the arena",
        None
    ).await.unwrap();

    assert_eq!(result.optimization_strategy, OptimizationStrategy::ActionPotential);
    assert_eq!(result.optimized_entities.len(), 3);
    assert_eq!(result.optimized_entities[0].name, "Hero");
    assert_eq!(result.optimized_entities[1].name, "Dark Knight");
    assert_eq!(result.optimized_entities[2].name, "Combat Arena");
    assert!(result.optimization_reasoning.contains("Combat scene"));
    assert_eq!(result.confidence, 0.88);
}

#[tokio::test]
async fn test_optimize_for_narrative_emotional_scene() {
    let mock_response = r#"{
        "optimization_reasoning": "Emotional reunion scene requires relationship history, character emotional states, and intimate setting details. Action-oriented content can be minimized.",
        "optimization_strategy": "EmotionalResonance",
        "total_estimated_tokens": 950,
        "optimized_entities": [
            {
                "entity_id": "father-id",
                "name": "Vader",
                "priority_score": 1.0,
                "inclusion_reason": "Central to emotional revelation",
                "token_contribution": 350,
                "narrative_relevance": 1.0
            },
            {
                "entity_id": "son-id",
                "name": "Luke",
                "priority_score": 1.0,
                "inclusion_reason": "Experiencing the revelation",
                "token_contribution": 300,
                "narrative_relevance": 1.0
            }
        ],
        "pruned_content": [
            {
                "content_type": "entity",
                "entity_name": "Stormtroopers",
                "reason": "Background elements distract from intimate moment",
                "tokens_saved": 400,
                "pruning_confidence": 0.95
            },
            {
                "content_type": "event",
                "entity_name": "Previous battles",
                "reason": "Combat history less relevant than relationship",
                "tokens_saved": 200,
                "pruning_confidence": 0.85
            }
        ],
        "suggested_refinements": [
            "Include key relationship milestones if available",
            "Character internal state descriptions would enhance emotional impact"
        ],
        "confidence": 0.91
    }"#.to_string();

    let mock_ai_client = MockAiClient::new_with_response(mock_response);
    let service = ContextOptimizationService::new(Arc::new(mock_ai_client), "gemini-2.5-flash".to_string());

    let context = create_test_context();
    let result = service.optimize_for_narrative(
        &context,
        "Luke discovers that Vader is his father - an emotional revelation",
        Some(1000)
    ).await.unwrap();

    assert_eq!(result.optimization_strategy, OptimizationStrategy::EmotionalResonance);
    assert_eq!(result.optimized_entities.len(), 2);
    assert!(result.optimization_reasoning.contains("Emotional"));
    assert_eq!(result.pruned_content.len(), 2);
    assert_eq!(result.confidence, 0.91);
}

#[tokio::test]
async fn test_optimize_context_narrative_coherence() {
    let mock_response = r#"{
        "optimization_reasoning": "Maintaining narrative coherence by preserving all story-critical elements and their connections, even at the cost of more tokens.",
        "optimization_strategy": "NarrativeCoherence",
        "total_estimated_tokens": 1500,
        "optimized_entities": [
            {
                "entity_id": "hero-id",
                "name": "Hero",
                "priority_score": 1.0,
                "inclusion_reason": "Central character arc",
                "token_contribution": 300,
                "narrative_relevance": 1.0
            },
            {
                "entity_id": "mentor-id",
                "name": "Mentor",
                "priority_score": 0.9,
                "inclusion_reason": "Key to hero's journey",
                "token_contribution": 250,
                "narrative_relevance": 0.85
            },
            {
                "entity_id": "artifact-id",
                "name": "MacGuffin",
                "priority_score": 0.85,
                "inclusion_reason": "Plot driver",
                "token_contribution": 200,
                "narrative_relevance": 0.8
            }
        ],
        "pruned_content": [
            {
                "content_type": "entity",
                "entity_name": "Random Villager",
                "reason": "No narrative function",
                "tokens_saved": 100,
                "pruning_confidence": 1.0
            }
        ],
        "suggested_refinements": [
            "Consider adding thematic connections between entities",
            "Foreshadowing elements could be included for richer narrative"
        ],
        "confidence": 0.87
    }"#.to_string();

    let mock_ai_client = MockAiClient::new_with_response(mock_response);
    let service = ContextOptimizationService::new(Arc::new(mock_ai_client), "gemini-2.5-flash".to_string());

    let context = create_test_context();
    let query_strategy = QueryStrategy::NarrativeContextAssembly;

    let result = service.optimize_context(&context, Some(&query_strategy), None).await.unwrap();

    assert_eq!(result.optimization_strategy, OptimizationStrategy::NarrativeCoherence);
    assert_eq!(result.optimized_entities.len(), 3);
    assert!(result.optimization_reasoning.contains("narrative coherence"));
    assert_eq!(result.confidence, 0.87);
}

#[tokio::test]
async fn test_optimize_context_conservative_pruning() {
    let mock_response = r#"{
        "optimization_reasoning": "Using conservative approach - keeping most content to avoid losing potentially important information. Only removing clearly redundant items.",
        "optimization_strategy": "ConservativePruning",
        "total_estimated_tokens": 2200,
        "optimized_entities": [
            {
                "entity_id": "entity-1",
                "name": "Luke Skywalker",
                "priority_score": 1.0,
                "inclusion_reason": "Core character",
                "token_contribution": 250,
                "narrative_relevance": 1.0
            },
            {
                "entity_id": "entity-2",
                "name": "Death Star",
                "priority_score": 0.95,
                "inclusion_reason": "Major location",
                "token_contribution": 200,
                "narrative_relevance": 0.9
            },
            {
                "entity_id": "entity-3",
                "name": "Random Stormtrooper #42",
                "priority_score": 0.3,
                "inclusion_reason": "Kept for scene completeness",
                "token_contribution": 150,
                "narrative_relevance": 0.3
            }
        ],
        "pruned_content": [
            {
                "content_type": "entity",
                "entity_name": "Duplicate background extra",
                "reason": "True duplicate with no unique attributes",
                "tokens_saved": 50,
                "pruning_confidence": 1.0
            }
        ],
        "suggested_refinements": [
            "More aggressive pruning possible if token limits require",
            "Consider context-specific optimization instead"
        ],
        "confidence": 0.8
    }"#.to_string();

    let mock_ai_client = MockAiClient::new_with_response(mock_response);
    let service = ContextOptimizationService::new(Arc::new(mock_ai_client), "gemini-2.5-flash".to_string());

    let context = create_test_context();
    let result = service.optimize_context(&context, None, None).await.unwrap();

    assert_eq!(result.optimization_strategy, OptimizationStrategy::ConservativePruning);
    assert!(result.optimized_entities.len() >= 3);
    assert_eq!(result.pruned_content.len(), 1);
    assert_eq!(result.pruned_content[0].pruning_confidence, 1.0);
    assert!(result.optimization_reasoning.contains("conservative"));
}

#[tokio::test]
async fn test_optimize_context_adaptive_optimization() {
    let mock_response = r#"{
        "optimization_reasoning": "Balancing multiple factors: narrative importance, token constraints, and information density. Adaptive approach based on context analysis.",
        "optimization_strategy": "AdaptiveOptimization",
        "total_estimated_tokens": 1100,
        "optimized_entities": [
            {
                "entity_id": "luke-id",
                "name": "Luke Skywalker",
                "priority_score": 1.0,
                "inclusion_reason": "Protagonist - highest adaptive priority",
                "token_contribution": 250,
                "narrative_relevance": 1.0
            },
            {
                "entity_id": "death-star-id",
                "name": "Death Star",
                "priority_score": 0.85,
                "inclusion_reason": "Setting - high adaptive value",
                "token_contribution": 200,
                "narrative_relevance": 0.85
            }
        ],
        "pruned_content": [
            {
                "content_type": "entity",
                "entity_name": "Background extras",
                "reason": "Low adaptive value across all metrics",
                "tokens_saved": 600,
                "pruning_confidence": 0.88
            }
        ],
        "suggested_refinements": [
            "Could adjust based on user interaction patterns",
            "Adaptive weights could be tuned per scene type"
        ],
        "confidence": 0.83
    }"#.to_string();

    let mock_ai_client = MockAiClient::new_with_response(mock_response);
    let service = ContextOptimizationService::new(Arc::new(mock_ai_client), "gemini-2.5-flash".to_string());

    let context = create_test_context();
    let result = service.optimize_context(&context, None, Some(1200)).await.unwrap();

    assert_eq!(result.optimization_strategy, OptimizationStrategy::AdaptiveOptimization);
    assert_eq!(result.optimized_entities.len(), 2);
    assert!(result.optimization_reasoning.contains("Balancing multiple factors"));
    assert_eq!(result.confidence, 0.83);
}

#[tokio::test]
async fn test_ai_response_parsing_error() {
    let mock_ai_client = MockAiClient::new_with_response("This is not valid JSON".to_string());
    
    let service = ContextOptimizationService::new(Arc::new(mock_ai_client), "gemini-2.5-flash".to_string());
    let context = create_test_context();
    
    let result = service.optimize_context(&context, None, None).await;
    
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("Failed to parse Flash optimization response"));
}

#[tokio::test]
async fn test_empty_context_optimization() {
    let mock_response = r#"{
        "optimization_reasoning": "Empty context requires no optimization. No entities to process.",
        "optimization_strategy": "AdaptiveOptimization",
        "total_estimated_tokens": 0,
        "optimized_entities": [],
        "pruned_content": [],
        "suggested_refinements": [
            "Add entities to enable optimization"
        ],
        "confidence": 1.0
    }"#.to_string();

    let mock_ai_client = MockAiClient::new_with_response(mock_response);
    let service = ContextOptimizationService::new(Arc::new(mock_ai_client), "gemini-2.5-flash".to_string());

    let empty_context = AssembledContext {
        strategy_used: QueryStrategy::NarrativeContextAssembly,
        results: vec![],
        total_tokens_used: 0,
        execution_time_ms: 0,
        success_rate: 100.0,
    };

    let result = service.optimize_context(&empty_context, None, None).await.unwrap();

    assert_eq!(result.total_estimated_tokens, 0);
    assert_eq!(result.optimized_entities.len(), 0);
    assert_eq!(result.pruned_content.len(), 0);
    assert_eq!(result.confidence, 1.0);
}

#[tokio::test]
async fn test_estimate_tokens() {
    let service = ContextOptimizationService::new(Arc::new(MockAiClient::new_with_response("".to_string())), "gemini-2.5-flash".to_string());
    
    // Test various content lengths
    assert_eq!(service.estimate_tokens("test"), 1); // 4 chars = 1 token
    assert_eq!(service.estimate_tokens("hello world"), 3); // 11 chars = 3 tokens
    assert_eq!(service.estimate_tokens("This is a longer sentence with multiple words."), 12); // 46 chars = 12 tokens
    assert_eq!(service.estimate_tokens(""), 0); // empty = 0 tokens
}

#[tokio::test]
async fn test_optimize_with_relationships_and_events() {
    let entity_id = Uuid::new_v4();
    let mock_response = format!(r#"{{
        "optimization_reasoning": "Including key relationships and recent events that directly impact narrative understanding.",
        "optimization_strategy": "NarrativeCoherence",
        "total_estimated_tokens": 1800,
        "optimized_entities": [
            {{
                "entity_id": "{}",
                "name": "Luke Skywalker",
                "priority_score": 1.0,
                "inclusion_reason": "Central character with key relationships",
                "token_contribution": 300,
                "narrative_relevance": 1.0
            }}
        ],
        "pruned_content": [
            {{
                "content_type": "relationship",
                "entity_name": "Distant cousin relationship",
                "reason": "Tangential relationship with no narrative impact",
                "tokens_saved": 100,
                "pruning_confidence": 0.9
            }},
            {{
                "content_type": "event",
                "entity_name": "Background chatter event",
                "reason": "Atmospheric event with no plot relevance",
                "tokens_saved": 80,
                "pruning_confidence": 0.95
            }}
        ],
        "suggested_refinements": [
            "Focus on causal relationships between events",
            "Consider temporal clustering of related events"
        ],
        "confidence": 0.86
    }}"#, entity_id);

    let mock_ai_client = MockAiClient::new_with_response(mock_response);
    let service = ContextOptimizationService::new(Arc::new(mock_ai_client), "gemini-2.5-flash".to_string());

    // Create a context with relationships and events
    use scribe_backend::services::context_assembly_engine::{
        EntityRelationshipsResult, RelationshipSummary,
        TimelineEventsResult, TimelineEvent
    };
    
    let relationships_result = EntityRelationshipsResult {
        entity_names: vec!["Luke Skywalker".to_string(), "Darth Vader".to_string()],
        relationships: vec![
            RelationshipSummary {
                from_entity: "Luke Skywalker".to_string(),
                to_entity: "Darth Vader".to_string(),
                relationship_type: "FAMILY".to_string(),
                strength: 1.0,
                context: "Father and son".to_string(),
            }
        ],
        max_depth: 1,
        tokens_used: 200,
    };

    let timeline_result = TimelineEventsResult {
        entity_names: vec!["Luke Skywalker".to_string()],
        timeline: vec![
            TimelineEvent {
                event_id: Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                description: "Luke learns about his father".to_string(),
                participants: vec!["Luke Skywalker".to_string(), "Darth Vader".to_string()],
                significance: 0.9,
            }
        ],
        event_categories: vec!["DIALOGUE".to_string()],
        tokens_used: 150,
    };

    let mut context = create_test_context();
    context.results.push(QueryExecutionResult::EntityRelationships(relationships_result));
    context.results.push(QueryExecutionResult::TimelineEvents(timeline_result));

    let result = service.optimize_context(&context, None, Some(2000)).await.unwrap();

    assert_eq!(result.optimization_strategy, OptimizationStrategy::NarrativeCoherence);
    assert_eq!(result.pruned_content.len(), 2);
    assert!(result.pruned_content.iter().any(|p| p.content_type == "relationship"));
    assert!(result.pruned_content.iter().any(|p| p.content_type == "event"));
    assert_eq!(result.confidence, 0.86);
}