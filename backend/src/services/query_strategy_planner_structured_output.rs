use serde::{Deserialize, Serialize};
use crate::errors::AppError;
use super::query_strategy_planner::{QueryStrategy, PlannedQueryType, QueryExecutionPlan, PlannedQuery, AlternativeStrategy};
use crate::services::query_registry::QueryRegistry;

/// Structured output schema for QueryStrategyPlanner
/// Ensures AI generates valid JSON for query planning with proper types

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryExecutionPlanOutput {
    pub primary_strategy: String, // One of the valid strategy names
    pub queries: Vec<PlannedQueryOutput>,
    pub context_budget: u32,
    pub execution_order: Vec<String>,
    pub reasoning: String,
    pub optimization_hints: Vec<String>,
    pub plan_confidence: f32,
    pub alternative_strategies: Vec<AlternativeStrategyOutput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedQueryOutput {
    pub query_type: String, // One of the valid query type names
    pub priority: f32,
    pub parameters: ParametersOutput,
    pub estimated_tokens: Option<u32>,
    pub dependencies: Vec<String>,
    pub query_reasoning: Option<String>,
    pub expected_yield: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParametersOutput {
    pub entity_names: Option<Vec<String>>,
    pub time_scope: Option<String>,
    pub max_results: Option<u32>,
    pub location_name: Option<String>,
    pub include_contained: Option<bool>,
    pub event_id: Option<String>,
    pub concept_type: Option<String>,
    pub search_query: Option<String>,
    pub context_keywords: Option<Vec<String>>,
    pub chronicle_id: Option<String>,
    pub character_name: Option<String>,
    pub entry_type: Option<String>,
    pub search_pattern: Option<String>,
    pub transition_type: Option<String>,
    pub search_context: Option<String>,
    pub max_depth: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlternativeStrategyOutput {
    pub strategy: String, // One of the valid strategy names
    pub reasoning: String,
    pub trade_offs: String,
}

/// Helper function to create the JSON schema for query execution plan
pub fn get_query_execution_plan_schema() -> serde_json::Value {
    let strategy_names = QueryRegistry::get_strategy_names();
    let query_type_names = QueryRegistry::get_query_type_names();
    
    serde_json::json!({
        "type": "object",
        "properties": {
            "primary_strategy": {
                "type": "string",
                "enum": strategy_names,
                "description": "The primary query strategy to use"
            },
            "queries": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "query_type": {
                            "type": "string",
                            "enum": query_type_names.clone(),
                            "description": "The type of query to execute"
                        },
                        "priority": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                            "description": "Priority of this query (0.0-1.0)"
                        },
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "entity_names": {
                                    "type": "array",
                                    "items": {"type": "string"}
                                },
                                "time_scope": {"type": "string"},
                                "max_results": {"type": "integer"},
                                "location_name": {"type": "string"},
                                "include_contained": {"type": "boolean"},
                                "event_id": {"type": "string"},
                                "concept_type": {"type": "string"},
                                "search_query": {"type": "string"},
                                "context_keywords": {
                                    "type": "array",
                                    "items": {"type": "string"}
                                },
                                "chronicle_id": {"type": "string"},
                                "character_name": {"type": "string"},
                                "entry_type": {"type": "string"},
                                "search_pattern": {"type": "string"},
                                "transition_type": {"type": "string"},
                                "search_context": {"type": "string"},
                                "max_depth": {"type": "integer"}
                            },
                            "description": "Query-specific parameters"
                        },
                        "estimated_tokens": {
                            "type": "integer",
                            "description": "Estimated tokens this query will consume"
                        },
                        "dependencies": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Query types this depends on"
                        },
                        "query_reasoning": {
                            "type": "string",
                            "description": "Why this query matters for the narrative"
                        },
                        "expected_yield": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                            "description": "Expected information yield (0.0-1.0)"
                        }
                    },
                    "required": ["query_type", "priority", "parameters", "dependencies"]
                },
                "description": "List of queries to execute"
            },
            "context_budget": {
                "type": "integer",
                "description": "Estimated tokens needed for the full context"
            },
            "execution_order": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Order to execute the queries in - MUST contain ONLY the exact query_type values from your queries array above (e.g., 'EntityCurrentState', 'SpatialEntities'). DO NOT include strategy names like 'LorebookCulturalContext' - those belong in primary_strategy field. Each item MUST match a query_type from one of your planned queries."
            },
            "reasoning": {
                "type": "string",
                "description": "Comprehensive explanation of strategy choice and expected narrative value"
            },
            "optimization_hints": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Hints about execution optimization and result processing"
            },
            "plan_confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Confidence level in the plan effectiveness (0.0-1.0)"
            },
            "alternative_strategies": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "strategy": {
                            "type": "string",
                            "enum": strategy_names.clone(),
                            "description": "Alternative strategy name"
                        },
                        "reasoning": {
                            "type": "string",
                            "description": "Why this strategy could work"
                        },
                        "trade_offs": {
                            "type": "string",
                            "description": "What we gain/lose with this approach"
                        }
                    },
                    "required": ["strategy", "reasoning", "trade_offs"]
                },
                "description": "Alternative strategies considered"
            }
        },
        "required": [
            "primary_strategy",
            "queries",
            "context_budget",
            "execution_order",
            "reasoning",
            "optimization_hints",
            "plan_confidence",
            "alternative_strategies"
        ]
    })
}

/// Convert structured output to internal QueryExecutionPlan type
impl QueryExecutionPlanOutput {
    pub fn to_query_execution_plan(&self) -> Result<QueryExecutionPlan, AppError> {
        // First validate that query types are not strategy names
        let strategy_names = vec![
            "SpatialContextMapping", "TemporalContextReconstruction", "CausalChainAnalysis",
            "EntityFocusedRetrieval", "NarrativeContextAssembly", "HistoricalContextRetrieval",
            "ContextualRelevanceOptimization", "ChronologicalReassembly", "LorebookContextualRetrieval",
            "LorebookConceptualMapping", "LorebookCulturalContext", "CausalChainTraversal",
            "RelationshipNetworkTraversal", "TemporalStateReconstruction", "CausalProjection",
            "StateSnapshot", "ComparativeAnalysis", "ChronicleNarrativeMapping",
            "ChronicleThematicAnalysis", "ChronicleTimelineReconstruction",
            "AdaptiveNarrativeStrategy", "EmergentPatternDiscovery"
        ];
        
        for query in &self.queries {
            if strategy_names.contains(&query.query_type.as_str()) {
                return Err(AppError::InvalidInput(
                    format!(
                        "Query type '{}' is actually a strategy name. Use specific query types like 'LorebookEntries', 'LorebookContext', or 'EntityCurrentState' instead",
                        query.query_type
                    )
                ));
            }
        }
        
        // Convert primary strategy
        let primary_strategy = match self.primary_strategy.as_str() {
            "CausalChainTraversal" => QueryStrategy::CausalChainTraversal,
            "SpatialContextMapping" => QueryStrategy::SpatialContextMapping,
            "RelationshipNetworkTraversal" => QueryStrategy::RelationshipNetworkTraversal,
            "TemporalStateReconstruction" => QueryStrategy::TemporalStateReconstruction,
            "CausalProjection" => QueryStrategy::CausalProjection,
            "NarrativeContextAssembly" => QueryStrategy::NarrativeContextAssembly,
            "StateSnapshot" => QueryStrategy::StateSnapshot,
            "ComparativeAnalysis" => QueryStrategy::ComparativeAnalysis,
            "ChronicleNarrativeMapping" => QueryStrategy::ChronicleNarrativeMapping,
            "ChronicleThematicAnalysis" => QueryStrategy::ChronicleThematicAnalysis,
            "ChronicleTimelineReconstruction" => QueryStrategy::ChronicleTimelineReconstruction,
            "LorebookContextualRetrieval" => QueryStrategy::LorebookContextualRetrieval,
            "LorebookConceptualMapping" => QueryStrategy::LorebookConceptualMapping,
            "LorebookCulturalContext" => QueryStrategy::LorebookCulturalContext,
            "AdaptiveNarrativeStrategy" => QueryStrategy::AdaptiveNarrativeStrategy,
            "EmergentPatternDiscovery" => QueryStrategy::EmergentPatternDiscovery,
            "ContextualRelevanceOptimization" => QueryStrategy::ContextualRelevanceOptimization,
            _ => return Err(AppError::InvalidInput(
                format!("Invalid primary strategy: {}", self.primary_strategy)
            )),
        };
        
        // Convert queries
        let mut queries = Vec::new();
        for query_output in &self.queries {
            let query_type = match query_output.query_type.as_str() {
                "EntityEvents" => PlannedQueryType::EntityEvents,
                "EntityCurrentState" => PlannedQueryType::EntityCurrentState,
                "EntityStates" => PlannedQueryType::EntityStates,
                "ActiveEntities" => PlannedQueryType::ActiveEntities,
                "EntityRelationships" => PlannedQueryType::EntityRelationships,
                "SharedEvents" => PlannedQueryType::SharedEvents,
                "CausalChain" => PlannedQueryType::CausalChain,
                "CausalFactors" => PlannedQueryType::CausalFactors,
                "SpatialEntities" => PlannedQueryType::SpatialEntities,
                "TimelineEvents" => PlannedQueryType::TimelineEvents,
                "StateTransitions" => PlannedQueryType::StateTransitions,
                "RecentEvents" => PlannedQueryType::RecentEvents,
                "HistoricalParallels" => PlannedQueryType::HistoricalParallels,
                "NarrativeThreads" => PlannedQueryType::NarrativeThreads,
                "ChronicleEvents" => PlannedQueryType::ChronicleEvents,
                "ChronicleTimeline" => PlannedQueryType::ChronicleTimeline,
                "ChronicleThemes" => PlannedQueryType::ChronicleThemes,
                "RelatedChronicles" => PlannedQueryType::RelatedChronicles,
                "LorebookEntries" => PlannedQueryType::LorebookEntries,
                "LorebookConcepts" => PlannedQueryType::LorebookConcepts,
                "LorebookCharacters" => PlannedQueryType::LorebookCharacters,
                "LorebookLocations" => PlannedQueryType::LorebookLocations,
                "LorebookContext" => PlannedQueryType::LorebookContext,
                "MissingEntities" => PlannedQueryType::MissingEntities,
                _ => return Err(AppError::InvalidInput(
                    format!("Invalid query type: {}", query_output.query_type)
                )),
            };
            
            // Convert parameters to HashMap
            let mut parameters = std::collections::HashMap::new();
            if let Some(entity_names) = &query_output.parameters.entity_names {
                parameters.insert("entity_names".to_string(), serde_json::to_value(entity_names)?);
            }
            if let Some(time_scope) = &query_output.parameters.time_scope {
                parameters.insert("time_scope".to_string(), serde_json::to_value(time_scope)?);
            }
            if let Some(max_results) = query_output.parameters.max_results {
                parameters.insert("max_results".to_string(), serde_json::to_value(max_results)?);
            }
            if let Some(location_name) = &query_output.parameters.location_name {
                parameters.insert("location_name".to_string(), serde_json::to_value(location_name)?);
            }
            if let Some(include_contained) = query_output.parameters.include_contained {
                parameters.insert("include_contained".to_string(), serde_json::to_value(include_contained)?);
            }
            if let Some(event_id) = &query_output.parameters.event_id {
                parameters.insert("event_id".to_string(), serde_json::to_value(event_id)?);
            }
            if let Some(concept_type) = &query_output.parameters.concept_type {
                parameters.insert("concept_type".to_string(), serde_json::to_value(concept_type)?);
            }
            if let Some(search_query) = &query_output.parameters.search_query {
                parameters.insert("search_query".to_string(), serde_json::to_value(search_query)?);
            }
            if let Some(context_keywords) = &query_output.parameters.context_keywords {
                parameters.insert("context_keywords".to_string(), serde_json::to_value(context_keywords)?);
            }
            if let Some(chronicle_id) = &query_output.parameters.chronicle_id {
                parameters.insert("chronicle_id".to_string(), serde_json::to_value(chronicle_id)?);
            }
            if let Some(character_name) = &query_output.parameters.character_name {
                parameters.insert("character_name".to_string(), serde_json::to_value(character_name)?);
            }
            if let Some(entry_type) = &query_output.parameters.entry_type {
                parameters.insert("entry_type".to_string(), serde_json::to_value(entry_type)?);
            }
            if let Some(search_pattern) = &query_output.parameters.search_pattern {
                parameters.insert("search_pattern".to_string(), serde_json::to_value(search_pattern)?);
            }
            if let Some(transition_type) = &query_output.parameters.transition_type {
                parameters.insert("transition_type".to_string(), serde_json::to_value(transition_type)?);
            }
            if let Some(search_context) = &query_output.parameters.search_context {
                parameters.insert("search_context".to_string(), serde_json::to_value(search_context)?);
            }
            if let Some(max_depth) = query_output.parameters.max_depth {
                parameters.insert("max_depth".to_string(), serde_json::to_value(max_depth)?);
            }
            
            queries.push(PlannedQuery {
                query_type,
                priority: query_output.priority,
                parameters,
                estimated_tokens: query_output.estimated_tokens,
                dependencies: query_output.dependencies.clone(),
                query_reasoning: query_output.query_reasoning.clone(),
                expected_yield: query_output.expected_yield,
            });
        }
        
        // Convert alternative strategies
        let mut alternative_strategies = Vec::new();
        for alt_output in &self.alternative_strategies {
            let strategy = match alt_output.strategy.as_str() {
                "CausalChainTraversal" => QueryStrategy::CausalChainTraversal,
                "SpatialContextMapping" => QueryStrategy::SpatialContextMapping,
                "RelationshipNetworkTraversal" => QueryStrategy::RelationshipNetworkTraversal,
                "TemporalStateReconstruction" => QueryStrategy::TemporalStateReconstruction,
                "CausalProjection" => QueryStrategy::CausalProjection,
                "NarrativeContextAssembly" => QueryStrategy::NarrativeContextAssembly,
                "StateSnapshot" => QueryStrategy::StateSnapshot,
                "ComparativeAnalysis" => QueryStrategy::ComparativeAnalysis,
                "ChronicleNarrativeMapping" => QueryStrategy::ChronicleNarrativeMapping,
                "ChronicleThematicAnalysis" => QueryStrategy::ChronicleThematicAnalysis,
                "ChronicleTimelineReconstruction" => QueryStrategy::ChronicleTimelineReconstruction,
                "LorebookContextualRetrieval" => QueryStrategy::LorebookContextualRetrieval,
                "LorebookConceptualMapping" => QueryStrategy::LorebookConceptualMapping,
                "LorebookCulturalContext" => QueryStrategy::LorebookCulturalContext,
                "AdaptiveNarrativeStrategy" => QueryStrategy::AdaptiveNarrativeStrategy,
                "EmergentPatternDiscovery" => QueryStrategy::EmergentPatternDiscovery,
                "ContextualRelevanceOptimization" => QueryStrategy::ContextualRelevanceOptimization,
                _ => return Err(AppError::InvalidInput(
                    format!("Invalid alternative strategy: {}", alt_output.strategy)
                )),
            };
            
            alternative_strategies.push(AlternativeStrategy {
                strategy,
                reasoning: alt_output.reasoning.clone(),
                trade_offs: alt_output.trade_offs.clone(),
            });
        }
        
        Ok(QueryExecutionPlan {
            primary_strategy,
            queries,
            context_budget: self.context_budget,
            execution_order: self.execution_order.clone(),
            reasoning: self.reasoning.clone(),
            optimization_hints: self.optimization_hints.clone(),
            plan_confidence: self.plan_confidence,
            alternative_strategies,
        })
    }
}

/// Validation for structured output
impl QueryExecutionPlanOutput {
    pub fn validate(&self) -> Result<(), AppError> {
        // Validate confidence is within range
        if self.plan_confidence < 0.0 || self.plan_confidence > 1.0 {
            return Err(AppError::InvalidInput(
                format!("Plan confidence must be between 0.0 and 1.0, got: {}", self.plan_confidence)
            ));
        }
        
        // Validate queries exist
        if self.queries.is_empty() {
            return Err(AppError::InvalidInput(
                "Plan must contain at least one query".to_string()
            ));
        }
        
        // Validate each query
        for query in &self.queries {
            // Validate priority
            if query.priority < 0.0 || query.priority > 1.0 {
                return Err(AppError::InvalidInput(
                    format!("Query priority must be between 0.0 and 1.0, got: {}", query.priority)
                ));
            }
            
            // Validate expected yield if present
            if let Some(yield_val) = query.expected_yield {
                if yield_val < 0.0 || yield_val > 1.0 {
                    return Err(AppError::InvalidInput(
                        format!("Expected yield must be between 0.0 and 1.0, got: {}", yield_val)
                    ));
                }
            }
        }
        
        // Validate execution order matches query types
        let query_types: Vec<&str> = self.queries.iter().map(|q| q.query_type.as_str()).collect();
        let strategy_names = vec![
            "SpatialContextMapping", "TemporalContextReconstruction", "CausalChainAnalysis",
            "EntityFocusedRetrieval", "NarrativeContextAssembly", "HistoricalContextRetrieval",
            "ContextualRelevanceOptimization", "ChronologicalReassembly", "LorebookContextualRetrieval",
            "LorebookConceptualMapping", "LorebookCulturalContext"
        ];
        
        for order_item in &self.execution_order {
            // Check if it's a strategy name instead of a query type
            if strategy_names.contains(&order_item.as_str()) {
                return Err(AppError::InvalidInput(
                    format!("Execution order contains strategy name '{}' instead of query type. Use query types like 'LorebookEntries' or 'EntityCurrentState'", order_item)
                ));
            }
            
            if !query_types.contains(&order_item.as_str()) {
                return Err(AppError::InvalidInput(
                    format!("Execution order contains invalid query type: {}", order_item)
                ));
            }
        }
        
        // Validate reasoning is not empty
        if self.reasoning.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "Plan reasoning cannot be empty".to_string()
            ));
        }
        
        Ok(())
    }
}