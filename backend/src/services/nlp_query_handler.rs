//! NLP Query Handler
//!
//! This service implements Phase 3.1.2 of the ECS Architecture Plan:
//! - Basic natural language query intent detection
//! - WorldModelSnapshot integration for LLM reasoning
//! - Structured response generation for LLM consumption
//!
//! Key Features:
//! - Keyword-based intent classification (expandable to ML-based)
//! - World model snapshot generation for query context
//! - LLM-optimized response formatting
//! - Query confidence scoring and fallback handling

use std::sync::Arc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use chrono::Duration;
use tracing::{info, debug, instrument};

use crate::{
    errors::AppError,
    models::world_model::*,
    services::{
        world_model_service::{WorldModelService, WorldModelOptions, LLMContextFocus, TimeFocus, ReasoningDepth},
        hybrid_query_service::HybridQueryService,
    },
};

/// Natural Language Query Handler for basic intent detection and processing
pub struct NLPQueryHandler {
    world_model_service: Arc<WorldModelService>,
    query_service: Arc<HybridQueryService>,
}

impl NLPQueryHandler {
    /// Create a new NLP query handler
    pub fn new(
        world_model_service: Arc<WorldModelService>,
        query_service: Arc<HybridQueryService>,
    ) -> Self {
        Self {
            world_model_service,
            query_service,
        }
    }

    /// Process natural language query and return LLM-ready response
    #[instrument(skip(self), fields(user_id = %user_id))]
    pub async fn process_natural_language_query(
        &self,
        user_id: Uuid,
        chronicle_id: Option<Uuid>,
        query: &str,
        context_window: Duration,
    ) -> Result<LLMReasoningResponse, AppError> {
        info!("Processing natural language query: {}", query);
        
        // Step 1: Analyze query intent
        let intent = self.analyze_query_intent(query)?;
        debug!("Query intent analyzed: {:?}", intent);
        
        // Step 2: Generate world model snapshot
        let snapshot = self.world_model_service.generate_world_snapshot(
            user_id,
            chronicle_id,
            None, // Current time
            WorldModelOptions {
                time_window: context_window,
                focus_entities: intent.focus_entities.clone(),
                include_inactive: false,
                max_entities: 100,
            },
        ).await?;
        
        // Step 3: Convert to LLM context
        let llm_context = self.world_model_service.snapshot_to_llm_context(
            &snapshot,
            LLMContextFocus {
                query_intent: intent.intent_type.to_string(),
                key_entities: intent.focus_entities.clone().unwrap_or_default(),
                time_focus: intent.time_focus.clone(),
                reasoning_depth: intent.reasoning_depth.clone(),
            },
        )?;
        
        // Step 4: Execute specific queries based on intent
        let query_results = self.execute_intent_queries(&intent, user_id).await?;
        
        // Step 5: Generate reasoning suggestions
        let reasoning_suggestions = self.generate_reasoning_suggestions(&intent, &llm_context)?;
        
        // Step 6: Calculate overall confidence before moving query_results
        let overall_confidence = self.calculate_overall_confidence(&intent, &query_results);
        
        // Step 7: Format response
        Ok(LLMReasoningResponse {
            original_query: query.to_string(),
            interpreted_intent: intent,
            world_context: llm_context,
            specific_results: query_results,
            reasoning_suggestions,
            confidence: overall_confidence,
        })
    }
    
    /// Analyze query intent using keyword-based classification
    pub fn analyze_query_intent(&self, query: &str) -> Result<QueryIntent, AppError> {
        let query_lower = query.to_lowercase();
        let mut confidence: f32 = 0.7; // Base confidence
        
        // Extract potential entity names (simple approach)
        let potential_entities = self.extract_entity_mentions(&query_lower);
        
        // Classify intent type based on keywords
        let intent_type = if query_lower.contains("what caused") || 
                             query_lower.contains("why did") || 
                             query_lower.contains("because of") ||
                             query_lower.contains("led to") {
            confidence += 0.2;
            IntentType::CausalReasoning
        } else if query_lower.contains("where is") || 
                  query_lower.contains("located at") ||
                  query_lower.contains("in the") ||
                  query_lower.contains("position") {
            confidence += 0.1;
            IntentType::SpatialQuery
        } else if query_lower.contains("relationship") || 
                  query_lower.contains("between") ||
                  query_lower.contains("friends with") ||
                  query_lower.contains("allies") ||
                  query_lower.contains("enemies") {
            confidence += 0.15;
            IntentType::RelationshipAnalysis
        } else if query_lower.contains("what happened") || 
                  query_lower.contains("timeline") ||
                  query_lower.contains("when did") ||
                  query_lower.contains("before") ||
                  query_lower.contains("after") {
            confidence += 0.1;
            IntentType::TemporalQuery
        } else if query_lower.contains("how many") ||
                  query_lower.contains("count") ||
                  query_lower.contains("list") {
            IntentType::QuantitativeQuery
        } else if query_lower.contains("compare") ||
                  query_lower.contains("difference") ||
                  query_lower.contains("similar") {
            IntentType::ComparativeQuery
        } else {
            IntentType::GeneralInquiry
        };
        
        // Determine time focus
        let time_focus = if query_lower.contains("currently") || 
                           query_lower.contains("now") ||
                           query_lower.contains("present") {
            TimeFocus::Current
        } else if query_lower.contains("yesterday") ||
                  query_lower.contains("last") ||
                  query_lower.contains("previous") {
            TimeFocus::Historical(Duration::days(1))
        } else if query_lower.contains("week") {
            TimeFocus::Historical(Duration::weeks(1))
        } else if query_lower.contains("month") {
            TimeFocus::Historical(Duration::days(30))
        } else {
            TimeFocus::Current
        };
        
        // Determine reasoning depth
        let reasoning_depth = match intent_type {
            IntentType::CausalReasoning => ReasoningDepth::Deep,
            IntentType::RelationshipAnalysis => ReasoningDepth::Causal,
            IntentType::TemporalQuery => ReasoningDepth::Causal,
            _ => ReasoningDepth::Surface,
        };
        
        Ok(QueryIntent {
            intent_type,
            focus_entities: if potential_entities.is_empty() { None } else { Some(potential_entities) },
            time_focus,
            reasoning_depth,
            confidence: confidence.min(1.0),
            extracted_keywords: self.extract_keywords(&query_lower),
            complexity_score: self.calculate_query_complexity(&query_lower),
        })
    }
    
    /// Execute specific queries based on detected intent
    async fn execute_intent_queries(
        &self,
        intent: &QueryIntent,
        _user_id: Uuid,
    ) -> Result<Vec<QueryResult>, AppError> {
        let mut results = Vec::new();
        
        match &intent.intent_type {
            IntentType::CausalReasoning => {
                // Execute causal chain queries
                if let Some(entities) = &intent.focus_entities {
                    for entity_id in entities {
                        // This would use the enhanced query types from Phase 2
                        results.push(QueryResult {
                            result_type: "causal_influences".to_string(),
                            data: serde_json::json!({
                                "entity_id": entity_id,
                                "query_type": "causal_analysis",
                                "placeholder": "Would execute CausalInfluences query here"
                            }),
                            relevance: 0.9,
                            confidence: intent.confidence,
                        });
                    }
                }
            },
            IntentType::RelationshipAnalysis => {
                // Execute relationship network queries
                if let Some(entities) = &intent.focus_entities {
                    for entity_id in entities {
                        results.push(QueryResult {
                            result_type: "relationship_network".to_string(),
                            data: serde_json::json!({
                                "center_entity_id": entity_id,
                                "query_type": "relationship_analysis",
                                "placeholder": "Would execute RelationshipNetwork query here"
                            }),
                            relevance: 0.85,
                            confidence: intent.confidence,
                        });
                    }
                }
            },
            IntentType::TemporalQuery => {
                // Execute temporal path queries
                if let Some(entities) = &intent.focus_entities {
                    for entity_id in entities {
                        results.push(QueryResult {
                            result_type: "temporal_path".to_string(),
                            data: serde_json::json!({
                                "entity_id": entity_id,
                                "query_type": "temporal_analysis", 
                                "placeholder": "Would execute TemporalPath query here"
                            }),
                            relevance: 0.8,
                            confidence: intent.confidence,
                        });
                    }
                }
            },
            IntentType::SpatialQuery => {
                // Execute spatial queries
                results.push(QueryResult {
                    result_type: "spatial_analysis".to_string(),
                    data: serde_json::json!({
                        "query_type": "spatial_query",
                        "placeholder": "Would execute spatial hierarchy queries here"
                    }),
                    relevance: 0.75,
                    confidence: intent.confidence,
                });
            },
            _ => {
                // General inquiry - provide world model snapshot
                results.push(QueryResult {
                    result_type: "general_context".to_string(),
                    data: serde_json::json!({
                        "query_type": "general_inquiry",
                        "context": "World model snapshot provided"
                    }),
                    relevance: 0.6,
                    confidence: intent.confidence,
                });
            }
        }
        
        Ok(results)
    }
    
    /// Generate reasoning suggestions based on intent and context
    pub fn generate_reasoning_suggestions(
        &self,
        intent: &QueryIntent,
        llm_context: &LLMWorldContext,
    ) -> Result<Vec<ReasoningSuggestion>, AppError> {
        let mut suggestions = Vec::new();
        
        match &intent.intent_type {
            IntentType::CausalReasoning => {
                suggestions.push(ReasoningSuggestion {
                    suggestion: "Trace through the causal chains to identify root causes".to_string(),
                    reasoning_path: vec![
                        "1. Identify the outcome or effect in question".to_string(),
                        "2. Look for immediate preceding events".to_string(),
                        "3. Follow causal links backwards to root causes".to_string(),
                        "4. Consider confidence levels of each causal link".to_string(),
                    ],
                    confidence: 0.9,
                    suggestion_type: "methodology".to_string(),
                });
                
                if !llm_context.causal_chains.is_empty() {
                    suggestions.push(ReasoningSuggestion {
                        suggestion: format!("Found {} causal chains in the current context", llm_context.causal_chains.len()),
                        reasoning_path: llm_context.causal_chains.iter()
                            .map(|chain| format!("{} -> {}", chain.root_cause, chain.final_effect))
                            .collect(),
                        confidence: 0.8,
                        suggestion_type: "evidence".to_string(),
                    });
                }
            },
            IntentType::RelationshipAnalysis => {
                suggestions.push(ReasoningSuggestion {
                    suggestion: "Analyze relationship patterns and strength dynamics".to_string(),
                    reasoning_path: vec![
                        "1. Identify the entities involved in the relationship".to_string(),
                        "2. Examine relationship strength and type".to_string(),
                        "3. Look for recent events that might have affected the relationship".to_string(),
                        "4. Consider relationship clusters and network effects".to_string(),
                    ],
                    confidence: 0.85,
                    suggestion_type: "methodology".to_string(),
                });
            },
            IntentType::TemporalQuery => {
                suggestions.push(ReasoningSuggestion {
                    suggestion: "Reconstruct the timeline of events and state changes".to_string(),
                    reasoning_path: vec![
                        "1. Establish the time period of interest".to_string(),
                        "2. Identify key events in chronological order".to_string(),
                        "3. Track entity state changes over time".to_string(),
                        "4. Note any causal relationships between temporal events".to_string(),
                    ],
                    confidence: 0.8,
                    suggestion_type: "methodology".to_string(),
                });
            },
            _ => {
                suggestions.push(ReasoningSuggestion {
                    suggestion: "Consider the full context of the world model".to_string(),
                    reasoning_path: vec![
                        "1. Review the current state of all relevant entities".to_string(),
                        "2. Consider spatial relationships and locations".to_string(),
                        "3. Look at recent events and their impacts".to_string(),
                        "4. Identify any patterns or anomalies".to_string(),
                    ],
                    confidence: 0.7,
                    suggestion_type: "general".to_string(),
                });
            }
        }
        
        Ok(suggestions)
    }
    
    // Helper methods
    
    /// Extract potential entity mentions from query (simple regex-based approach)
    fn extract_entity_mentions(&self, _query: &str) -> Vec<Uuid> {
        // In a real implementation, this would:
        // 1. Use NER (Named Entity Recognition) to find entity names
        // 2. Match entity names against the database
        // 3. Return the corresponding UUIDs
        // For now, return empty vec (would be enhanced in v1.1)
        Vec::new()
    }
    
    /// Extract keywords from query for intent analysis
    fn extract_keywords(&self, query: &str) -> Vec<String> {
        let stop_words = ["the", "is", "at", "which", "on", "a", "an", "and", "or", "but"];
        
        query.split_whitespace()
            .filter(|word| !stop_words.contains(word) && word.len() > 2)
            .map(|word| word.to_string())
            .collect()
    }
    
    /// Calculate query complexity score
    pub fn calculate_query_complexity(&self, query: &str) -> f32 {
        let mut complexity: f32 = 0.3; // Base complexity
        
        // Add complexity for certain keywords
        if query.contains("why") || query.contains("because") { complexity += 0.3; }
        if query.contains("relationship") || query.contains("between") { complexity += 0.2; }
        if query.contains("timeline") || query.contains("happened") { complexity += 0.2; }
        if query.contains("compare") || query.contains("difference") { complexity += 0.25; }
        
        // Add complexity for question length
        let word_count = query.split_whitespace().count();
        if word_count > 10 { complexity += 0.1; }
        if word_count > 20 { complexity += 0.1; }
        
        complexity.min(1.0)
    }
    
    /// Calculate overall confidence based on intent and results
    fn calculate_overall_confidence(&self, intent: &QueryIntent, results: &[QueryResult]) -> f32 {
        if results.is_empty() {
            return intent.confidence * 0.5; // Reduce confidence if no results
        }
        
        let avg_result_confidence = results.iter()
            .map(|r| r.confidence)
            .sum::<f32>() / results.len() as f32;
        
        // Weighted average of intent confidence and result confidence
        (intent.confidence * 0.6 + avg_result_confidence * 0.4).min(1.0)
    }
}

/// Response structure for LLM reasoning queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMReasoningResponse {
    /// Original natural language query
    pub original_query: String,
    /// Interpreted intent from the query
    pub interpreted_intent: QueryIntent,
    /// Structured world context for LLM reasoning
    pub world_context: LLMWorldContext,
    /// Specific query results based on intent
    pub specific_results: Vec<QueryResult>,
    /// Reasoning suggestions for the LLM
    pub reasoning_suggestions: Vec<ReasoningSuggestion>,
    /// Overall confidence in the response
    pub confidence: f32,
}

/// Detected query intent with analysis metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryIntent {
    /// Type of intent detected
    pub intent_type: IntentType,
    /// Entities that the query focuses on
    pub focus_entities: Option<Vec<Uuid>>,
    /// Temporal focus of the query
    pub time_focus: TimeFocus,
    /// Required reasoning depth
    pub reasoning_depth: ReasoningDepth,
    /// Confidence in the intent detection
    pub confidence: f32,
    /// Keywords extracted from the query
    pub extracted_keywords: Vec<String>,
    /// Complexity score of the query
    pub complexity_score: f32,
}

/// Types of query intents that can be detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntentType {
    /// Query about cause-effect relationships
    CausalReasoning,
    /// Query about spatial relationships and locations
    SpatialQuery,
    /// Query about entity relationships
    RelationshipAnalysis,
    /// Query about timelines and temporal sequences
    TemporalQuery,
    /// Query asking for counts or quantities
    QuantitativeQuery,
    /// Query comparing entities or states
    ComparativeQuery,
    /// General information request
    GeneralInquiry,
}

impl std::fmt::Display for IntentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntentType::CausalReasoning => write!(f, "causal_reasoning"),
            IntentType::SpatialQuery => write!(f, "spatial_query"),
            IntentType::RelationshipAnalysis => write!(f, "relationship_analysis"),
            IntentType::TemporalQuery => write!(f, "temporal_query"),
            IntentType::QuantitativeQuery => write!(f, "quantitative_query"),
            IntentType::ComparativeQuery => write!(f, "comparative_query"),
            IntentType::GeneralInquiry => write!(f, "general_inquiry"),
        }
    }
}

/// Individual query result with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    /// Type of result returned
    pub result_type: String,
    /// Actual result data
    pub data: JsonValue,
    /// Relevance to the original query (0.0-1.0)
    pub relevance: f32,
    /// Confidence in this specific result
    pub confidence: f32,
}

/// Reasoning suggestion to guide LLM analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningSuggestion {
    /// The suggestion text
    pub suggestion: String,
    /// Step-by-step reasoning path
    pub reasoning_path: Vec<String>,
    /// Confidence in this suggestion
    pub confidence: f32,
    /// Type of suggestion (methodology, evidence, general)
    pub suggestion_type: String,
}