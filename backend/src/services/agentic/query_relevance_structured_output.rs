use serde::{Deserialize, Serialize};
use crate::errors::AppError;

/// Structured output schema for Query Relevance Scoring
/// Ensures AI generates comprehensive multi-factor relevance analysis

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryRelevanceOutput {
    pub entity_name_relevance: RelevanceFactor, // How relevant is the entity name to the query
    pub current_state_relevance: RelevanceFactor, // How relevant is the entity's current state
    pub timeline_relevance: RelevanceFactor, // How relevant are the entity's timeline events
    pub semantic_relevance: RelevanceFactor, // Overall semantic/contextual relevance
    pub query_type_relevance: RelevanceFactor, // Specific relevance based on query type
    pub temporal_relevance: RelevanceFactor, // Time-based relevance (recency, time period match)
    pub overall_relevance_score: f32, // Weighted combination of all factors (0.0-1.0)
    pub relevance_explanation: String, // Natural language explanation of the relevance
    pub confidence_score: f32, // Confidence in the relevance assessment (0.0-1.0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelevanceFactor {
    pub score: f32, // Individual factor score (0.0-1.0)
    pub weight: f32, // How much this factor contributes to overall score
    pub reasoning: String, // Why this score was assigned
    pub evidence: Vec<String>, // Specific evidence supporting this score
}

/// Helper function to create the JSON schema for query relevance scoring
pub fn get_query_relevance_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "entity_name_relevance": {
                "type": "object",
                "properties": {
                    "score": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Relevance score for entity name match"
                    },
                    "weight": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Weight of this factor in overall score"
                    },
                    "reasoning": {
                        "type": "string",
                        "description": "Explanation for the score"
                    },
                    "evidence": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific matches or patterns found"
                    }
                },
                "required": ["score", "weight", "reasoning", "evidence"],
                "description": "How well does the entity name match the query"
            },
            "current_state_relevance": {
                "type": "object",
                "properties": {
                    "score": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Relevance score for current entity state"
                    },
                    "weight": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Weight of this factor"
                    },
                    "reasoning": {
                        "type": "string",
                        "description": "Explanation for the score"
                    },
                    "evidence": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Relevant state components or attributes"
                    }
                },
                "required": ["score", "weight", "reasoning", "evidence"],
                "description": "How relevant is the entity's current state to the query"
            },
            "timeline_relevance": {
                "type": "object",
                "properties": {
                    "score": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Relevance score for timeline events"
                    },
                    "weight": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Weight of this factor"
                    },
                    "reasoning": {
                        "type": "string",
                        "description": "Explanation for the score"
                    },
                    "evidence": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Relevant events from the timeline"
                    }
                },
                "required": ["score", "weight", "reasoning", "evidence"],
                "description": "How relevant are the entity's past events"
            },
            "semantic_relevance": {
                "type": "object",
                "properties": {
                    "score": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Overall semantic/contextual relevance"
                    },
                    "weight": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Weight of this factor"
                    },
                    "reasoning": {
                        "type": "string",
                        "description": "Explanation for the score"
                    },
                    "evidence": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Semantic connections found"
                    }
                },
                "required": ["score", "weight", "reasoning", "evidence"],
                "description": "Deeper semantic and contextual relevance"
            },
            "query_type_relevance": {
                "type": "object",
                "properties": {
                    "score": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Relevance based on query type"
                    },
                    "weight": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Weight of this factor"
                    },
                    "reasoning": {
                        "type": "string",
                        "description": "Why this entity is relevant to this query type"
                    },
                    "evidence": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Query type specific evidence"
                    }
                },
                "required": ["score", "weight", "reasoning", "evidence"],
                "description": "Specific relevance based on the type of query"
            },
            "temporal_relevance": {
                "type": "object",
                "properties": {
                    "score": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Time-based relevance score"
                    },
                    "weight": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Weight of this factor"
                    },
                    "reasoning": {
                        "type": "string",
                        "description": "Temporal relevance explanation"
                    },
                    "evidence": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Time-related evidence"
                    }
                },
                "required": ["score", "weight", "reasoning", "evidence"],
                "description": "Recency and time period relevance"
            },
            "overall_relevance_score": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Weighted combination of all relevance factors"
            },
            "relevance_explanation": {
                "type": "string",
                "description": "Natural language summary of why this entity is relevant"
            },
            "confidence_score": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Confidence in the relevance assessment"
            }
        },
        "required": [
            "entity_name_relevance",
            "current_state_relevance",
            "timeline_relevance",
            "semantic_relevance",
            "query_type_relevance",
            "temporal_relevance",
            "overall_relevance_score",
            "relevance_explanation",
            "confidence_score"
        ]
    })
}

/// Validation for structured output
impl QueryRelevanceOutput {
    pub fn validate(&self) -> Result<(), AppError> {
        // Validate overall scores
        if self.overall_relevance_score < 0.0 || self.overall_relevance_score > 1.0 {
            return Err(AppError::InvalidInput(
                "Overall relevance score must be between 0.0 and 1.0".to_string()
            ));
        }
        
        if self.confidence_score < 0.0 || self.confidence_score > 1.0 {
            return Err(AppError::InvalidInput(
                "Confidence score must be between 0.0 and 1.0".to_string()
            ));
        }
        
        // Validate individual factors
        let factors = vec![
            &self.entity_name_relevance,
            &self.current_state_relevance,
            &self.timeline_relevance,
            &self.semantic_relevance,
            &self.query_type_relevance,
            &self.temporal_relevance,
        ];
        
        let mut total_weight = 0.0;
        
        for (i, factor) in factors.iter().enumerate() {
            if factor.score < 0.0 || factor.score > 1.0 {
                return Err(AppError::InvalidInput(
                    format!("Factor {} score must be between 0.0 and 1.0", i)
                ));
            }
            
            if factor.weight < 0.0 || factor.weight > 1.0 {
                return Err(AppError::InvalidInput(
                    format!("Factor {} weight must be between 0.0 and 1.0", i)
                ));
            }
            
            if factor.reasoning.trim().is_empty() {
                return Err(AppError::InvalidInput(
                    format!("Factor {} reasoning cannot be empty", i)
                ));
            }
            
            total_weight += factor.weight;
        }
        
        // Weights should sum to approximately 1.0
        if (total_weight - 1.0).abs() > 0.1 {
            return Err(AppError::InvalidInput(
                format!("Factor weights should sum to approximately 1.0, got {}", total_weight)
            ));
        }
        
        // Explanation should not be empty
        if self.relevance_explanation.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "Relevance explanation cannot be empty".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Calculate the weighted overall score from individual factors
    pub fn calculate_weighted_score(&self) -> f32 {
        let factors = vec![
            (&self.entity_name_relevance, "entity_name"),
            (&self.current_state_relevance, "current_state"),
            (&self.timeline_relevance, "timeline"),
            (&self.semantic_relevance, "semantic"),
            (&self.query_type_relevance, "query_type"),
            (&self.temporal_relevance, "temporal"),
        ];
        
        let mut weighted_score = 0.0;
        
        for (factor, name) in factors {
            let contribution = factor.score * factor.weight;
            tracing::debug!("{} contribution: {:.3} (score: {:.3}, weight: {:.3})", 
                           name, contribution, factor.score, factor.weight);
            weighted_score += contribution;
        }
        
        weighted_score.min(1.0).max(0.0)
    }
}