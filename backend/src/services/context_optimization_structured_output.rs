use serde::{Deserialize, Serialize};
use crate::errors::AppError;

/// Structured output schema for context optimization service
/// This ensures AI always generates valid JSON with proper types

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextOptimizationOutput {
    pub optimization_reasoning: String,
    pub optimization_strategy: String, // Will be validated against enum values
    pub total_estimated_tokens: u32,
    pub optimized_entities: Vec<OptimizedEntityOutput>,
    pub pruned_content: Vec<PrunedContentOutput>,
    pub suggested_refinements: Vec<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizedEntityOutput {
    pub entity_id: String,
    pub name: String,
    pub priority_score: f32,
    pub inclusion_reason: String,
    pub token_contribution: u32,
    pub narrative_relevance: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrunedContentOutput {
    pub content_type: String,
    pub entity_name: String,
    pub reason: String,
    pub tokens_saved: u32,
    pub pruning_confidence: f32,
}

/// Helper function to create the JSON schema for structured output
pub fn get_context_optimization_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "optimization_reasoning": {
                "type": "string",
                "maxLength": 300,
                "description": "Concise explanation of optimization approach"
            },
            "optimization_strategy": {
                "type": "string",
                "enum": [
                    "EntityPrioritization",
                    "TemporalFiltering",
                    "RelevanceClustering",
                    "CausalPathFocus",
                    "SpatialContextPrioritization",
                    "TokenBudgetConstraint",
                    "ConservativePruning",
                    "AdaptiveOptimization",
                    "NarrativeCoherence",
                    "EmotionalResonance",
                    "ActionPotential"
                ],
                "description": "The optimization strategy used"
            },
            "total_estimated_tokens": {
                "type": "integer",
                "minimum": 0,
                "description": "Estimated total tokens after optimization"
            },
            "optimized_entities": {
                "type": "array",
                "maxItems": 5,
                "items": {
                    "type": "object",
                    "properties": {
                        "entity_id": {
                            "type": "string",
                            "description": "Unique identifier for the entity"
                        },
                        "name": {
                            "type": "string",
                            "description": "Entity name"
                        },
                        "priority_score": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                            "description": "Priority score from 0.0 to 1.0"
                        },
                        "inclusion_reason": {
                            "type": "string",
                            "maxLength": 150,
                            "description": "Why this entity is essential"
                        },
                        "token_contribution": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Estimated tokens this entity contributes"
                        },
                        "narrative_relevance": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                            "description": "Relevance to current narrative context (0.0-1.0)"
                        }
                    },
                    "required": ["entity_id", "name", "priority_score", "inclusion_reason", "token_contribution", "narrative_relevance"]
                }
            },
            "pruned_content": {
                "type": "array",
                "maxItems": 5,
                "items": {
                    "type": "object",
                    "properties": {
                        "content_type": {
                            "type": "string",
                            "description": "Type of content pruned (entity|relationship|event|result_type)"
                        },
                        "entity_name": {
                            "type": "string",
                            "description": "Name of the pruned content"
                        },
                        "reason": {
                            "type": "string",
                            "maxLength": 150,
                            "description": "Why this content was pruned"
                        },
                        "tokens_saved": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Number of tokens saved by pruning"
                        },
                        "pruning_confidence": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                            "description": "Confidence in this pruning decision (0.0-1.0)"
                        }
                    },
                    "required": ["content_type", "entity_name", "reason", "tokens_saved", "pruning_confidence"]
                }
            },
            "suggested_refinements": {
                "type": "array",
                "maxItems": 2,
                "items": {
                    "type": "string",
                    "maxLength": 100
                },
                "description": "Potential optimization improvements"
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Overall confidence in the optimization (0.0-1.0)"
            }
        },
        "required": ["optimization_reasoning", "optimization_strategy", "total_estimated_tokens", "optimized_entities", "pruned_content", "suggested_refinements", "confidence"]
    })
}

/// Convert structured output to internal ContextOptimization type
impl ContextOptimizationOutput {
    pub fn to_context_optimization(&self) -> Result<super::ContextOptimization, AppError> {
        use super::{ContextOptimization, OptimizedEntity, PrunedContent, OptimizationStrategy};
        
        // Parse optimization strategy
        let optimization_strategy = match self.optimization_strategy.as_str() {
            "EntityPrioritization" => OptimizationStrategy::EntityPrioritization,
            "TemporalFiltering" => OptimizationStrategy::TemporalFiltering,
            "RelevanceClustering" => OptimizationStrategy::RelevanceClustering,
            "CausalPathFocus" => OptimizationStrategy::CausalPathFocus,
            "SpatialContextPrioritization" => OptimizationStrategy::SpatialContextPrioritization,
            "TokenBudgetConstraint" => OptimizationStrategy::TokenBudgetConstraint,
            "ConservativePruning" => OptimizationStrategy::ConservativePruning,
            "AdaptiveOptimization" => OptimizationStrategy::AdaptiveOptimization,
            "NarrativeCoherence" => OptimizationStrategy::NarrativeCoherence,
            "EmotionalResonance" => OptimizationStrategy::EmotionalResonance,
            "ActionPotential" => OptimizationStrategy::ActionPotential,
            _ => return Err(AppError::InvalidInput(
                format!("Invalid optimization strategy: {}", self.optimization_strategy)
            )),
        };
        
        // Convert optimized entities
        let optimized_entities = self.optimized_entities.iter().map(|e| OptimizedEntity {
            entity_id: e.entity_id.clone(),
            name: e.name.clone(),
            priority_score: e.priority_score,
            inclusion_reason: e.inclusion_reason.clone(),
            token_contribution: e.token_contribution,
            narrative_relevance: e.narrative_relevance,
        }).collect();
        
        // Convert pruned content
        let pruned_content = self.pruned_content.iter().map(|p| PrunedContent {
            content_type: p.content_type.clone(),
            entity_name: p.entity_name.clone(),
            reason: p.reason.clone(),
            tokens_saved: p.tokens_saved,
            pruning_confidence: p.pruning_confidence,
        }).collect();
        
        Ok(ContextOptimization {
            total_estimated_tokens: self.total_estimated_tokens,
            optimized_entities,
            pruned_content,
            optimization_strategy,
            confidence: self.confidence,
            optimization_reasoning: self.optimization_reasoning.clone(),
            suggested_refinements: self.suggested_refinements.clone(),
        })
    }
}

/// Validation for structured output
impl ContextOptimizationOutput {
    pub fn validate(&self) -> Result<(), AppError> {
        if self.optimization_reasoning.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "Optimization reasoning cannot be empty".to_string()
            ));
        }
        
        // Validate strategy is one of the allowed values
        let valid_strategies = [
            "EntityPrioritization", "TemporalFiltering", "RelevanceClustering",
            "CausalPathFocus", "SpatialContextPrioritization", "TokenBudgetConstraint",
            "ConservativePruning", "AdaptiveOptimization", "NarrativeCoherence",
            "EmotionalResonance", "ActionPotential"
        ];
        
        if !valid_strategies.contains(&self.optimization_strategy.as_str()) {
            return Err(AppError::InvalidInput(
                format!("Invalid optimization strategy: {}", self.optimization_strategy)
            ));
        }
        
        // Validate confidence is in range
        if self.confidence < 0.0 || self.confidence > 1.0 {
            return Err(AppError::InvalidInput(
                format!("Confidence must be between 0.0 and 1.0, got: {}", self.confidence)
            ));
        }
        
        // Validate all priority scores and relevance scores
        for entity in &self.optimized_entities {
            if entity.priority_score < 0.0 || entity.priority_score > 1.0 {
                return Err(AppError::InvalidInput(
                    format!("Priority score must be between 0.0 and 1.0 for entity: {}", entity.name)
                ));
            }
            if entity.narrative_relevance < 0.0 || entity.narrative_relevance > 1.0 {
                return Err(AppError::InvalidInput(
                    format!("Narrative relevance must be between 0.0 and 1.0 for entity: {}", entity.name)
                ));
            }
        }
        
        // Validate pruning confidence scores
        for pruned in &self.pruned_content {
            if pruned.pruning_confidence < 0.0 || pruned.pruning_confidence > 1.0 {
                return Err(AppError::InvalidInput(
                    format!("Pruning confidence must be between 0.0 and 1.0 for: {}", pruned.entity_name)
                ));
            }
        }
        
        Ok(())
    }
}