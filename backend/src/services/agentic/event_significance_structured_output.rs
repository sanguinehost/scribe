// backend/src/services/agentic/event_significance_structured_output.rs
//
// Structured output definitions for AI-driven event significance scoring
//
// This module provides the structured output schema for analyzing chronicle events
// and calculating significance scores using AI models (Flash/Flash-Lite).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;
use crate::errors::AppError;

/// Structured output for event significance analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSignificanceOutput {
    /// Analysis of different significance factors
    pub significance_factors: Vec<SignificanceFactor>,
    
    /// Overall significance score (0.0-1.0)
    pub overall_significance: f32,
    
    /// Confidence in the significance assessment (0.0-1.0)
    pub confidence_score: f32,
    
    /// Detailed analysis explaining the significance score
    pub significance_analysis: SignificanceAnalysis,
    
    /// Justification for the significance score
    pub justification: String,
}

/// Individual significance factor analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignificanceFactor {
    /// Factor name (e.g., "event_type", "entity_role", "complexity", "recency", "participant_count")
    pub factor_name: String,
    
    /// Factor description
    pub factor_description: String,
    
    /// Score for this factor (0.0-1.0)
    pub factor_score: f32,
    
    /// Weight assigned to this factor (0.0-1.0)
    pub factor_weight: f32,
    
    /// Weighted contribution to overall score
    pub weighted_contribution: f32,
    
    /// Evidence supporting this factor's score
    pub evidence: Vec<String>,
    
    /// Confidence in this factor's assessment (0.0-1.0)
    pub confidence: f32,
}

/// Comprehensive significance analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignificanceAnalysis {
    /// Event type and its narrative impact
    pub event_type_impact: EventTypeImpact,
    
    /// Entity's role and involvement in the event
    pub entity_role_analysis: EntityRoleAnalysis,
    
    /// Event complexity and information richness
    pub complexity_assessment: ComplexityAssessment,
    
    /// Temporal relevance and recency factors
    pub temporal_relevance: TemporalRelevance,
    
    /// Social and network significance
    pub social_significance: SocialSignificance,
    
    /// Narrative and world-building impact
    pub narrative_impact: NarrativeImpact,
}

/// Analysis of event type's inherent significance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventTypeImpact {
    /// Event type category
    pub event_type: String,
    
    /// Significance category (e.g., "critical", "high", "medium", "low")
    pub significance_category: String,
    
    /// Impact on world state
    pub world_state_impact: String,
    
    /// Impact on character development
    pub character_impact: String,
    
    /// Long-term consequences
    pub long_term_consequences: Vec<String>,
}

/// Analysis of entity's role in the event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityRoleAnalysis {
    /// Entity's primary role (e.g., "protagonist", "antagonist", "observer", "victim")
    pub primary_role: String,
    
    /// Level of agency in the event (0.0-1.0)
    pub agency_level: f32,
    
    /// Impact on the entity (0.0-1.0)
    pub impact_on_entity: f32,
    
    /// Role in the narrative
    pub narrative_role: String,
    
    /// Specific actions taken by the entity
    pub entity_actions: Vec<String>,
}

/// Assessment of event complexity and information richness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplexityAssessment {
    /// Information density (0.0-1.0)
    pub information_density: f32,
    
    /// Narrative complexity (0.0-1.0)
    pub narrative_complexity: f32,
    
    /// Number of distinct elements/concepts
    pub element_count: u32,
    
    /// Quality of descriptive detail
    pub descriptive_quality: String,
    
    /// Complexity indicators
    pub complexity_indicators: Vec<String>,
}

/// Temporal relevance and recency analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalRelevance {
    /// Recency score (0.0-1.0)
    pub recency_score: f32,
    
    /// Temporal context importance
    pub temporal_context: String,
    
    /// Time-sensitive factors
    pub time_sensitive_factors: Vec<String>,
    
    /// Historical significance
    pub historical_significance: f32,
}

/// Social and network significance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialSignificance {
    /// Number of participants
    pub participant_count: u32,
    
    /// Network centrality (0.0-1.0)
    pub network_centrality: f32,
    
    /// Relationship impacts
    pub relationship_impacts: Vec<String>,
    
    /// Social ripple effects
    pub social_ripple_effects: Vec<String>,
}

/// Narrative and world-building impact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeImpact {
    /// Plot significance (0.0-1.0)
    pub plot_significance: f32,
    
    /// Character development impact (0.0-1.0)
    pub character_development: f32,
    
    /// World-building contribution (0.0-1.0)
    pub world_building: f32,
    
    /// Thematic relevance
    pub thematic_relevance: Vec<String>,
    
    /// Narrative consequences
    pub narrative_consequences: Vec<String>,
}

impl EventSignificanceOutput {
    /// Validate the output structure and values
    pub fn validate(&self) -> Result<(), AppError> {
        // Validate overall significance score
        if self.overall_significance < 0.0 || self.overall_significance > 1.0 {
            return Err(AppError::BadRequest(
                "Overall significance score must be between 0.0 and 1.0".to_string()
            ));
        }
        
        // Validate confidence score
        if self.confidence_score < 0.0 || self.confidence_score > 1.0 {
            return Err(AppError::BadRequest(
                "Confidence score must be between 0.0 and 1.0".to_string()
            ));
        }
        
        // Validate significance factors
        for factor in &self.significance_factors {
            if factor.factor_score < 0.0 || factor.factor_score > 1.0 {
                return Err(AppError::BadRequest(
                    format!("Factor score for {} must be between 0.0 and 1.0", factor.factor_name)
                ));
            }
            
            if factor.factor_weight < 0.0 || factor.factor_weight > 1.0 {
                return Err(AppError::BadRequest(
                    format!("Factor weight for {} must be between 0.0 and 1.0", factor.factor_name)
                ));
            }
            
            if factor.confidence < 0.0 || factor.confidence > 1.0 {
                return Err(AppError::BadRequest(
                    format!("Factor confidence for {} must be between 0.0 and 1.0", factor.factor_name)
                ));
            }
        }
        
        // Validate weights sum to approximately 1.0
        let weight_sum: f32 = self.significance_factors.iter().map(|f| f.factor_weight).sum();
        if (weight_sum - 1.0).abs() > 0.1 {
            return Err(AppError::BadRequest(
                format!("Factor weights should sum to approximately 1.0, got {:.3}", weight_sum)
            ));
        }
        
        // Validate required fields
        if self.justification.trim().is_empty() {
            return Err(AppError::BadRequest(
                "Justification cannot be empty".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Calculate weighted significance score from factors
    pub fn calculate_weighted_score(&self) -> f32 {
        self.significance_factors.iter()
            .map(|factor| factor.weighted_contribution)
            .sum::<f32>()
            .min(1.0)
            .max(0.0)
    }
    
    /// Get the most significant factors
    pub fn get_top_factors(&self, count: usize) -> Vec<&SignificanceFactor> {
        let mut factors = self.significance_factors.iter().collect::<Vec<_>>();
        factors.sort_by(|a, b| b.weighted_contribution.partial_cmp(&a.weighted_contribution).unwrap());
        factors.into_iter().take(count).collect()
    }
    
    /// Get significance category based on score
    pub fn get_significance_category(&self) -> &'static str {
        match self.overall_significance {
            score if score >= 0.8 => "Critical",
            score if score >= 0.6 => "High",
            score if score >= 0.4 => "Medium",
            score if score >= 0.2 => "Low",
            _ => "Minimal"
        }
    }
}

/// Create the JSON schema for event significance analysis
pub fn get_event_significance_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "significance_factors": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "factor_name": { "type": "string" },
                        "factor_description": { "type": "string" },
                        "factor_score": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                        "factor_weight": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                        "weighted_contribution": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                        "evidence": { "type": "array", "items": { "type": "string" } },
                        "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 }
                    },
                    "required": ["factor_name", "factor_description", "factor_score", "factor_weight", "weighted_contribution", "evidence", "confidence"]
                },
                "minItems": 1
            },
            "overall_significance": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
            "confidence_score": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
            "significance_analysis": {
                "type": "object",
                "properties": {
                    "event_type_impact": {
                        "type": "object",
                        "properties": {
                            "event_type": { "type": "string" },
                            "significance_category": { "type": "string" },
                            "world_state_impact": { "type": "string" },
                            "character_impact": { "type": "string" },
                            "long_term_consequences": { "type": "array", "items": { "type": "string" } }
                        },
                        "required": ["event_type", "significance_category", "world_state_impact", "character_impact", "long_term_consequences"]
                    },
                    "entity_role_analysis": {
                        "type": "object",
                        "properties": {
                            "primary_role": { "type": "string" },
                            "agency_level": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                            "impact_on_entity": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                            "narrative_role": { "type": "string" },
                            "entity_actions": { "type": "array", "items": { "type": "string" } }
                        },
                        "required": ["primary_role", "agency_level", "impact_on_entity", "narrative_role", "entity_actions"]
                    },
                    "complexity_assessment": {
                        "type": "object",
                        "properties": {
                            "information_density": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                            "narrative_complexity": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                            "element_count": { "type": "integer", "minimum": 0 },
                            "descriptive_quality": { "type": "string" },
                            "complexity_indicators": { "type": "array", "items": { "type": "string" } }
                        },
                        "required": ["information_density", "narrative_complexity", "element_count", "descriptive_quality", "complexity_indicators"]
                    },
                    "temporal_relevance": {
                        "type": "object",
                        "properties": {
                            "recency_score": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                            "temporal_context": { "type": "string" },
                            "time_sensitive_factors": { "type": "array", "items": { "type": "string" } },
                            "historical_significance": { "type": "number", "minimum": 0.0, "maximum": 1.0 }
                        },
                        "required": ["recency_score", "temporal_context", "time_sensitive_factors", "historical_significance"]
                    },
                    "social_significance": {
                        "type": "object",
                        "properties": {
                            "participant_count": { "type": "integer", "minimum": 0 },
                            "network_centrality": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                            "relationship_impacts": { "type": "array", "items": { "type": "string" } },
                            "social_ripple_effects": { "type": "array", "items": { "type": "string" } }
                        },
                        "required": ["participant_count", "network_centrality", "relationship_impacts", "social_ripple_effects"]
                    },
                    "narrative_impact": {
                        "type": "object",
                        "properties": {
                            "plot_significance": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                            "character_development": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                            "world_building": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                            "thematic_relevance": { "type": "array", "items": { "type": "string" } },
                            "narrative_consequences": { "type": "array", "items": { "type": "string" } }
                        },
                        "required": ["plot_significance", "character_development", "world_building", "thematic_relevance", "narrative_consequences"]
                    }
                },
                "required": ["event_type_impact", "entity_role_analysis", "complexity_assessment", "temporal_relevance", "social_significance", "narrative_impact"]
            },
            "justification": { "type": "string" }
        },
        "required": ["significance_factors", "overall_significance", "confidence_score", "significance_analysis", "justification"]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    
    #[test]
    fn test_event_significance_validation() {
        let valid_output = EventSignificanceOutput {
            significance_factors: vec![
                SignificanceFactor {
                    factor_name: "event_type".to_string(),
                    factor_description: "Event type significance".to_string(),
                    factor_score: 0.8,
                    factor_weight: 0.3,
                    weighted_contribution: 0.24,
                    evidence: vec!["Combat event".to_string()],
                    confidence: 0.9,
                },
                SignificanceFactor {
                    factor_name: "entity_role".to_string(),
                    factor_description: "Entity role in event".to_string(),
                    factor_score: 0.9,
                    factor_weight: 0.3,
                    weighted_contribution: 0.27,
                    evidence: vec!["Primary actor".to_string()],
                    confidence: 0.85,
                },
                SignificanceFactor {
                    factor_name: "complexity".to_string(),
                    factor_description: "Event complexity".to_string(),
                    factor_score: 0.6,
                    factor_weight: 0.4,
                    weighted_contribution: 0.24,
                    evidence: vec!["Detailed description".to_string()],
                    confidence: 0.8,
                },
            ],
            overall_significance: 0.75,
            confidence_score: 0.85,
            significance_analysis: SignificanceAnalysis {
                event_type_impact: EventTypeImpact {
                    event_type: "combat".to_string(),
                    significance_category: "high".to_string(),
                    world_state_impact: "Territory control change".to_string(),
                    character_impact: "Health and reputation effects".to_string(),
                    long_term_consequences: vec!["Ongoing conflict".to_string()],
                },
                entity_role_analysis: EntityRoleAnalysis {
                    primary_role: "protagonist".to_string(),
                    agency_level: 0.9,
                    impact_on_entity: 0.8,
                    narrative_role: "hero".to_string(),
                    entity_actions: vec!["attacked", "defended"].iter().map(|s| s.to_string()).collect(),
                },
                complexity_assessment: ComplexityAssessment {
                    information_density: 0.7,
                    narrative_complexity: 0.8,
                    element_count: 5,
                    descriptive_quality: "detailed".to_string(),
                    complexity_indicators: vec!["Multiple actors".to_string()],
                },
                temporal_relevance: TemporalRelevance {
                    recency_score: 0.9,
                    temporal_context: "Recent event".to_string(),
                    time_sensitive_factors: vec!["Immediate consequences".to_string()],
                    historical_significance: 0.6,
                },
                social_significance: SocialSignificance {
                    participant_count: 3,
                    network_centrality: 0.8,
                    relationship_impacts: vec!["Alliance strain".to_string()],
                    social_ripple_effects: vec!["Reputation change".to_string()],
                },
                narrative_impact: NarrativeImpact {
                    plot_significance: 0.8,
                    character_development: 0.7,
                    world_building: 0.6,
                    thematic_relevance: vec!["Conflict theme".to_string()],
                    narrative_consequences: vec!["Story progression".to_string()],
                },
            },
            justification: "High significance due to combat nature and protagonist involvement".to_string(),
        };
        
        assert!(valid_output.validate().is_ok());
        
        let calculated_score = valid_output.calculate_weighted_score();
        assert!(calculated_score >= 0.0 && calculated_score <= 1.0);
        
        let category = valid_output.get_significance_category();
        assert_eq!(category, "High");
    }
    
    #[test]
    fn test_invalid_significance_scores() {
        let mut invalid_output = EventSignificanceOutput {
            significance_factors: vec![
                SignificanceFactor {
                    factor_name: "test".to_string(),
                    factor_description: "Test".to_string(),
                    factor_score: 1.5, // Invalid: > 1.0
                    factor_weight: 0.5,
                    weighted_contribution: 0.75,
                    evidence: vec![],
                    confidence: 0.8,
                },
                SignificanceFactor {
                    factor_name: "test2".to_string(),
                    factor_description: "Test2".to_string(),
                    factor_score: 0.5,
                    factor_weight: 0.5,
                    weighted_contribution: 0.25,
                    evidence: vec![],
                    confidence: 0.8,
                },
            ],
            overall_significance: 0.75,
            confidence_score: 0.85,
            significance_analysis: SignificanceAnalysis {
                event_type_impact: EventTypeImpact {
                    event_type: "test".to_string(),
                    significance_category: "medium".to_string(),
                    world_state_impact: "test".to_string(),
                    character_impact: "test".to_string(),
                    long_term_consequences: vec![],
                },
                entity_role_analysis: EntityRoleAnalysis {
                    primary_role: "test".to_string(),
                    agency_level: 0.5,
                    impact_on_entity: 0.5,
                    narrative_role: "test".to_string(),
                    entity_actions: vec![],
                },
                complexity_assessment: ComplexityAssessment {
                    information_density: 0.5,
                    narrative_complexity: 0.5,
                    element_count: 1,
                    descriptive_quality: "test".to_string(),
                    complexity_indicators: vec![],
                },
                temporal_relevance: TemporalRelevance {
                    recency_score: 0.5,
                    temporal_context: "test".to_string(),
                    time_sensitive_factors: vec![],
                    historical_significance: 0.5,
                },
                social_significance: SocialSignificance {
                    participant_count: 1,
                    network_centrality: 0.5,
                    relationship_impacts: vec![],
                    social_ripple_effects: vec![],
                },
                narrative_impact: NarrativeImpact {
                    plot_significance: 0.5,
                    character_development: 0.5,
                    world_building: 0.5,
                    thematic_relevance: vec![],
                    narrative_consequences: vec![],
                },
            },
            justification: "Test justification".to_string(),
        };
        
        assert!(invalid_output.validate().is_err());
    }
    
    #[test]
    fn test_top_factors() {
        let output = EventSignificanceOutput {
            significance_factors: vec![
                SignificanceFactor {
                    factor_name: "low".to_string(),
                    factor_description: "Low impact".to_string(),
                    factor_score: 0.3,
                    factor_weight: 0.2,
                    weighted_contribution: 0.06,
                    evidence: vec![],
                    confidence: 0.8,
                },
                SignificanceFactor {
                    factor_name: "high".to_string(),
                    factor_description: "High impact".to_string(),
                    factor_score: 0.9,
                    factor_weight: 0.4,
                    weighted_contribution: 0.36,
                    evidence: vec![],
                    confidence: 0.9,
                },
                SignificanceFactor {
                    factor_name: "medium".to_string(),
                    factor_description: "Medium impact".to_string(),
                    factor_score: 0.6,
                    factor_weight: 0.4,
                    weighted_contribution: 0.24,
                    evidence: vec![],
                    confidence: 0.85,
                },
            ],
            overall_significance: 0.66,
            confidence_score: 0.85,
            significance_analysis: SignificanceAnalysis {
                event_type_impact: EventTypeImpact {
                    event_type: "test".to_string(),
                    significance_category: "medium".to_string(),
                    world_state_impact: "test".to_string(),
                    character_impact: "test".to_string(),
                    long_term_consequences: vec![],
                },
                entity_role_analysis: EntityRoleAnalysis {
                    primary_role: "test".to_string(),
                    agency_level: 0.5,
                    impact_on_entity: 0.5,
                    narrative_role: "test".to_string(),
                    entity_actions: vec![],
                },
                complexity_assessment: ComplexityAssessment {
                    information_density: 0.5,
                    narrative_complexity: 0.5,
                    element_count: 1,
                    descriptive_quality: "test".to_string(),
                    complexity_indicators: vec![],
                },
                temporal_relevance: TemporalRelevance {
                    recency_score: 0.5,
                    temporal_context: "test".to_string(),
                    time_sensitive_factors: vec![],
                    historical_significance: 0.5,
                },
                social_significance: SocialSignificance {
                    participant_count: 1,
                    network_centrality: 0.5,
                    relationship_impacts: vec![],
                    social_ripple_effects: vec![],
                },
                narrative_impact: NarrativeImpact {
                    plot_significance: 0.5,
                    character_development: 0.5,
                    world_building: 0.5,
                    thematic_relevance: vec![],
                    narrative_consequences: vec![],
                },
            },
            justification: "Test justification".to_string(),
        };
        
        let top_factors = output.get_top_factors(2);
        assert_eq!(top_factors.len(), 2);
        assert_eq!(top_factors[0].factor_name, "high");
        assert_eq!(top_factors[1].factor_name, "medium");
    }
}