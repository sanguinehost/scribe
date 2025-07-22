// backend/src/services/agentic/relationship_analysis_structured_output.rs
//
// Structured output definitions for AI-driven relationship analysis
//
// This module provides the structured output schema for analyzing relationships
// between entities using AI models (Flash/Flash-Lite).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::errors::AppError;

/// Structured output for relationship analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipAnalysisOutput {
    /// Analysis of the relationship between two entities
    pub relationship_analysis: RelationshipAnalysisDetails,
    
    /// Metrics quantifying the relationship
    pub relationship_metrics: RelationshipMetricsOutput,
    
    /// Historical analysis of relationship changes
    pub relationship_history: RelationshipHistoryAnalysis,
    
    /// Confidence in the analysis (0.0-1.0)
    pub confidence_score: f32,
    
    /// Detailed justification for the analysis
    pub justification: String,
}

/// Detailed analysis of the relationship
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipAnalysisDetails {
    /// Type of relationship (e.g., "friendship", "rivalry", "family", "professional", "romantic")
    pub relationship_type: String,
    
    /// Current status of the relationship
    pub current_status: String,
    
    /// Nature of the relationship
    pub relationship_nature: String,
    
    /// Key characteristics of the relationship
    pub key_characteristics: Vec<String>,
    
    /// Power dynamics in the relationship
    pub power_dynamics: PowerDynamicsAnalysis,
    
    /// Communication patterns
    pub communication_patterns: CommunicationPatternAnalysis,
    
    /// Emotional dynamics
    pub emotional_dynamics: EmotionalDynamicsAnalysis,
    
    /// Trust and loyalty factors
    pub trust_loyalty: TrustLoyaltyAnalysis,
}

/// Power dynamics analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerDynamicsAnalysis {
    /// Power balance (0.0 = entity A dominant, 0.5 = balanced, 1.0 = entity B dominant)
    pub power_balance: f32,
    
    /// Authority structure
    pub authority_structure: String,
    
    /// Influence patterns
    pub influence_patterns: Vec<String>,
    
    /// Decision-making dynamics
    pub decision_making: String,
}

/// Communication patterns analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunicationPatternAnalysis {
    /// Communication frequency (0.0-1.0)
    pub frequency: f32,
    
    /// Communication quality (0.0-1.0)
    pub quality: f32,
    
    /// Directness of communication (0.0-1.0)
    pub directness: f32,
    
    /// Conflict resolution style
    pub conflict_resolution: String,
    
    /// Common communication themes
    pub common_themes: Vec<String>,
}

/// Emotional dynamics analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmotionalDynamicsAnalysis {
    /// Emotional intensity (0.0-1.0)
    pub intensity: f32,
    
    /// Emotional valence (-1.0 to 1.0, negative to positive)
    pub valence: f32,
    
    /// Emotional stability (0.0-1.0)
    pub stability: f32,
    
    /// Dominant emotions in the relationship
    pub dominant_emotions: Vec<String>,
    
    /// Emotional triggers
    pub emotional_triggers: Vec<String>,
}

/// Trust and loyalty analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustLoyaltyAnalysis {
    /// Trust level (0.0-1.0)
    pub trust_level: f32,
    
    /// Loyalty strength (0.0-1.0)
    pub loyalty_strength: f32,
    
    /// Reliability assessment (0.0-1.0)
    pub reliability: f32,
    
    /// Commitment level (0.0-1.0)
    pub commitment: f32,
    
    /// Factors affecting trust
    pub trust_factors: Vec<String>,
}

/// Quantitative relationship metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipMetricsOutput {
    /// Overall relationship strength (0.0-1.0)
    pub strength: f32,
    
    /// Relationship stability (0.0-1.0)
    pub stability: f32,
    
    /// Interaction frequency (0.0-1.0)
    pub interaction_frequency: f32,
    
    /// Relationship trend
    pub trend: RelationshipTrendOutput,
    
    /// Interaction quality (0.0-1.0)
    pub interaction_quality: f32,
    
    /// Mutual dependence (0.0-1.0)
    pub mutual_dependence: f32,
}

/// Relationship trend analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipTrendOutput {
    /// Trend direction
    pub direction: String, // "improving", "declining", "stable", "volatile", "unknown"
    
    /// Trend strength (0.0-1.0)
    pub strength: f32,
    
    /// Trend confidence (0.0-1.0)
    pub confidence: f32,
    
    /// Factors driving the trend
    pub driving_factors: Vec<String>,
    
    /// Predicted future direction
    pub predicted_direction: String,
}

/// Historical relationship analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipHistoryAnalysis {
    /// Key phases in the relationship
    pub relationship_phases: Vec<RelationshipPhase>,
    
    /// Turning points in the relationship
    pub turning_points: Vec<TurningPoint>,
    
    /// Relationship milestones
    pub milestones: Vec<RelationshipMilestone>,
    
    /// Patterns of change
    pub change_patterns: Vec<String>,
    
    /// Cyclical behaviors
    pub cyclical_behaviors: Vec<String>,
}

/// A distinct phase in the relationship
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipPhase {
    /// Phase name/description
    pub phase_name: String,
    
    /// Phase duration description
    pub duration: String,
    
    /// Characteristics of this phase
    pub characteristics: Vec<String>,
    
    /// Key events in this phase
    pub key_events: Vec<String>,
    
    /// Relationship strength during this phase (0.0-1.0)
    pub strength_level: f32,
}

/// A significant turning point in the relationship
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurningPoint {
    /// Event or moment that caused the turning point
    pub trigger_event: String,
    
    /// Impact of the turning point
    pub impact_description: String,
    
    /// Type of change (e.g., "strengthening", "weakening", "transformation")
    pub change_type: String,
    
    /// Significance of the turning point (0.0-1.0)
    pub significance: f32,
    
    /// Long-term effects
    pub long_term_effects: Vec<String>,
}

/// A significant milestone in the relationship
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipMilestone {
    /// Description of the milestone
    pub milestone_description: String,
    
    /// Type of milestone
    pub milestone_type: String,
    
    /// Importance of the milestone (0.0-1.0)
    pub importance: f32,
    
    /// Impact on the relationship
    pub impact: String,
}

impl RelationshipAnalysisOutput {
    /// Validate the output structure and values
    pub fn validate(&self) -> Result<(), AppError> {
        // Validate confidence score
        if self.confidence_score < 0.0 || self.confidence_score > 1.0 {
            return Err(AppError::BadRequest(
                "Confidence score must be between 0.0 and 1.0".to_string()
            ));
        }
        
        // Validate relationship metrics
        let metrics = &self.relationship_metrics;
        if metrics.strength < 0.0 || metrics.strength > 1.0 {
            return Err(AppError::BadRequest(
                "Relationship strength must be between 0.0 and 1.0".to_string()
            ));
        }
        
        if metrics.stability < 0.0 || metrics.stability > 1.0 {
            return Err(AppError::BadRequest(
                "Relationship stability must be between 0.0 and 1.0".to_string()
            ));
        }
        
        if metrics.interaction_frequency < 0.0 || metrics.interaction_frequency > 1.0 {
            return Err(AppError::BadRequest(
                "Interaction frequency must be between 0.0 and 1.0".to_string()
            ));
        }
        
        if metrics.interaction_quality < 0.0 || metrics.interaction_quality > 1.0 {
            return Err(AppError::BadRequest(
                "Interaction quality must be between 0.0 and 1.0".to_string()
            ));
        }
        
        if metrics.mutual_dependence < 0.0 || metrics.mutual_dependence > 1.0 {
            return Err(AppError::BadRequest(
                "Mutual dependence must be between 0.0 and 1.0".to_string()
            ));
        }
        
        // Validate trend strength and confidence
        if metrics.trend.strength < 0.0 || metrics.trend.strength > 1.0 {
            return Err(AppError::BadRequest(
                "Trend strength must be between 0.0 and 1.0".to_string()
            ));
        }
        
        if metrics.trend.confidence < 0.0 || metrics.trend.confidence > 1.0 {
            return Err(AppError::BadRequest(
                "Trend confidence must be between 0.0 and 1.0".to_string()
            ));
        }
        
        // Validate emotional dynamics
        let emotions = &self.relationship_analysis.emotional_dynamics;
        if emotions.intensity < 0.0 || emotions.intensity > 1.0 {
            return Err(AppError::BadRequest(
                "Emotional intensity must be between 0.0 and 1.0".to_string()
            ));
        }
        
        if emotions.valence < -1.0 || emotions.valence > 1.0 {
            return Err(AppError::BadRequest(
                "Emotional valence must be between -1.0 and 1.0".to_string()
            ));
        }
        
        if emotions.stability < 0.0 || emotions.stability > 1.0 {
            return Err(AppError::BadRequest(
                "Emotional stability must be between 0.0 and 1.0".to_string()
            ));
        }
        
        // Validate power dynamics
        let power = &self.relationship_analysis.power_dynamics;
        if power.power_balance < 0.0 || power.power_balance > 1.0 {
            return Err(AppError::BadRequest(
                "Power balance must be between 0.0 and 1.0".to_string()
            ));
        }
        
        // Validate communication patterns
        let comm = &self.relationship_analysis.communication_patterns;
        if comm.frequency < 0.0 || comm.frequency > 1.0 {
            return Err(AppError::BadRequest(
                "Communication frequency must be between 0.0 and 1.0".to_string()
            ));
        }
        
        if comm.quality < 0.0 || comm.quality > 1.0 {
            return Err(AppError::BadRequest(
                "Communication quality must be between 0.0 and 1.0".to_string()
            ));
        }
        
        if comm.directness < 0.0 || comm.directness > 1.0 {
            return Err(AppError::BadRequest(
                "Communication directness must be between 0.0 and 1.0".to_string()
            ));
        }
        
        // Validate trust and loyalty
        let trust = &self.relationship_analysis.trust_loyalty;
        if trust.trust_level < 0.0 || trust.trust_level > 1.0 {
            return Err(AppError::BadRequest(
                "Trust level must be between 0.0 and 1.0".to_string()
            ));
        }
        
        if trust.loyalty_strength < 0.0 || trust.loyalty_strength > 1.0 {
            return Err(AppError::BadRequest(
                "Loyalty strength must be between 0.0 and 1.0".to_string()
            ));
        }
        
        if trust.reliability < 0.0 || trust.reliability > 1.0 {
            return Err(AppError::BadRequest(
                "Reliability must be between 0.0 and 1.0".to_string()
            ));
        }
        
        if trust.commitment < 0.0 || trust.commitment > 1.0 {
            return Err(AppError::BadRequest(
                "Commitment must be between 0.0 and 1.0".to_string()
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
    
    /// Get the relationship trend as a simple enum-like value
    pub fn get_relationship_trend(&self) -> &str {
        &self.relationship_metrics.trend.direction
    }
    
    /// Get the overall relationship assessment
    pub fn get_relationship_assessment(&self) -> &'static str {
        let strength = self.relationship_metrics.strength;
        let stability = self.relationship_metrics.stability;
        let avg_score = (strength + stability) / 2.0;
        
        match avg_score {
            score if score >= 0.8 => "Excellent",
            score if score >= 0.6 => "Good",
            score if score >= 0.4 => "Moderate",
            score if score >= 0.2 => "Weak",
            _ => "Poor"
        }
    }
    
    /// Get the most significant turning points
    pub fn get_significant_turning_points(&self) -> Vec<&TurningPoint> {
        let mut points = self.relationship_history.turning_points.iter().collect::<Vec<_>>();
        points.sort_by(|a, b| b.significance.partial_cmp(&a.significance).unwrap_or(std::cmp::Ordering::Equal));
        points.into_iter().take(3).collect()
    }
}

/// Create the JSON schema for relationship analysis
pub fn get_relationship_analysis_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "relationship_analysis": {
                "type": "object",
                "properties": {
                    "relationship_type": { "type": "string" },
                    "current_status": { "type": "string" },
                    "relationship_nature": { "type": "string" },
                    "key_characteristics": { "type": "array", "items": { "type": "string" } },
                    "power_dynamics": {
                        "type": "object",
                        "properties": {
                            "power_balance": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                            "authority_structure": { "type": "string" },
                            "influence_patterns": { "type": "array", "items": { "type": "string" } },
                            "decision_making": { "type": "string" }
                        },
                        "required": ["power_balance", "authority_structure", "influence_patterns", "decision_making"]
                    },
                    "communication_patterns": {
                        "type": "object",
                        "properties": {
                            "frequency": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                            "quality": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                            "directness": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                            "conflict_resolution": { "type": "string" },
                            "common_themes": { "type": "array", "items": { "type": "string" } }
                        },
                        "required": ["frequency", "quality", "directness", "conflict_resolution", "common_themes"]
                    },
                    "emotional_dynamics": {
                        "type": "object",
                        "properties": {
                            "intensity": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                            "valence": { "type": "number", "minimum": -1.0, "maximum": 1.0 },
                            "stability": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                            "dominant_emotions": { "type": "array", "items": { "type": "string" } },
                            "emotional_triggers": { "type": "array", "items": { "type": "string" } }
                        },
                        "required": ["intensity", "valence", "stability", "dominant_emotions", "emotional_triggers"]
                    },
                    "trust_loyalty": {
                        "type": "object",
                        "properties": {
                            "trust_level": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                            "loyalty_strength": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                            "reliability": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                            "commitment": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                            "trust_factors": { "type": "array", "items": { "type": "string" } }
                        },
                        "required": ["trust_level", "loyalty_strength", "reliability", "commitment", "trust_factors"]
                    }
                },
                "required": ["relationship_type", "current_status", "relationship_nature", "key_characteristics", "power_dynamics", "communication_patterns", "emotional_dynamics", "trust_loyalty"]
            },
            "relationship_metrics": {
                "type": "object",
                "properties": {
                    "strength": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                    "stability": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                    "interaction_frequency": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                    "interaction_quality": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                    "mutual_dependence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                    "trend": {
                        "type": "object",
                        "properties": {
                            "direction": { "type": "string", "enum": ["improving", "declining", "stable", "volatile", "unknown"] },
                            "strength": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                            "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                            "driving_factors": { "type": "array", "items": { "type": "string" } },
                            "predicted_direction": { "type": "string" }
                        },
                        "required": ["direction", "strength", "confidence", "driving_factors", "predicted_direction"]
                    }
                },
                "required": ["strength", "stability", "interaction_frequency", "interaction_quality", "mutual_dependence", "trend"]
            },
            "relationship_history": {
                "type": "object",
                "properties": {
                    "relationship_phases": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "phase_name": { "type": "string" },
                                "duration": { "type": "string" },
                                "characteristics": { "type": "array", "items": { "type": "string" } },
                                "key_events": { "type": "array", "items": { "type": "string" } },
                                "strength_level": { "type": "number", "minimum": 0.0, "maximum": 1.0 }
                            },
                            "required": ["phase_name", "duration", "characteristics", "key_events", "strength_level"]
                        }
                    },
                    "turning_points": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "trigger_event": { "type": "string" },
                                "impact_description": { "type": "string" },
                                "change_type": { "type": "string" },
                                "significance": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                                "long_term_effects": { "type": "array", "items": { "type": "string" } }
                            },
                            "required": ["trigger_event", "impact_description", "change_type", "significance", "long_term_effects"]
                        }
                    },
                    "milestones": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "milestone_description": { "type": "string" },
                                "milestone_type": { "type": "string" },
                                "importance": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                                "impact": { "type": "string" }
                            },
                            "required": ["milestone_description", "milestone_type", "importance", "impact"]
                        }
                    },
                    "change_patterns": { "type": "array", "items": { "type": "string" } },
                    "cyclical_behaviors": { "type": "array", "items": { "type": "string" } }
                },
                "required": ["relationship_phases", "turning_points", "milestones", "change_patterns", "cyclical_behaviors"]
            },
            "confidence_score": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
            "justification": { "type": "string" }
        },
        "required": ["relationship_analysis", "relationship_metrics", "relationship_history", "confidence_score", "justification"]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    
    #[test]
    fn test_relationship_analysis_validation() {
        let valid_output = RelationshipAnalysisOutput {
            relationship_analysis: RelationshipAnalysisDetails {
                relationship_type: "friendship".to_string(),
                current_status: "active".to_string(),
                relationship_nature: "close personal friendship".to_string(),
                key_characteristics: vec!["mutual respect".to_string(), "shared interests".to_string()],
                power_dynamics: PowerDynamicsAnalysis {
                    power_balance: 0.5,
                    authority_structure: "equal".to_string(),
                    influence_patterns: vec!["mutual influence".to_string()],
                    decision_making: "collaborative".to_string(),
                },
                communication_patterns: CommunicationPatternAnalysis {
                    frequency: 0.8,
                    quality: 0.9,
                    directness: 0.7,
                    conflict_resolution: "discussion".to_string(),
                    common_themes: vec!["shared goals".to_string()],
                },
                emotional_dynamics: EmotionalDynamicsAnalysis {
                    intensity: 0.6,
                    valence: 0.8,
                    stability: 0.9,
                    dominant_emotions: vec!["affection".to_string(), "trust".to_string()],
                    emotional_triggers: vec!["betrayal".to_string()],
                },
                trust_loyalty: TrustLoyaltyAnalysis {
                    trust_level: 0.9,
                    loyalty_strength: 0.8,
                    reliability: 0.9,
                    commitment: 0.7,
                    trust_factors: vec!["consistent behavior".to_string()],
                },
            },
            relationship_metrics: RelationshipMetricsOutput {
                strength: 0.8,
                stability: 0.9,
                interaction_frequency: 0.7,
                interaction_quality: 0.9,
                mutual_dependence: 0.6,
                trend: RelationshipTrendOutput {
                    direction: "improving".to_string(),
                    strength: 0.7,
                    confidence: 0.8,
                    driving_factors: vec!["shared experiences".to_string()],
                    predicted_direction: "continued improvement".to_string(),
                },
            },
            relationship_history: RelationshipHistoryAnalysis {
                relationship_phases: vec![
                    RelationshipPhase {
                        phase_name: "initial meeting".to_string(),
                        duration: "first month".to_string(),
                        characteristics: vec!["cautious".to_string()],
                        key_events: vec!["first encounter".to_string()],
                        strength_level: 0.3,
                    }
                ],
                turning_points: vec![
                    TurningPoint {
                        trigger_event: "shared challenge".to_string(),
                        impact_description: "strengthened bond".to_string(),
                        change_type: "strengthening".to_string(),
                        significance: 0.8,
                        long_term_effects: vec!["deeper trust".to_string()],
                    }
                ],
                milestones: vec![
                    RelationshipMilestone {
                        milestone_description: "first agreement".to_string(),
                        milestone_type: "cooperation".to_string(),
                        importance: 0.7,
                        impact: "positive".to_string(),
                    }
                ],
                change_patterns: vec!["gradual improvement".to_string()],
                cyclical_behaviors: vec!["periodic cooperation".to_string()],
            },
            confidence_score: 0.85,
            justification: "Strong evidence from multiple interactions showing consistent positive relationship patterns".to_string(),
        };
        
        assert!(valid_output.validate().is_ok());
        
        let assessment = valid_output.get_relationship_assessment();
        assert_eq!(assessment, "Excellent");
        
        let trend = valid_output.get_relationship_trend();
        assert_eq!(trend, "improving");
        
        let significant_points = valid_output.get_significant_turning_points();
        assert_eq!(significant_points.len(), 1);
        assert_eq!(significant_points[0].significance, 0.8);
    }
    
    #[test]
    fn test_invalid_relationship_metrics() {
        let mut invalid_output = RelationshipAnalysisOutput {
            relationship_analysis: RelationshipAnalysisDetails {
                relationship_type: "test".to_string(),
                current_status: "test".to_string(),
                relationship_nature: "test".to_string(),
                key_characteristics: vec!["test".to_string()],
                power_dynamics: PowerDynamicsAnalysis {
                    power_balance: 0.5,
                    authority_structure: "test".to_string(),
                    influence_patterns: vec!["test".to_string()],
                    decision_making: "test".to_string(),
                },
                communication_patterns: CommunicationPatternAnalysis {
                    frequency: 0.5,
                    quality: 0.5,
                    directness: 0.5,
                    conflict_resolution: "test".to_string(),
                    common_themes: vec!["test".to_string()],
                },
                emotional_dynamics: EmotionalDynamicsAnalysis {
                    intensity: 0.5,
                    valence: 0.5,
                    stability: 0.5,
                    dominant_emotions: vec!["test".to_string()],
                    emotional_triggers: vec!["test".to_string()],
                },
                trust_loyalty: TrustLoyaltyAnalysis {
                    trust_level: 0.5,
                    loyalty_strength: 0.5,
                    reliability: 0.5,
                    commitment: 0.5,
                    trust_factors: vec!["test".to_string()],
                },
            },
            relationship_metrics: RelationshipMetricsOutput {
                strength: 1.5, // Invalid: > 1.0
                stability: 0.5,
                interaction_frequency: 0.5,
                interaction_quality: 0.5,
                mutual_dependence: 0.5,
                trend: RelationshipTrendOutput {
                    direction: "stable".to_string(),
                    strength: 0.5,
                    confidence: 0.5,
                    driving_factors: vec!["test".to_string()],
                    predicted_direction: "test".to_string(),
                },
            },
            relationship_history: RelationshipHistoryAnalysis {
                relationship_phases: vec![],
                turning_points: vec![],
                milestones: vec![],
                change_patterns: vec![],
                cyclical_behaviors: vec![],
            },
            confidence_score: 0.5,
            justification: "Test justification".to_string(),
        };
        
        assert!(invalid_output.validate().is_err());
    }
    
    #[test]
    fn test_relationship_assessment_categories() {
        let mut output = RelationshipAnalysisOutput {
            relationship_analysis: RelationshipAnalysisDetails {
                relationship_type: "test".to_string(),
                current_status: "test".to_string(),
                relationship_nature: "test".to_string(),
                key_characteristics: vec!["test".to_string()],
                power_dynamics: PowerDynamicsAnalysis {
                    power_balance: 0.5,
                    authority_structure: "test".to_string(),
                    influence_patterns: vec!["test".to_string()],
                    decision_making: "test".to_string(),
                },
                communication_patterns: CommunicationPatternAnalysis {
                    frequency: 0.5,
                    quality: 0.5,
                    directness: 0.5,
                    conflict_resolution: "test".to_string(),
                    common_themes: vec!["test".to_string()],
                },
                emotional_dynamics: EmotionalDynamicsAnalysis {
                    intensity: 0.5,
                    valence: 0.5,
                    stability: 0.5,
                    dominant_emotions: vec!["test".to_string()],
                    emotional_triggers: vec!["test".to_string()],
                },
                trust_loyalty: TrustLoyaltyAnalysis {
                    trust_level: 0.5,
                    loyalty_strength: 0.5,
                    reliability: 0.5,
                    commitment: 0.5,
                    trust_factors: vec!["test".to_string()],
                },
            },
            relationship_metrics: RelationshipMetricsOutput {
                strength: 0.9,
                stability: 0.9,
                interaction_frequency: 0.5,
                interaction_quality: 0.5,
                mutual_dependence: 0.5,
                trend: RelationshipTrendOutput {
                    direction: "stable".to_string(),
                    strength: 0.5,
                    confidence: 0.5,
                    driving_factors: vec!["test".to_string()],
                    predicted_direction: "test".to_string(),
                },
            },
            relationship_history: RelationshipHistoryAnalysis {
                relationship_phases: vec![],
                turning_points: vec![],
                milestones: vec![],
                change_patterns: vec![],
                cyclical_behaviors: vec![],
            },
            confidence_score: 0.5,
            justification: "Test justification".to_string(),
        };
        
        // Test Excellent category
        assert_eq!(output.get_relationship_assessment(), "Excellent");
        
        // Test Good category
        output.relationship_metrics.strength = 0.7;
        output.relationship_metrics.stability = 0.6;
        assert_eq!(output.get_relationship_assessment(), "Good");
        
        // Test Moderate category
        output.relationship_metrics.strength = 0.5;
        output.relationship_metrics.stability = 0.4;
        assert_eq!(output.get_relationship_assessment(), "Moderate");
        
        // Test Weak category
        output.relationship_metrics.strength = 0.3;
        output.relationship_metrics.stability = 0.2;
        assert_eq!(output.get_relationship_assessment(), "Weak");
        
        // Test Poor category
        output.relationship_metrics.strength = 0.1;
        output.relationship_metrics.stability = 0.1;
        assert_eq!(output.get_relationship_assessment(), "Poor");
    }
}