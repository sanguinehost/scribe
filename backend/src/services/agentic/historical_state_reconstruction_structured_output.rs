// backend/src/services/agentic/historical_state_reconstruction_structured_output.rs
//
// Structured output definitions for AI-driven historical state reconstruction
//
// This module provides the structured output schema for analyzing chronicle events
// and reconstructing historical entity states using AI models (Flash/Flash-Lite).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use uuid::Uuid;
use crate::errors::AppError;

/// Structured output for historical state reconstruction analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalStateReconstructionOutput {
    /// Analysis of what state changes occurred in the event
    pub state_changes: Vec<StateChangeAnalysis>,
    
    /// Reconstructed entity state at the time of the event
    pub reconstructed_state: ReconstructedEntityState,
    
    /// Analysis of the reconstruction process
    pub reconstruction_analysis: ReconstructionAnalysis,
    
    /// Confidence score for the reconstruction (0.0-1.0)
    pub reconstruction_confidence: f32,
    
    /// Explanation of the reconstruction logic
    pub reconstruction_explanation: String,
}

/// Analysis of state changes identified in an event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChangeAnalysis {
    /// Type of component that changed (e.g., "health", "location", "inventory")
    pub component_type: String,
    
    /// Specific field that changed (e.g., "current_health", "position", "items")
    pub field_name: String,
    
    /// Type of change (e.g., "increase", "decrease", "set", "add_item", "remove_item")
    pub change_type: String,
    
    /// Magnitude of change (for numeric changes)
    pub change_magnitude: Option<f64>,
    
    /// Previous value (if determinable)
    pub previous_value: Option<Value>,
    
    /// New value after change
    pub new_value: Option<Value>,
    
    /// Confidence in this state change analysis (0.0-1.0)
    pub confidence: f32,
    
    /// Evidence supporting this change
    pub evidence: Vec<String>,
}

/// Reconstructed entity state at a specific point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructedEntityState {
    /// Entity ID this state belongs to
    pub entity_id: Uuid,
    
    /// Timestamp this state represents
    pub state_timestamp: String, // ISO8601 format
    
    /// Component data organized by component type
    pub components: HashMap<String, Value>,
    
    /// Status indicators for the entity at this time
    pub status_indicators: Vec<String>,
    
    /// Archetype signature if determinable
    pub archetype_signature: Option<String>,
    
    /// Uncertainty factors in the reconstruction
    pub uncertainty_factors: Vec<String>,
}

/// Analysis of the reconstruction process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructionAnalysis {
    /// Method used for reconstruction (e.g., "backward_reconstruction", "forward_reconstruction", "event_based")
    pub reconstruction_method: String,
    
    /// Number of events analyzed for reconstruction
    pub events_analyzed: u32,
    
    /// Sources of information used
    pub information_sources: Vec<String>,
    
    /// Limitations in the reconstruction
    pub limitations: Vec<String>,
    
    /// Reliability assessment
    pub reliability_assessment: ReliabilityAssessment,
}

/// Assessment of reconstruction reliability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReliabilityAssessment {
    /// Overall reliability score (0.0-1.0)
    pub reliability_score: f32,
    
    /// Factors that increase reliability
    pub reliability_factors: Vec<String>,
    
    /// Factors that decrease reliability
    pub uncertainty_factors: Vec<String>,
    
    /// Recommended actions to improve reliability
    pub improvement_recommendations: Vec<String>,
}

impl HistoricalStateReconstructionOutput {
    /// Validate the output structure and values
    pub fn validate(&self) -> Result<(), AppError> {
        // Validate reconstruction confidence
        if self.reconstruction_confidence < 0.0 || self.reconstruction_confidence > 1.0 {
            return Err(AppError::BadRequest(
                "Reconstruction confidence must be between 0.0 and 1.0".to_string()
            ));
        }
        
        // Validate state changes
        for change in &self.state_changes {
            if change.confidence < 0.0 || change.confidence > 1.0 {
                return Err(AppError::BadRequest(
                    "State change confidence must be between 0.0 and 1.0".to_string()
                ));
            }
        }
        
        // Validate reliability assessment
        let reliability = &self.reconstruction_analysis.reliability_assessment;
        if reliability.reliability_score < 0.0 || reliability.reliability_score > 1.0 {
            return Err(AppError::BadRequest(
                "Reliability score must be between 0.0 and 1.0".to_string()
            ));
        }
        
        // Validate required fields
        if self.reconstruction_explanation.trim().is_empty() {
            return Err(AppError::BadRequest(
                "Reconstruction explanation cannot be empty".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Calculate overall reconstruction quality score
    pub fn calculate_quality_score(&self) -> f32 {
        let confidence_weight = 0.4;
        let reliability_weight = 0.3;
        let evidence_weight = 0.3;
        
        let confidence_score = self.reconstruction_confidence;
        let reliability_score = self.reconstruction_analysis.reliability_assessment.reliability_score;
        
        // Calculate evidence score based on number of state changes with evidence
        let evidence_score = if self.state_changes.is_empty() {
            0.0
        } else {
            let changes_with_evidence = self.state_changes.iter()
                .filter(|change| !change.evidence.is_empty())
                .count() as f32;
            changes_with_evidence / self.state_changes.len() as f32
        };
        
        confidence_score * confidence_weight +
        reliability_score * reliability_weight +
        evidence_score * evidence_weight
    }
    
    /// Get all identified state changes as a summary
    pub fn get_state_changes_summary(&self) -> HashMap<String, Vec<String>> {
        let mut summary = HashMap::new();
        
        for change in &self.state_changes {
            let entry = summary.entry(change.component_type.clone()).or_insert_with(Vec::new);
            entry.push(format!("{}: {} (confidence: {:.2})", 
                change.field_name, change.change_type, change.confidence));
        }
        
        summary
    }
}

/// Create the JSON schema for historical state reconstruction
pub fn get_historical_state_reconstruction_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "state_changes": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "component_type": { "type": "string" },
                        "field_name": { "type": "string" },
                        "change_type": { "type": "string" },
                        "change_magnitude": { "type": ["number", "null"] },
                        "previous_value": { "type": ["object", "string", "number", "boolean", "null"] },
                        "new_value": { "type": ["object", "string", "number", "boolean", "null"] },
                        "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                        "evidence": { "type": "array", "items": { "type": "string" } }
                    },
                    "required": ["component_type", "field_name", "change_type", "confidence", "evidence"]
                }
            },
            "reconstructed_state": {
                "type": "object",
                "properties": {
                    "entity_id": { "type": "string" },
                    "state_timestamp": { "type": "string" },
                    "components": { "type": "object" },
                    "status_indicators": { "type": "array", "items": { "type": "string" } },
                    "archetype_signature": { "type": ["string", "null"] },
                    "uncertainty_factors": { "type": "array", "items": { "type": "string" } }
                },
                "required": ["entity_id", "state_timestamp", "components", "status_indicators", "uncertainty_factors"]
            },
            "reconstruction_analysis": {
                "type": "object",
                "properties": {
                    "reconstruction_method": { "type": "string" },
                    "events_analyzed": { "type": "integer", "minimum": 0 },
                    "information_sources": { "type": "array", "items": { "type": "string" } },
                    "limitations": { "type": "array", "items": { "type": "string" } },
                    "reliability_assessment": {
                        "type": "object",
                        "properties": {
                            "reliability_score": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                            "reliability_factors": { "type": "array", "items": { "type": "string" } },
                            "uncertainty_factors": { "type": "array", "items": { "type": "string" } },
                            "improvement_recommendations": { "type": "array", "items": { "type": "string" } }
                        },
                        "required": ["reliability_score", "reliability_factors", "uncertainty_factors", "improvement_recommendations"]
                    }
                },
                "required": ["reconstruction_method", "events_analyzed", "information_sources", "limitations", "reliability_assessment"]
            },
            "reconstruction_confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
            "reconstruction_explanation": { "type": "string" }
        },
        "required": ["state_changes", "reconstructed_state", "reconstruction_analysis", "reconstruction_confidence", "reconstruction_explanation"]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    
    #[test]
    fn test_historical_state_reconstruction_validation() {
        let valid_output = HistoricalStateReconstructionOutput {
            state_changes: vec![
                StateChangeAnalysis {
                    component_type: "health".to_string(),
                    field_name: "current_health".to_string(),
                    change_type: "decrease".to_string(),
                    change_magnitude: Some(10.0),
                    previous_value: Some(json!(100)),
                    new_value: Some(json!(90)),
                    confidence: 0.9,
                    evidence: vec!["Combat event with damage".to_string()],
                }
            ],
            reconstructed_state: ReconstructedEntityState {
                entity_id: Uuid::new_v4(),
                state_timestamp: "2025-01-01T00:00:00Z".to_string(),
                components: HashMap::new(),
                status_indicators: vec!["healthy".to_string()],
                archetype_signature: Some("character".to_string()),
                uncertainty_factors: vec![],
            },
            reconstruction_analysis: ReconstructionAnalysis {
                reconstruction_method: "backward_reconstruction".to_string(),
                events_analyzed: 5,
                information_sources: vec!["chronicle_events".to_string()],
                limitations: vec!["Limited event history".to_string()],
                reliability_assessment: ReliabilityAssessment {
                    reliability_score: 0.8,
                    reliability_factors: vec!["Recent events".to_string()],
                    uncertainty_factors: vec!["Missing data".to_string()],
                    improvement_recommendations: vec!["Collect more event data".to_string()],
                },
            },
            reconstruction_confidence: 0.85,
            reconstruction_explanation: "Reconstructed state by analyzing combat events".to_string(),
        };
        
        assert!(valid_output.validate().is_ok());
        
        let quality_score = valid_output.calculate_quality_score();
        assert!(quality_score >= 0.0 && quality_score <= 1.0);
    }
    
    #[test]
    fn test_invalid_confidence_scores() {
        let invalid_output = HistoricalStateReconstructionOutput {
            state_changes: vec![],
            reconstructed_state: ReconstructedEntityState {
                entity_id: Uuid::new_v4(),
                state_timestamp: "2025-01-01T00:00:00Z".to_string(),
                components: HashMap::new(),
                status_indicators: vec![],
                archetype_signature: None,
                uncertainty_factors: vec![],
            },
            reconstruction_analysis: ReconstructionAnalysis {
                reconstruction_method: "test".to_string(),
                events_analyzed: 0,
                information_sources: vec![],
                limitations: vec![],
                reliability_assessment: ReliabilityAssessment {
                    reliability_score: 0.5,
                    reliability_factors: vec![],
                    uncertainty_factors: vec![],
                    improvement_recommendations: vec![],
                },
            },
            reconstruction_confidence: 1.5, // Invalid: > 1.0
            reconstruction_explanation: "Test".to_string(),
        };
        
        assert!(invalid_output.validate().is_err());
    }
    
    #[test]
    fn test_state_changes_summary() {
        let output = HistoricalStateReconstructionOutput {
            state_changes: vec![
                StateChangeAnalysis {
                    component_type: "health".to_string(),
                    field_name: "current_health".to_string(),
                    change_type: "decrease".to_string(),
                    change_magnitude: Some(10.0),
                    previous_value: None,
                    new_value: None,
                    confidence: 0.9,
                    evidence: vec![],
                },
                StateChangeAnalysis {
                    component_type: "location".to_string(),
                    field_name: "position".to_string(),
                    change_type: "set".to_string(),
                    change_magnitude: None,
                    previous_value: None,
                    new_value: None,
                    confidence: 0.8,
                    evidence: vec![],
                },
            ],
            reconstructed_state: ReconstructedEntityState {
                entity_id: Uuid::new_v4(),
                state_timestamp: "2025-01-01T00:00:00Z".to_string(),
                components: HashMap::new(),
                status_indicators: vec![],
                archetype_signature: None,
                uncertainty_factors: vec![],
            },
            reconstruction_analysis: ReconstructionAnalysis {
                reconstruction_method: "test".to_string(),
                events_analyzed: 2,
                information_sources: vec![],
                limitations: vec![],
                reliability_assessment: ReliabilityAssessment {
                    reliability_score: 0.5,
                    reliability_factors: vec![],
                    uncertainty_factors: vec![],
                    improvement_recommendations: vec![],
                },
            },
            reconstruction_confidence: 0.85,
            reconstruction_explanation: "Test".to_string(),
        };
        
        let summary = output.get_state_changes_summary();
        assert_eq!(summary.len(), 2);
        assert!(summary.contains_key("health"));
        assert!(summary.contains_key("location"));
    }
}