// backend/tests/relationship_analysis_test.rs
//
// Unit tests for AI-driven relationship analysis functionality
//
// Tests the relationship analysis feature that uses AI models (Flash/Flash-Lite)
// to analyze relationships between entities instead of hardcoded logic.

use uuid::Uuid;
use chrono::Utc;

use scribe_backend::{
    models::chronicle_event::ChronicleEvent,
    services::agentic::relationship_analysis_structured_output::*,
};

// Helper function to create test ChronicleEvent objects
fn create_test_chronicle_event(user_id: Uuid, event_type: &str, summary: &str, event_data: Option<serde_json::Value>) -> ChronicleEvent {
    let now = Utc::now();
    ChronicleEvent {
        id: Uuid::new_v4(),
        chronicle_id: Uuid::new_v4(),
        user_id,
        event_type: event_type.to_string(),
        summary: summary.to_string(),
        source: "USER_ADDED".to_string(),
        event_data,
        created_at: now,
        updated_at: now,
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: now,
        actors: None,
        action: None,
        context_data: None,
        causality: None,
        valence: None,
        modality: None,
        caused_by_event_id: None,
        causes_event_ids: None,
        sequence_number: 1,
    }
}

#[tokio::test]
async fn test_relationship_analysis_output_validation() {
    // Test valid relationship analysis output
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

    // Test validation
    assert!(valid_output.validate().is_ok());
    
    // Test assessment methods
    let assessment = valid_output.get_relationship_assessment();
    assert_eq!(assessment, "Excellent");
    
    let trend = valid_output.get_relationship_trend();
    assert_eq!(trend, "improving");
    
    let significant_points = valid_output.get_significant_turning_points();
    assert_eq!(significant_points.len(), 1);
    assert_eq!(significant_points[0].significance, 0.8);
}

#[tokio::test]
async fn test_relationship_analysis_schema_generation() {
    // Test that schema generation works correctly
    let schema = get_relationship_analysis_schema();
    
    // Verify basic structure
    assert!(schema.get("type").is_some());
    assert!(schema.get("properties").is_some());
    assert!(schema.get("required").is_some());
    
    // Verify key properties exist
    let properties = schema.get("properties").unwrap();
    assert!(properties.get("relationship_analysis").is_some());
    assert!(properties.get("relationship_metrics").is_some());
    assert!(properties.get("relationship_history").is_some());
    assert!(properties.get("confidence_score").is_some());
    assert!(properties.get("justification").is_some());
}

#[tokio::test]
async fn test_relationship_analysis_validation_failures() {
    // Test validation with invalid metrics
    let invalid_output = RelationshipAnalysisOutput {
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

    // Test validation failure
    assert!(invalid_output.validate().is_err());
}

#[tokio::test]
async fn test_relationship_analysis_assessment_categories() {
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

#[tokio::test]
async fn test_relationship_analysis_turning_points() {
    // Test turning points analysis
    let output = RelationshipAnalysisOutput {
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
            relationship_phases: vec![],
            turning_points: vec![
                TurningPoint {
                    trigger_event: "major conflict".to_string(),
                    impact_description: "temporary strain".to_string(),
                    change_type: "weakening".to_string(),
                    significance: 0.9,
                    long_term_effects: vec!["increased boundaries".to_string()],
                },
                TurningPoint {
                    trigger_event: "shared victory".to_string(),
                    impact_description: "strengthened bond".to_string(),
                    change_type: "strengthening".to_string(),
                    significance: 0.8,
                    long_term_effects: vec!["deeper trust".to_string()],
                },
                TurningPoint {
                    trigger_event: "mutual assistance".to_string(),
                    impact_description: "improved cooperation".to_string(),
                    change_type: "strengthening".to_string(),
                    significance: 0.6,
                    long_term_effects: vec!["better communication".to_string()],
                },
            ],
            milestones: vec![],
            change_patterns: vec![],
            cyclical_behaviors: vec![],
        },
        confidence_score: 0.85,
        justification: "Test justification".to_string(),
    };

    // Test significant turning points (should return top 3, ordered by significance)
    let significant_points = output.get_significant_turning_points();
    assert_eq!(significant_points.len(), 3);
    assert_eq!(significant_points[0].significance, 0.9); // Most significant first
    assert_eq!(significant_points[1].significance, 0.8);
    assert_eq!(significant_points[2].significance, 0.6);
}

#[tokio::test]
async fn test_relationship_analysis_empty_justification() {
    // Test validation with empty justification
    let invalid_output = RelationshipAnalysisOutput {
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
            strength: 0.8,
            stability: 0.9,
            interaction_frequency: 0.7,
            interaction_quality: 0.9,
            mutual_dependence: 0.6,
            trend: RelationshipTrendOutput {
                direction: "stable".to_string(),
                strength: 0.7,
                confidence: 0.8,
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
        confidence_score: 0.85,
        justification: "".to_string(), // Empty justification
    };

    // Test validation failure
    let result = invalid_output.validate();
    assert!(result.is_err());
    
    if let Err(error) = result {
        assert!(error.to_string().contains("Justification cannot be empty"));
    }
}