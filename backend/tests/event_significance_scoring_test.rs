// backend/tests/event_significance_scoring_test.rs
//
// Unit tests for Event Significance Scoring AI-driven refactoring
//
// Tests the structured output schema and validation logic

use std::collections::HashMap;
use scribe_backend::services::agentic::event_significance_structured_output::*;
use serde_json::json;

#[test]
fn test_event_significance_output_validation() {
    // Test valid output
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
                factor_weight: 0.4,
                weighted_contribution: 0.36,
                evidence: vec!["Primary actor".to_string()],
                confidence: 0.85,
            },
            SignificanceFactor {
                factor_name: "complexity".to_string(),
                factor_description: "Event complexity".to_string(),
                factor_score: 0.6,
                factor_weight: 0.3,
                weighted_contribution: 0.18,
                evidence: vec!["Detailed description".to_string()],
                confidence: 0.8,
            },
        ],
        overall_significance: 0.78,
        confidence_score: 0.85,
        significance_analysis: create_test_significance_analysis(),
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
    // Test invalid overall significance
    let mut invalid_output = create_basic_significance_output();
    invalid_output.overall_significance = 1.5; // Invalid: > 1.0
    assert!(invalid_output.validate().is_err());
    
    // Test invalid confidence score
    let mut invalid_output = create_basic_significance_output();
    invalid_output.confidence_score = -0.1; // Invalid: < 0.0
    assert!(invalid_output.validate().is_err());
    
    // Test invalid factor score
    let mut invalid_output = create_basic_significance_output();
    invalid_output.significance_factors[0].factor_score = 2.0; // Invalid: > 1.0
    assert!(invalid_output.validate().is_err());
    
    // Test invalid factor weight
    let mut invalid_output = create_basic_significance_output();
    invalid_output.significance_factors[0].factor_weight = -0.5; // Invalid: < 0.0
    assert!(invalid_output.validate().is_err());
}

#[test]
fn test_weight_sum_validation() {
    // Test weights that don't sum to ~1.0
    let mut invalid_output = create_basic_significance_output();
    invalid_output.significance_factors[0].factor_weight = 0.2;
    invalid_output.significance_factors[1].factor_weight = 0.2;
    invalid_output.significance_factors[2].factor_weight = 0.2;
    // Total = 0.6, which is too far from 1.0
    assert!(invalid_output.validate().is_err());
}

#[test]
fn test_empty_justification() {
    // Test empty justification
    let mut invalid_output = create_basic_significance_output();
    invalid_output.justification = "".to_string();
    assert!(invalid_output.validate().is_err());
    
    // Test whitespace-only justification
    let mut invalid_output = create_basic_significance_output();
    invalid_output.justification = "   ".to_string();
    assert!(invalid_output.validate().is_err());
}

#[test]
fn test_significance_categories() {
    let mut output = create_basic_significance_output();
    
    // Test Critical category
    output.overall_significance = 0.9;
    assert_eq!(output.get_significance_category(), "Critical");
    
    // Test High category
    output.overall_significance = 0.7;
    assert_eq!(output.get_significance_category(), "High");
    
    // Test Medium category
    output.overall_significance = 0.5;
    assert_eq!(output.get_significance_category(), "Medium");
    
    // Test Low category
    output.overall_significance = 0.3;
    assert_eq!(output.get_significance_category(), "Low");
    
    // Test Minimal category
    output.overall_significance = 0.1;
    assert_eq!(output.get_significance_category(), "Minimal");
}

#[test]
fn test_top_factors_ranking() {
    let output = EventSignificanceOutput {
        significance_factors: vec![
            SignificanceFactor {
                factor_name: "low_impact".to_string(),
                factor_description: "Low impact factor".to_string(),
                factor_score: 0.3,
                factor_weight: 0.2,
                weighted_contribution: 0.06,
                evidence: vec![],
                confidence: 0.8,
            },
            SignificanceFactor {
                factor_name: "highest_impact".to_string(),
                factor_description: "Highest impact factor".to_string(),
                factor_score: 0.9,
                factor_weight: 0.4,
                weighted_contribution: 0.36,
                evidence: vec![],
                confidence: 0.9,
            },
            SignificanceFactor {
                factor_name: "medium_impact".to_string(),
                factor_description: "Medium impact factor".to_string(),
                factor_score: 0.6,
                factor_weight: 0.4,
                weighted_contribution: 0.24,
                evidence: vec![],
                confidence: 0.85,
            },
        ],
        overall_significance: 0.66,
        confidence_score: 0.85,
        significance_analysis: create_test_significance_analysis(),
        justification: "Test justification".to_string(),
    };
    
    let top_factors = output.get_top_factors(2);
    assert_eq!(top_factors.len(), 2);
    assert_eq!(top_factors[0].factor_name, "highest_impact");
    assert_eq!(top_factors[1].factor_name, "medium_impact");
    
    // Test requesting more factors than available
    let all_factors = output.get_top_factors(10);
    assert_eq!(all_factors.len(), 3);
}

#[test]
fn test_weighted_score_calculation() {
    let output = EventSignificanceOutput {
        significance_factors: vec![
            SignificanceFactor {
                factor_name: "factor1".to_string(),
                factor_description: "Factor 1".to_string(),
                factor_score: 0.8,
                factor_weight: 0.5,
                weighted_contribution: 0.4,
                evidence: vec![],
                confidence: 0.9,
            },
            SignificanceFactor {
                factor_name: "factor2".to_string(),
                factor_description: "Factor 2".to_string(),
                factor_score: 0.6,
                factor_weight: 0.5,
                weighted_contribution: 0.3,
                evidence: vec![],
                confidence: 0.8,
            },
        ],
        overall_significance: 0.7,
        confidence_score: 0.85,
        significance_analysis: create_test_significance_analysis(),
        justification: "Test justification".to_string(),
    };
    
    let weighted_score = output.calculate_weighted_score();
    assert!((weighted_score - 0.7).abs() < 0.01); // Should be 0.4 + 0.3 = 0.7
}

#[test]
fn test_json_schema_generation() {
    let schema = get_event_significance_schema();
    
    // Test that schema is a valid JSON object
    assert!(schema.is_object());
    
    // Test required top-level properties
    let properties = schema.get("properties").unwrap().as_object().unwrap();
    assert!(properties.contains_key("significance_factors"));
    assert!(properties.contains_key("overall_significance"));
    assert!(properties.contains_key("confidence_score"));
    assert!(properties.contains_key("significance_analysis"));
    assert!(properties.contains_key("justification"));
    
    // Test required fields
    let required = schema.get("required").unwrap().as_array().unwrap();
    assert!(required.contains(&json!("significance_factors")));
    assert!(required.contains(&json!("overall_significance")));
    assert!(required.contains(&json!("confidence_score")));
    assert!(required.contains(&json!("significance_analysis")));
    assert!(required.contains(&json!("justification")));
}

#[test]
fn test_significance_factor_validation() {
    let factor = SignificanceFactor {
        factor_name: "test_factor".to_string(),
        factor_description: "Test factor description".to_string(),
        factor_score: 0.8,
        factor_weight: 0.3,
        weighted_contribution: 0.24,
        evidence: vec!["Test evidence".to_string()],
        confidence: 0.9,
    };
    
    // Test serialization/deserialization
    let serialized = serde_json::to_string(&factor).unwrap();
    let deserialized: SignificanceFactor = serde_json::from_str(&serialized).unwrap();
    assert_eq!(factor.factor_name, deserialized.factor_name);
    assert_eq!(factor.factor_score, deserialized.factor_score);
}

// Helper functions for creating test data

fn create_basic_significance_output() -> EventSignificanceOutput {
    EventSignificanceOutput {
        significance_factors: vec![
            SignificanceFactor {
                factor_name: "factor1".to_string(),
                factor_description: "Factor 1".to_string(),
                factor_score: 0.8,
                factor_weight: 0.4,
                weighted_contribution: 0.32,
                evidence: vec!["Evidence 1".to_string()],
                confidence: 0.9,
            },
            SignificanceFactor {
                factor_name: "factor2".to_string(),
                factor_description: "Factor 2".to_string(),
                factor_score: 0.6,
                factor_weight: 0.3,
                weighted_contribution: 0.18,
                evidence: vec!["Evidence 2".to_string()],
                confidence: 0.8,
            },
            SignificanceFactor {
                factor_name: "factor3".to_string(),
                factor_description: "Factor 3".to_string(),
                factor_score: 0.7,
                factor_weight: 0.3,
                weighted_contribution: 0.21,
                evidence: vec!["Evidence 3".to_string()],
                confidence: 0.85,
            },
        ],
        overall_significance: 0.71,
        confidence_score: 0.85,
        significance_analysis: create_test_significance_analysis(),
        justification: "Test justification".to_string(),
    }
}

fn create_test_significance_analysis() -> SignificanceAnalysis {
    SignificanceAnalysis {
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
            entity_actions: vec!["attacked".to_string(), "defended".to_string()],
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
    }
}