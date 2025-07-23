// backend/tests/narrative_answer_generation_test.rs
//
// Unit tests for AI-driven narrative answer generation functionality
//
// Tests the narrative answer generation feature that uses AI models (Flash/Flash-Lite)
// to generate natural language responses instead of hardcoded templates.

use uuid::Uuid;
use chrono::Utc;

use scribe_backend::{
    models::chronicle_event::ChronicleEvent,
    services::agentic::narrative_answer_generation_structured_output::*,
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
async fn test_narrative_generation_output_validation() {
    // Test valid narrative generation output
    let valid_output = NarrativeGenerationOutput {
        narrative_response: NarrativeResponse {
            opening_statement: "This is a comprehensive analysis of the requested information.".to_string(),
            main_content: vec![
                ContentSection {
                    section_type: "overview".to_string(),
                    heading: "Overview".to_string(),
                    content: "This section provides an overview of the key findings.".to_string(),
                    supporting_details: vec!["Detail 1".to_string(), "Detail 2".to_string()],
                    importance_level: 0.8,
                    evidence_strength: 0.9,
                },
                ContentSection {
                    section_type: "analysis".to_string(),
                    heading: "Detailed Analysis".to_string(),
                    content: "This section provides detailed analysis of the findings.".to_string(),
                    supporting_details: vec!["Analysis point 1".to_string()],
                    importance_level: 0.7,
                    evidence_strength: 0.8,
                }
            ],
            conclusion: "In conclusion, the analysis reveals important insights about the query.".to_string(),
            tone: "informative".to_string(),
            style: "analytical".to_string(),
            perspective: "third-person".to_string(),
        },
        content_structure: ContentStructure {
            narrative_flow: "chronological".to_string(),
            logical_progression: vec!["introduction".to_string(), "analysis".to_string(), "conclusion".to_string()],
            key_themes: vec!["theme1".to_string(), "theme2".to_string()],
            information_hierarchy: vec![
                InformationPriority {
                    topic: "main_topic".to_string(),
                    priority_level: 0.9,
                    relevance_to_query: 0.95,
                    supporting_evidence: vec!["evidence1".to_string(), "evidence2".to_string()],
                    narrative_placement: "main_content".to_string(),
                }
            ],
            coherence_score: 0.85,
        },
        narrative_quality: NarrativeQualityMetrics {
            clarity_score: 0.9,
            completeness_score: 0.8,
            engagement_score: 0.85,
            accuracy_score: 0.9,
            readability_score: 0.8,
            narrative_cohesion: 0.85,
            information_density: 0.75,
        },
        confidence_score: 0.85,
        justification: "The narrative was generated based on comprehensive analysis of the available data, structured to provide clear and actionable insights.".to_string(),
    };

    // Test validation
    assert!(valid_output.validate().is_ok());
    
    // Test quality assessment
    let quality_assessment = valid_output.get_quality_assessment();
    assert_eq!(quality_assessment, "Very Good");
    
    // Test structure analysis
    let structure_analysis = valid_output.get_structure_analysis();
    assert!(structure_analysis.contains("chronological"));
    assert!(structure_analysis.contains("2 key themes"));
    assert!(structure_analysis.contains("0.85"));
    
    // Test high-priority topics
    let high_priority_topics = valid_output.get_high_priority_topics();
    assert_eq!(high_priority_topics.len(), 1);
    assert_eq!(high_priority_topics[0], "main_topic");
    
    // Test final narrative generation
    let final_narrative = valid_output.generate_final_narrative();
    assert!(final_narrative.contains("This is a comprehensive analysis"));
    assert!(final_narrative.contains("**Overview**"));
    assert!(final_narrative.contains("**Detailed Analysis**"));
    assert!(final_narrative.contains("In conclusion"));
    assert!(final_narrative.contains("• Detail 1"));
    assert!(final_narrative.contains("• Detail 2"));
}

#[tokio::test]
async fn test_narrative_generation_schema_generation() {
    // Test that schema generation works correctly
    let schema = get_narrative_generation_schema();
    
    // Verify basic structure
    assert!(schema.get("type").is_some());
    assert!(schema.get("properties").is_some());
    assert!(schema.get("required").is_some());
    
    // Verify key properties exist
    let properties = schema.get("properties").unwrap();
    assert!(properties.get("narrative_response").is_some());
    assert!(properties.get("content_structure").is_some());
    assert!(properties.get("narrative_quality").is_some());
    assert!(properties.get("confidence_score").is_some());
    assert!(properties.get("justification").is_some());
    
    // Verify narrative_response structure
    let narrative_response = properties.get("narrative_response").unwrap();
    let nr_props = narrative_response.get("properties").unwrap();
    assert!(nr_props.get("opening_statement").is_some());
    assert!(nr_props.get("main_content").is_some());
    assert!(nr_props.get("conclusion").is_some());
    assert!(nr_props.get("tone").is_some());
    assert!(nr_props.get("style").is_some());
    assert!(nr_props.get("perspective").is_some());
}

#[tokio::test]
async fn test_narrative_generation_validation_failures() {
    // Test validation with invalid confidence score
    let mut invalid_output = NarrativeGenerationOutput {
        narrative_response: NarrativeResponse {
            opening_statement: "Test opening".to_string(),
            main_content: vec![
                ContentSection {
                    section_type: "test".to_string(),
                    heading: "Test".to_string(),
                    content: "Test content".to_string(),
                    supporting_details: vec![],
                    importance_level: 0.5,
                    evidence_strength: 0.5,
                }
            ],
            conclusion: "Test conclusion".to_string(),
            tone: "test".to_string(),
            style: "test".to_string(),
            perspective: "test".to_string(),
        },
        content_structure: ContentStructure {
            narrative_flow: "test".to_string(),
            logical_progression: vec!["test".to_string()],
            key_themes: vec!["test".to_string()],
            information_hierarchy: vec![],
            coherence_score: 0.5,
        },
        narrative_quality: NarrativeQualityMetrics {
            clarity_score: 0.5,
            completeness_score: 0.5,
            engagement_score: 0.5,
            accuracy_score: 0.5,
            readability_score: 0.5,
            narrative_cohesion: 0.5,
            information_density: 0.5,
        },
        confidence_score: 1.5, // Invalid: > 1.0
        justification: "Test justification".to_string(),
    };

    // Test validation failure
    assert!(invalid_output.validate().is_err());
    
    // Test with empty justification
    invalid_output.confidence_score = 0.5;
    invalid_output.justification = "".to_string();
    assert!(invalid_output.validate().is_err());
    
    // Test with empty opening statement
    invalid_output.justification = "Test justification".to_string();
    invalid_output.narrative_response.opening_statement = "".to_string();
    assert!(invalid_output.validate().is_err());
    
    // Test with empty main content
    invalid_output.narrative_response.opening_statement = "Test opening".to_string();
    invalid_output.narrative_response.main_content = vec![];
    assert!(invalid_output.validate().is_err());
    
    // Test with empty conclusion
    invalid_output.narrative_response.main_content = vec![
        ContentSection {
            section_type: "test".to_string(),
            heading: "Test".to_string(),
            content: "Test content".to_string(),
            supporting_details: vec![],
            importance_level: 0.5,
            evidence_strength: 0.5,
        }
    ];
    invalid_output.narrative_response.conclusion = "".to_string();
    assert!(invalid_output.validate().is_err());
}

#[tokio::test]
async fn test_narrative_generation_quality_assessment_levels() {
    let mut output = NarrativeGenerationOutput {
        narrative_response: NarrativeResponse {
            opening_statement: "Test opening".to_string(),
            main_content: vec![
                ContentSection {
                    section_type: "test".to_string(),
                    heading: "Test".to_string(),
                    content: "Test content".to_string(),
                    supporting_details: vec![],
                    importance_level: 0.5,
                    evidence_strength: 0.5,
                }
            ],
            conclusion: "Test conclusion".to_string(),
            tone: "test".to_string(),
            style: "test".to_string(),
            perspective: "test".to_string(),
        },
        content_structure: ContentStructure {
            narrative_flow: "test".to_string(),
            logical_progression: vec!["test".to_string()],
            key_themes: vec!["test".to_string()],
            information_hierarchy: vec![],
            coherence_score: 0.5,
        },
        narrative_quality: NarrativeQualityMetrics {
            clarity_score: 0.95,
            completeness_score: 0.95,
            engagement_score: 0.95,
            accuracy_score: 0.95,
            readability_score: 0.95,
            narrative_cohesion: 0.95,
            information_density: 0.95,
        },
        confidence_score: 0.85,
        justification: "Test justification".to_string(),
    };

    // Test Excellent category
    assert_eq!(output.get_quality_assessment(), "Excellent");
    
    // Test Very Good category
    output.narrative_quality.clarity_score = 0.85;
    output.narrative_quality.completeness_score = 0.85;
    output.narrative_quality.engagement_score = 0.85;
    output.narrative_quality.accuracy_score = 0.85;
    output.narrative_quality.readability_score = 0.85;
    output.narrative_quality.narrative_cohesion = 0.85;
    assert_eq!(output.get_quality_assessment(), "Very Good");
    
    // Test Good category
    output.narrative_quality.clarity_score = 0.75;
    output.narrative_quality.completeness_score = 0.75;
    output.narrative_quality.engagement_score = 0.75;
    output.narrative_quality.accuracy_score = 0.75;
    output.narrative_quality.readability_score = 0.75;
    output.narrative_quality.narrative_cohesion = 0.75;
    assert_eq!(output.get_quality_assessment(), "Good");
    
    // Test Fair category
    output.narrative_quality.clarity_score = 0.65;
    output.narrative_quality.completeness_score = 0.65;
    output.narrative_quality.engagement_score = 0.65;
    output.narrative_quality.accuracy_score = 0.65;
    output.narrative_quality.readability_score = 0.65;
    output.narrative_quality.narrative_cohesion = 0.65;
    assert_eq!(output.get_quality_assessment(), "Fair");
    
    // Test Adequate category
    output.narrative_quality.clarity_score = 0.55;
    output.narrative_quality.completeness_score = 0.55;
    output.narrative_quality.engagement_score = 0.55;
    output.narrative_quality.accuracy_score = 0.55;
    output.narrative_quality.readability_score = 0.55;
    output.narrative_quality.narrative_cohesion = 0.55;
    assert_eq!(output.get_quality_assessment(), "Adequate");
    
    // Test Needs Improvement category
    output.narrative_quality.clarity_score = 0.45;
    output.narrative_quality.completeness_score = 0.45;
    output.narrative_quality.engagement_score = 0.45;
    output.narrative_quality.accuracy_score = 0.45;
    output.narrative_quality.readability_score = 0.45;
    output.narrative_quality.narrative_cohesion = 0.45;
    assert_eq!(output.get_quality_assessment(), "Needs Improvement");
}

#[tokio::test]
async fn test_narrative_generation_content_section_validation() {
    // Test validation with invalid section importance level
    let invalid_output = NarrativeGenerationOutput {
        narrative_response: NarrativeResponse {
            opening_statement: "Test opening".to_string(),
            main_content: vec![
                ContentSection {
                    section_type: "test".to_string(),
                    heading: "Test".to_string(),
                    content: "Test content".to_string(),
                    supporting_details: vec![],
                    importance_level: 1.5, // Invalid: > 1.0
                    evidence_strength: 0.5,
                }
            ],
            conclusion: "Test conclusion".to_string(),
            tone: "test".to_string(),
            style: "test".to_string(),
            perspective: "test".to_string(),
        },
        content_structure: ContentStructure {
            narrative_flow: "test".to_string(),
            logical_progression: vec!["test".to_string()],
            key_themes: vec!["test".to_string()],
            information_hierarchy: vec![],
            coherence_score: 0.5,
        },
        narrative_quality: NarrativeQualityMetrics {
            clarity_score: 0.5,
            completeness_score: 0.5,
            engagement_score: 0.5,
            accuracy_score: 0.5,
            readability_score: 0.5,
            narrative_cohesion: 0.5,
            information_density: 0.5,
        },
        confidence_score: 0.85,
        justification: "Test justification".to_string(),
    };

    // Test validation failure
    assert!(invalid_output.validate().is_err());
}

#[tokio::test]
async fn test_narrative_generation_information_priority_validation() {
    // Test validation with invalid priority level
    let invalid_output = NarrativeGenerationOutput {
        narrative_response: NarrativeResponse {
            opening_statement: "Test opening".to_string(),
            main_content: vec![
                ContentSection {
                    section_type: "test".to_string(),
                    heading: "Test".to_string(),
                    content: "Test content".to_string(),
                    supporting_details: vec![],
                    importance_level: 0.5,
                    evidence_strength: 0.5,
                }
            ],
            conclusion: "Test conclusion".to_string(),
            tone: "test".to_string(),
            style: "test".to_string(),
            perspective: "test".to_string(),
        },
        content_structure: ContentStructure {
            narrative_flow: "test".to_string(),
            logical_progression: vec!["test".to_string()],
            key_themes: vec!["test".to_string()],
            information_hierarchy: vec![
                InformationPriority {
                    topic: "test_topic".to_string(),
                    priority_level: 1.5, // Invalid: > 1.0
                    relevance_to_query: 0.5,
                    supporting_evidence: vec!["evidence".to_string()],
                    narrative_placement: "main_content".to_string(),
                }
            ],
            coherence_score: 0.5,
        },
        narrative_quality: NarrativeQualityMetrics {
            clarity_score: 0.5,
            completeness_score: 0.5,
            engagement_score: 0.5,
            accuracy_score: 0.5,
            readability_score: 0.5,
            narrative_cohesion: 0.5,
            information_density: 0.5,
        },
        confidence_score: 0.85,
        justification: "Test justification".to_string(),
    };

    // Test validation failure
    assert!(invalid_output.validate().is_err());
}

#[tokio::test]
async fn test_narrative_generation_entity_timeline_narrative() {
    // Test entity timeline narrative structure
    let timeline_narrative = EntityTimelineNarrative {
        entity_introduction: "This entity is a central character in the narrative.".to_string(),
        timeline_overview: "The entity's timeline spans several key events and developments.".to_string(),
        key_events: vec![
            TimelineEvent {
                event_description: "Initial appearance in the story".to_string(),
                significance: 0.8,
                impact_description: "Established the entity's role and importance".to_string(),
                connections_to_other_events: vec!["Connected to event B".to_string()],
            },
            TimelineEvent {
                event_description: "Major character development".to_string(),
                significance: 0.9,
                impact_description: "Fundamentally changed the entity's characteristics".to_string(),
                connections_to_other_events: vec!["Led to event C".to_string(), "Influenced event D".to_string()],
            }
        ],
        current_status: "The entity is currently in a stable state with defined characteristics.".to_string(),
        future_implications: "The entity's future development may involve further interactions.".to_string(),
    };

    // Test that the timeline structure is valid
    assert!(!timeline_narrative.entity_introduction.is_empty());
    assert!(!timeline_narrative.timeline_overview.is_empty());
    assert_eq!(timeline_narrative.key_events.len(), 2);
    assert_eq!(timeline_narrative.key_events[0].significance, 0.8);
    assert_eq!(timeline_narrative.key_events[1].significance, 0.9);
    assert!(!timeline_narrative.current_status.is_empty());
    assert!(!timeline_narrative.future_implications.is_empty());
}

#[tokio::test]
async fn test_narrative_generation_relationship_narrative() {
    // Test relationship narrative structure
    let relationship_narrative = RelationshipNarrative {
        relationship_overview: "This is a complex relationship between two key entities.".to_string(),
        relationship_development: "The relationship has evolved through several stages.".to_string(),
        key_interactions: vec![
            "Initial meeting and first impressions".to_string(),
            "Collaborative project that strengthened bonds".to_string(),
            "Conflict resolution that deepened understanding".to_string(),
        ],
        current_dynamic: "The relationship is currently stable and mutually beneficial.".to_string(),
        future_trajectory: "The relationship is likely to continue developing positively.".to_string(),
    };

    // Test that the relationship structure is valid
    assert!(!relationship_narrative.relationship_overview.is_empty());
    assert!(!relationship_narrative.relationship_development.is_empty());
    assert_eq!(relationship_narrative.key_interactions.len(), 3);
    assert!(!relationship_narrative.current_dynamic.is_empty());
    assert!(!relationship_narrative.future_trajectory.is_empty());
}

#[tokio::test]
async fn test_narrative_generation_event_participants_narrative() {
    // Test event participants narrative structure
    let participants_narrative = EventParticipantsNarrative {
        event_context: "This event took place in a significant historical moment.".to_string(),
        participant_overview: "Multiple entities participated with different roles and motivations.".to_string(),
        participant_roles: vec![
            ParticipantRole {
                participant_name: "Entity A".to_string(),
                role_description: "Primary organizer and leader".to_string(),
                involvement_level: 0.9,
                key_contributions: vec!["Organized the event".to_string(), "Led key discussions".to_string()],
            },
            ParticipantRole {
                participant_name: "Entity B".to_string(),
                role_description: "Supporting participant".to_string(),
                involvement_level: 0.6,
                key_contributions: vec!["Provided resources".to_string()],
            }
        ],
        interaction_dynamics: "The participants worked together effectively with clear role divisions.".to_string(),
        event_outcomes: "The event achieved its primary objectives with positive results.".to_string(),
    };

    // Test that the participants structure is valid
    assert!(!participants_narrative.event_context.is_empty());
    assert!(!participants_narrative.participant_overview.is_empty());
    assert_eq!(participants_narrative.participant_roles.len(), 2);
    assert_eq!(participants_narrative.participant_roles[0].involvement_level, 0.9);
    assert_eq!(participants_narrative.participant_roles[1].involvement_level, 0.6);
    assert!(!participants_narrative.interaction_dynamics.is_empty());
    assert!(!participants_narrative.event_outcomes.is_empty());
}