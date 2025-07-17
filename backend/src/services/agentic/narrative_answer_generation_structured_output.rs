// backend/src/services/agentic/narrative_answer_generation_structured_output.rs
//
// AI-driven narrative answer generation using structured outputs
//
// This module provides comprehensive narrative generation capabilities
// for the hybrid query service, replacing hardcoded templates with
// AI-generated natural language responses.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use crate::errors::AppError;

/// Main output structure for AI-driven narrative generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeGenerationOutput {
    pub narrative_response: NarrativeResponse,
    pub content_structure: ContentStructure,
    pub narrative_quality: NarrativeQualityMetrics,
    pub confidence_score: f32,
    pub justification: String,
}

/// Core narrative response with generated content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeResponse {
    pub opening_statement: String,
    pub main_content: Vec<ContentSection>,
    pub conclusion: String,
    pub tone: String,
    pub style: String,
    pub perspective: String,
}

/// Individual content section within the narrative
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentSection {
    pub section_type: String,
    pub heading: String,
    pub content: String,
    pub supporting_details: Vec<String>,
    pub importance_level: f32,
    pub evidence_strength: f32,
}

/// Structure and organization of the narrative content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentStructure {
    pub narrative_flow: String,
    pub logical_progression: Vec<String>,
    pub key_themes: Vec<String>,
    pub information_hierarchy: Vec<InformationPriority>,
    pub coherence_score: f32,
}

/// Information priority and relevance assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InformationPriority {
    pub topic: String,
    pub priority_level: f32,
    pub relevance_to_query: f32,
    pub supporting_evidence: Vec<String>,
    pub narrative_placement: String,
}

/// Metrics for narrative quality assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeQualityMetrics {
    pub clarity_score: f32,
    pub completeness_score: f32,
    pub engagement_score: f32,
    pub accuracy_score: f32,
    pub readability_score: f32,
    pub narrative_cohesion: f32,
    pub information_density: f32,
}

/// Specialized outputs for different query types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityTimelineNarrative {
    pub entity_introduction: String,
    pub timeline_overview: String,
    pub key_events: Vec<TimelineEvent>,
    pub current_status: String,
    pub future_implications: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub event_description: String,
    pub significance: f32,
    pub impact_description: String,
    pub connections_to_other_events: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipNarrative {
    pub relationship_overview: String,
    pub relationship_development: String,
    pub key_interactions: Vec<String>,
    pub current_dynamic: String,
    pub future_trajectory: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventParticipantsNarrative {
    pub event_context: String,
    pub participant_overview: String,
    pub participant_roles: Vec<ParticipantRole>,
    pub interaction_dynamics: String,
    pub event_outcomes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantRole {
    pub participant_name: String,
    pub role_description: String,
    pub involvement_level: f32,
    pub key_contributions: Vec<String>,
}

impl NarrativeGenerationOutput {
    /// Validate the narrative generation output
    pub fn validate(&self) -> Result<(), AppError> {
        // Validate confidence score
        if self.confidence_score < 0.0 || self.confidence_score > 1.0 {
            return Err(AppError::BadRequest("Confidence score must be between 0.0 and 1.0".to_string()));
        }

        // Validate justification
        if self.justification.trim().is_empty() {
            return Err(AppError::BadRequest("Justification cannot be empty".to_string()));
        }

        // Validate narrative response
        if self.narrative_response.opening_statement.trim().is_empty() {
            return Err(AppError::BadRequest("Opening statement cannot be empty".to_string()));
        }

        if self.narrative_response.main_content.is_empty() {
            return Err(AppError::BadRequest("Main content cannot be empty".to_string()));
        }

        if self.narrative_response.conclusion.trim().is_empty() {
            return Err(AppError::BadRequest("Conclusion cannot be empty".to_string()));
        }

        // Validate quality metrics
        let quality = &self.narrative_quality;
        if quality.clarity_score < 0.0 || quality.clarity_score > 1.0 ||
           quality.completeness_score < 0.0 || quality.completeness_score > 1.0 ||
           quality.engagement_score < 0.0 || quality.engagement_score > 1.0 ||
           quality.accuracy_score < 0.0 || quality.accuracy_score > 1.0 ||
           quality.readability_score < 0.0 || quality.readability_score > 1.0 ||
           quality.narrative_cohesion < 0.0 || quality.narrative_cohesion > 1.0 ||
           quality.information_density < 0.0 || quality.information_density > 1.0 {
            return Err(AppError::BadRequest("Quality metrics must be between 0.0 and 1.0".to_string()));
        }

        // Validate content structure
        if self.content_structure.coherence_score < 0.0 || self.content_structure.coherence_score > 1.0 {
            return Err(AppError::BadRequest("Coherence score must be between 0.0 and 1.0".to_string()));
        }

        // Validate content sections
        for section in &self.narrative_response.main_content {
            if section.importance_level < 0.0 || section.importance_level > 1.0 {
                return Err(AppError::BadRequest("Section importance level must be between 0.0 and 1.0".to_string()));
            }
            if section.evidence_strength < 0.0 || section.evidence_strength > 1.0 {
                return Err(AppError::BadRequest("Section evidence strength must be between 0.0 and 1.0".to_string()));
            }
        }

        // Validate information priorities
        for priority in &self.content_structure.information_hierarchy {
            if priority.priority_level < 0.0 || priority.priority_level > 1.0 {
                return Err(AppError::BadRequest("Priority level must be between 0.0 and 1.0".to_string()));
            }
            if priority.relevance_to_query < 0.0 || priority.relevance_to_query > 1.0 {
                return Err(AppError::BadRequest("Relevance to query must be between 0.0 and 1.0".to_string()));
            }
        }

        Ok(())
    }

    /// Generate final narrative text from the structured output
    pub fn generate_final_narrative(&self) -> String {
        let mut narrative = String::new();

        // Add opening statement
        narrative.push_str(&self.narrative_response.opening_statement);
        narrative.push_str("\n\n");

        // Add main content sections
        for section in &self.narrative_response.main_content {
            if !section.heading.trim().is_empty() {
                narrative.push_str(&format!("**{}**\n\n", section.heading));
            }
            narrative.push_str(&section.content);
            narrative.push_str("\n\n");

            // Add supporting details if present
            if !section.supporting_details.is_empty() {
                for detail in &section.supporting_details {
                    narrative.push_str(&format!("• {}\n", detail));
                }
                narrative.push_str("\n");
            }
        }

        // Add conclusion
        narrative.push_str(&self.narrative_response.conclusion);

        narrative
    }

    /// Get narrative quality assessment
    pub fn get_quality_assessment(&self) -> String {
        let avg_quality = (self.narrative_quality.clarity_score + 
                          self.narrative_quality.completeness_score + 
                          self.narrative_quality.engagement_score + 
                          self.narrative_quality.accuracy_score + 
                          self.narrative_quality.readability_score + 
                          self.narrative_quality.narrative_cohesion) / 6.0;

        match avg_quality {
            q if q >= 0.9 => "Excellent",
            q if q >= 0.8 => "Very Good",
            q if q >= 0.7 => "Good",
            q if q >= 0.6 => "Fair",
            q if q >= 0.5 => "Adequate",
            _ => "Needs Improvement"
        }.to_string()
    }

    /// Get content structure analysis
    pub fn get_structure_analysis(&self) -> String {
        format!("Narrative follows {} flow with {} key themes and coherence score of {:.2}",
                self.content_structure.narrative_flow,
                self.content_structure.key_themes.len(),
                self.content_structure.coherence_score)
    }

    /// Get high-priority information topics
    pub fn get_high_priority_topics(&self) -> Vec<String> {
        self.content_structure.information_hierarchy
            .iter()
            .filter(|info| info.priority_level >= 0.7)
            .map(|info| info.topic.clone())
            .collect()
    }
}

/// Generate JSON schema for narrative generation
pub fn get_narrative_generation_schema() -> JsonValue {
    json!({
        "type": "object",
        "properties": {
            "narrative_response": {
                "type": "object",
                "properties": {
                    "opening_statement": {
                        "type": "string",
                        "description": "Engaging opening statement that introduces the narrative response"
                    },
                    "main_content": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "section_type": {
                                    "type": "string",
                                    "description": "Type of content section (overview, timeline, analysis, etc.)"
                                },
                                "heading": {
                                    "type": "string",
                                    "description": "Section heading or title"
                                },
                                "content": {
                                    "type": "string",
                                    "description": "Main content text for this section"
                                },
                                "supporting_details": {
                                    "type": "array",
                                    "items": {
                                        "type": "string"
                                    },
                                    "description": "Additional supporting details or bullet points"
                                },
                                "importance_level": {
                                    "type": "number",
                                    "minimum": 0.0,
                                    "maximum": 1.0,
                                    "description": "Importance level of this section (0.0-1.0)"
                                },
                                "evidence_strength": {
                                    "type": "number",
                                    "minimum": 0.0,
                                    "maximum": 1.0,
                                    "description": "Strength of evidence supporting this section (0.0-1.0)"
                                }
                            },
                            "required": ["section_type", "heading", "content", "supporting_details", "importance_level", "evidence_strength"]
                        }
                    },
                    "conclusion": {
                        "type": "string",
                        "description": "Concluding statement that summarizes key insights"
                    },
                    "tone": {
                        "type": "string",
                        "description": "Overall tone of the narrative (formal, conversational, analytical, etc.)"
                    },
                    "style": {
                        "type": "string",
                        "description": "Writing style used (informative, narrative, technical, etc.)"
                    },
                    "perspective": {
                        "type": "string",
                        "description": "Narrative perspective (third-person, omniscient, etc.)"
                    }
                },
                "required": ["opening_statement", "main_content", "conclusion", "tone", "style", "perspective"]
            },
            "content_structure": {
                "type": "object",
                "properties": {
                    "narrative_flow": {
                        "type": "string",
                        "description": "Overall flow and structure of the narrative"
                    },
                    "logical_progression": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        },
                        "description": "Logical progression of ideas through the narrative"
                    },
                    "key_themes": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        },
                        "description": "Key themes and topics covered in the narrative"
                    },
                    "information_hierarchy": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "topic": {
                                    "type": "string",
                                    "description": "Topic or information category"
                                },
                                "priority_level": {
                                    "type": "number",
                                    "minimum": 0.0,
                                    "maximum": 1.0,
                                    "description": "Priority level of this information (0.0-1.0)"
                                },
                                "relevance_to_query": {
                                    "type": "number",
                                    "minimum": 0.0,
                                    "maximum": 1.0,
                                    "description": "Relevance to the original query (0.0-1.0)"
                                },
                                "supporting_evidence": {
                                    "type": "array",
                                    "items": {
                                        "type": "string"
                                    },
                                    "description": "Evidence supporting this information"
                                },
                                "narrative_placement": {
                                    "type": "string",
                                    "description": "Where this information is placed in the narrative"
                                }
                            },
                            "required": ["topic", "priority_level", "relevance_to_query", "supporting_evidence", "narrative_placement"]
                        }
                    },
                    "coherence_score": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Overall coherence and flow of the narrative (0.0-1.0)"
                    }
                },
                "required": ["narrative_flow", "logical_progression", "key_themes", "information_hierarchy", "coherence_score"]
            },
            "narrative_quality": {
                "type": "object",
                "properties": {
                    "clarity_score": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Clarity and understandability of the narrative (0.0-1.0)"
                    },
                    "completeness_score": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Completeness of information coverage (0.0-1.0)"
                    },
                    "engagement_score": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Engagement and readability of the narrative (0.0-1.0)"
                    },
                    "accuracy_score": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Accuracy of information presented (0.0-1.0)"
                    },
                    "readability_score": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Readability and accessibility of the text (0.0-1.0)"
                    },
                    "narrative_cohesion": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Cohesion and consistency of the narrative (0.0-1.0)"
                    },
                    "information_density": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Appropriate density of information (0.0-1.0)"
                    }
                },
                "required": ["clarity_score", "completeness_score", "engagement_score", "accuracy_score", "readability_score", "narrative_cohesion", "information_density"]
            },
            "confidence_score": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Overall confidence in the narrative generation (0.0-1.0)"
            },
            "justification": {
                "type": "string",
                "description": "Justification for the narrative approach and content choices"
            }
        },
        "required": ["narrative_response", "content_structure", "narrative_quality", "confidence_score", "justification"]
    })
}