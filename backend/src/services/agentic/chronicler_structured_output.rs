use serde::{Deserialize, Serialize};
use crate::errors::AppError;

/// Structured output schema for Chronicler Agent
/// Ensures AI generates valid chronicle events with proper types

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChronicleEventExtractionOutput {
    pub events: Vec<ExtractedChronicleEvent>,
    pub temporal_context: TemporalContextOutput,
    pub narrative_significance: NarrativeSignificanceOutput,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedChronicleEvent {
    pub event_type: String, // "dialogue", "action", "discovery", "conflict", "resolution", etc.
    pub summary: String,
    pub participants: Vec<ParticipantOutput>,
    pub temporal_marker: String, // "immediate", "moments_later", "hours_later", "days_later", etc.
    pub significance_level: String, // "minor", "moderate", "major", "critical"
    pub causal_links: Vec<String>, // References to other events this links to
    pub emotional_tone: String,
    pub world_state_changes: Vec<String>, // What changed in the world
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantOutput {
    pub entity_name: String,
    pub entity_type: String, // "character", "location", "object", "concept"
    pub role_in_event: String, // "actor", "recipient", "witness", "catalyst"
    pub state_change: Option<String>, // How this participant changed
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalContextOutput {
    pub sequence_position: String, // "beginning", "middle", "end", "climax", "denouement"
    pub pacing: String, // "rapid", "steady", "slow", "time_skip"
    pub duration: String, // "instant", "minutes", "hours", "days", "unspecified"
    pub chronological_markers: Vec<String>, // Specific time references if any
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeSignificanceOutput {
    pub plot_advancement: bool,
    pub character_development: bool,
    pub world_building: bool,
    pub relationship_evolution: bool,
    pub thematic_relevance: String,
    pub chronicle_worthiness_score: f32, // 0.0 to 1.0
}

/// Helper function to create the JSON schema for chronicle event extraction
pub fn get_chronicle_event_extraction_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "events": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "event_type": {
                            "type": "string",
                            "enum": ["dialogue", "action", "discovery", "conflict", "resolution", "transition", "revelation", "decision", "consequence"],
                            "description": "Category of the chronicle event"
                        },
                        "summary": {
                            "type": "string",
                            "description": "Concise summary of what happened"
                        },
                        "participants": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "entity_name": {
                                        "type": "string",
                                        "description": "Name of the participating entity"
                                    },
                                    "entity_type": {
                                        "type": "string",
                                        "enum": ["character", "location", "object", "concept", "group"],
                                        "description": "Type of entity"
                                    },
                                    "role_in_event": {
                                        "type": "string",
                                        "enum": ["actor", "recipient", "witness", "catalyst", "victim", "beneficiary"],
                                        "description": "Role played in this event"
                                    },
                                    "state_change": {
                                        "type": ["string", "null"],
                                        "description": "How this participant changed (optional)"
                                    }
                                },
                                "required": ["entity_name", "entity_type", "role_in_event"]
                            },
                            "description": "Entities involved in this event"
                        },
                        "temporal_marker": {
                            "type": "string",
                            "enum": ["immediate", "moments_later", "minutes_later", "hours_later", "days_later", "weeks_later", "months_later", "years_later", "simultaneous", "flashback"],
                            "description": "When this event occurs relative to previous"
                        },
                        "significance_level": {
                            "type": "string",
                            "enum": ["minor", "moderate", "major", "critical"],
                            "description": "How significant this event is"
                        },
                        "causal_links": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            },
                            "description": "References to events this is caused by or causes"
                        },
                        "emotional_tone": {
                            "type": "string",
                            "description": "Emotional quality of the event"
                        },
                        "world_state_changes": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            },
                            "description": "What changed in the world state"
                        }
                    },
                    "required": ["event_type", "summary", "participants", "temporal_marker", "significance_level", "emotional_tone"]
                },
                "description": "Chronicle events extracted from narrative"
            },
            "temporal_context": {
                "type": "object",
                "properties": {
                    "sequence_position": {
                        "type": "string",
                        "enum": ["beginning", "rising_action", "climax", "falling_action", "resolution", "ongoing", "flashback", "flash_forward"],
                        "description": "Position in narrative sequence"
                    },
                    "pacing": {
                        "type": "string",
                        "enum": ["rapid", "steady", "slow", "time_skip", "montage", "real_time"],
                        "description": "Pacing of events"
                    },
                    "duration": {
                        "type": "string",
                        "enum": ["instant", "seconds", "minutes", "hours", "days", "weeks", "months", "years", "unspecified"],
                        "description": "Time span covered"
                    },
                    "chronological_markers": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        },
                        "description": "Specific time references found"
                    }
                },
                "required": ["sequence_position", "pacing", "duration", "chronological_markers"]
            },
            "narrative_significance": {
                "type": "object",
                "properties": {
                    "plot_advancement": {
                        "type": "boolean",
                        "description": "Does this advance the plot?"
                    },
                    "character_development": {
                        "type": "boolean",
                        "description": "Does this develop characters?"
                    },
                    "world_building": {
                        "type": "boolean",
                        "description": "Does this build the world?"
                    },
                    "relationship_evolution": {
                        "type": "boolean",
                        "description": "Does this evolve relationships?"
                    },
                    "thematic_relevance": {
                        "type": "string",
                        "description": "How this relates to story themes"
                    },
                    "chronicle_worthiness_score": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1,
                        "description": "Score from 0-1 of how chronicle-worthy this is"
                    }
                },
                "required": ["plot_advancement", "character_development", "world_building", "relationship_evolution", "thematic_relevance", "chronicle_worthiness_score"]
            }
        },
        "required": ["events", "temporal_context", "narrative_significance"]
    })
}

/// Validation for structured output
impl ChronicleEventExtractionOutput {
    pub fn validate(&self) -> Result<(), AppError> {
        // Must have at least one event if significance is high
        if self.narrative_significance.chronicle_worthiness_score > 0.5 && self.events.is_empty() {
            return Err(AppError::InvalidInput(
                "High significance narrative must contain at least one event".to_string()
            ));
        }
        
        // Validate each event
        for (idx, event) in self.events.iter().enumerate() {
            // Summary must not be empty
            if event.summary.trim().is_empty() {
                return Err(AppError::InvalidInput(
                    format!("Event {} summary cannot be empty", idx)
                ));
            }
            
            // Must have at least one participant
            if event.participants.is_empty() {
                return Err(AppError::InvalidInput(
                    format!("Event {} must have at least one participant", idx)
                ));
            }
            
            // Validate participants
            for participant in &event.participants {
                if participant.entity_name.trim().is_empty() {
                    return Err(AppError::InvalidInput(
                        "Participant name cannot be empty".to_string()
                    ));
                }
            }
            
            // Validate event type
            let valid_event_types = [
                "dialogue", "action", "discovery", "conflict", "resolution",
                "transition", "revelation", "decision", "consequence"
            ];
            if !valid_event_types.contains(&event.event_type.as_str()) {
                return Err(AppError::InvalidInput(
                    format!("Invalid event type: {}", event.event_type)
                ));
            }
            
            // Validate significance level
            let valid_significance = ["minor", "moderate", "major", "critical"];
            if !valid_significance.contains(&event.significance_level.as_str()) {
                return Err(AppError::InvalidInput(
                    format!("Invalid significance level: {}", event.significance_level)
                ));
            }
        }
        
        // Validate temporal context
        let valid_positions = [
            "beginning", "rising_action", "climax", "falling_action", 
            "resolution", "ongoing", "flashback", "flash_forward"
        ];
        if !valid_positions.contains(&self.temporal_context.sequence_position.as_str()) {
            return Err(AppError::InvalidInput(
                format!("Invalid sequence position: {}", self.temporal_context.sequence_position)
            ));
        }
        
        // Validate chronicle worthiness score
        if self.narrative_significance.chronicle_worthiness_score < 0.0 || 
           self.narrative_significance.chronicle_worthiness_score > 1.0 {
            return Err(AppError::InvalidInput(
                "Chronicle worthiness score must be between 0 and 1".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Convert to internal chronicle event creation format
    pub fn to_chronicle_events(&self) -> Vec<ChronicleEventData> {
        self.events.iter().map(|event| {
            ChronicleEventData {
                event_type: event.event_type.clone(),
                summary: event.summary.clone(),
                actors: event.participants.iter().map(|p| ActorData {
                    entity_name: p.entity_name.clone(),
                    entity_type: p.entity_type.clone(),
                    role: p.role_in_event.clone(),
                }).collect(),
                emotional_tone: event.emotional_tone.clone(),
                significance_level: event.significance_level.clone(),
                world_state_changes: event.world_state_changes.clone(),
            }
        }).collect()
    }
}

/// Internal data structure for chronicle event creation
#[derive(Debug, Clone)]
pub struct ChronicleEventData {
    pub event_type: String,
    pub summary: String,
    pub actors: Vec<ActorData>,
    pub emotional_tone: String,
    pub significance_level: String,
    pub world_state_changes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ActorData {
    pub entity_name: String,
    pub entity_type: String,
    pub role: String,
}

/// Helper to determine if narrative should be processed
impl NarrativeSignificanceOutput {
    pub fn should_chronicle(&self) -> bool {
        // Chronicle if score is above threshold or any major narrative element is present
        self.chronicle_worthiness_score > 0.3 ||
        self.plot_advancement ||
        self.character_development ||
        self.relationship_evolution
    }
}