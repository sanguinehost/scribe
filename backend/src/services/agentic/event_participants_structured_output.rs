use serde::{Deserialize, Serialize};
use crate::errors::AppError;

/// Structured output schema for Event Participants Analysis
/// Ensures AI generates comprehensive participant analysis with roles and relationships

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventParticipantsOutput {
    pub primary_participants: Vec<EventParticipant>, // Main actors/agents in the event
    pub secondary_participants: Vec<EventParticipant>, // Supporting roles or observers
    pub mentioned_participants: Vec<EventParticipant>, // Entities referenced but not directly involved
    pub participant_relationships: Vec<ParticipantRelationship>, // How participants relate to each other
    pub participant_count: u32, // Total unique participant count
    pub confidence_score: f32, // Overall confidence in the participant analysis (0.0-1.0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventParticipant {
    pub entity_name: String, // Name/identifier of the participant
    pub entity_id: Option<String>, // UUID if already known
    pub role: String, // "agent", "patient", "observer", "facilitator", "victim", "beneficiary", etc.
    pub involvement_type: String, // "active", "passive", "mentioned", "indirect"
    pub actions: Vec<String>, // What this participant did in the event
    pub confidence: f32, // Confidence in this participant's involvement (0.0-1.0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantRelationship {
    pub from_participant: String, // Name of first participant
    pub to_participant: String, // Name of second participant
    pub relationship_type: String, // "cooperates_with", "opposes", "helps", "hinders", "observes"
    pub relationship_context: String, // Brief description of their interaction
    pub strength: f32, // Strength of the relationship in this event (0.0-1.0)
}

/// Helper function to create the JSON schema for event participants analysis
pub fn get_event_participants_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "primary_participants": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "entity_name": {
                            "type": "string",
                            "description": "Name or identifier of the participant"
                        },
                        "entity_id": {
                            "type": "string",
                            "description": "UUID of the entity if already known (optional)"
                        },
                        "role": {
                            "type": "string",
                            "enum": ["agent", "patient", "observer", "facilitator", "victim", "beneficiary", "antagonist", "mediator", "witness"],
                            "description": "The participant's role in the event"
                        },
                        "involvement_type": {
                            "type": "string",
                            "enum": ["active", "passive", "mentioned", "indirect", "implied"],
                            "description": "How the participant is involved"
                        },
                        "actions": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            },
                            "description": "List of actions this participant performed"
                        },
                        "confidence": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                            "description": "Confidence in this participant's involvement"
                        }
                    },
                    "required": ["entity_name", "role", "involvement_type", "actions", "confidence"]
                },
                "description": "Main actors or agents directly involved in the event"
            },
            "secondary_participants": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "entity_name": {
                            "type": "string",
                            "description": "Name or identifier of the participant"
                        },
                        "entity_id": {
                            "type": "string",
                            "description": "UUID of the entity if already known (optional)"
                        },
                        "role": {
                            "type": "string",
                            "enum": ["agent", "patient", "observer", "facilitator", "victim", "beneficiary", "antagonist", "mediator", "witness"],
                            "description": "The participant's role in the event"
                        },
                        "involvement_type": {
                            "type": "string",
                            "enum": ["active", "passive", "mentioned", "indirect", "implied"],
                            "description": "How the participant is involved"
                        },
                        "actions": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            },
                            "description": "List of actions this participant performed"
                        },
                        "confidence": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                            "description": "Confidence in this participant's involvement"
                        }
                    },
                    "required": ["entity_name", "role", "involvement_type", "actions", "confidence"]
                },
                "description": "Supporting participants or observers"
            },
            "mentioned_participants": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "entity_name": {
                            "type": "string",
                            "description": "Name or identifier of the participant"
                        },
                        "entity_id": {
                            "type": "string",
                            "description": "UUID of the entity if already known (optional)"
                        },
                        "role": {
                            "type": "string",
                            "enum": ["agent", "patient", "observer", "facilitator", "victim", "beneficiary", "antagonist", "mediator", "witness"],
                            "description": "The participant's role in the event"
                        },
                        "involvement_type": {
                            "type": "string",
                            "enum": ["active", "passive", "mentioned", "indirect", "implied"],
                            "description": "How the participant is involved"
                        },
                        "actions": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            },
                            "description": "List of actions this participant performed"
                        },
                        "confidence": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                            "description": "Confidence in this participant's involvement"
                        }
                    },
                    "required": ["entity_name", "role", "involvement_type", "actions", "confidence"]
                },
                "description": "Entities referenced but not directly participating"
            },
            "participant_relationships": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "from_participant": {
                            "type": "string",
                            "description": "Name of the first participant in the relationship"
                        },
                        "to_participant": {
                            "type": "string",
                            "description": "Name of the second participant in the relationship"
                        },
                        "relationship_type": {
                            "type": "string",
                            "enum": ["cooperates_with", "opposes", "helps", "hinders", "observes", "commands", "follows", "negotiates_with", "protects", "threatens"],
                            "description": "Type of relationship between participants in this event"
                        },
                        "relationship_context": {
                            "type": "string",
                            "description": "Brief description of how they interact in this event"
                        },
                        "strength": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                            "description": "Strength of the relationship in this event"
                        }
                    },
                    "required": ["from_participant", "to_participant", "relationship_type", "relationship_context", "strength"]
                },
                "description": "Relationships between participants in this event"
            },
            "participant_count": {
                "type": "integer",
                "minimum": 0,
                "description": "Total number of unique participants"
            },
            "confidence_score": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Overall confidence in the participant analysis"
            }
        },
        "required": [
            "primary_participants",
            "secondary_participants",
            "mentioned_participants",
            "participant_relationships",
            "participant_count",
            "confidence_score"
        ]
    })
}

/// Validation for structured output
impl EventParticipantsOutput {
    pub fn validate(&self) -> Result<(), AppError> {
        // Validate confidence score
        if self.confidence_score < 0.0 || self.confidence_score > 1.0 {
            return Err(AppError::InvalidInput(
                "Overall confidence score must be between 0.0 and 1.0".to_string()
            ));
        }
        
        // Validate primary participants
        for participant in &self.primary_participants {
            if participant.entity_name.trim().is_empty() {
                return Err(AppError::InvalidInput(
                    "Participant name cannot be empty".to_string()
                ));
            }
            if participant.confidence < 0.0 || participant.confidence > 1.0 {
                return Err(AppError::InvalidInput(
                    "Participant confidence must be between 0.0 and 1.0".to_string()
                ));
            }
        }
        
        // Validate secondary participants
        for participant in &self.secondary_participants {
            if participant.entity_name.trim().is_empty() {
                return Err(AppError::InvalidInput(
                    "Secondary participant name cannot be empty".to_string()
                ));
            }
            if participant.confidence < 0.0 || participant.confidence > 1.0 {
                return Err(AppError::InvalidInput(
                    "Secondary participant confidence must be between 0.0 and 1.0".to_string()
                ));
            }
        }
        
        // Validate relationships
        for relationship in &self.participant_relationships {
            if relationship.from_participant.trim().is_empty() || 
               relationship.to_participant.trim().is_empty() {
                return Err(AppError::InvalidInput(
                    "Relationship participants cannot be empty".to_string()
                ));
            }
            if relationship.strength < 0.0 || relationship.strength > 1.0 {
                return Err(AppError::InvalidInput(
                    "Relationship strength must be between 0.0 and 1.0".to_string()
                ));
            }
        }
        
        // Validate participant count
        let total_unique_participants = self.get_all_unique_participants().len();
        if self.participant_count != total_unique_participants as u32 {
            return Err(AppError::InvalidInput(
                format!("Participant count mismatch: reported {}, actual {}", 
                        self.participant_count, total_unique_participants)
            ));
        }
        
        Ok(())
    }
    
    /// Get all unique participants across all categories
    pub fn get_all_unique_participants(&self) -> Vec<String> {
        let mut participants = std::collections::HashSet::new();
        
        for p in &self.primary_participants {
            participants.insert(p.entity_name.clone());
        }
        for p in &self.secondary_participants {
            participants.insert(p.entity_name.clone());
        }
        for p in &self.mentioned_participants {
            participants.insert(p.entity_name.clone());
        }
        
        participants.into_iter().collect()
    }
    
    /// Convert to simple UUID list for backward compatibility
    pub fn to_participant_ids(&self, exclude_entity_id: Option<uuid::Uuid>) -> Vec<uuid::Uuid> {
        let mut participant_ids = Vec::new();
        
        // Collect all entity IDs that are UUIDs
        let all_participants = self.primary_participants.iter()
            .chain(self.secondary_participants.iter())
            .chain(self.mentioned_participants.iter());
        
        for participant in all_participants {
            if let Some(id_str) = &participant.entity_id {
                if let Ok(uuid) = uuid::Uuid::parse_str(id_str) {
                    if Some(uuid) != exclude_entity_id {
                        participant_ids.push(uuid);
                    }
                }
            }
        }
        
        // Remove duplicates
        participant_ids.sort();
        participant_ids.dedup();
        
        participant_ids
    }
}