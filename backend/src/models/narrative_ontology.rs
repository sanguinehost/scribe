//! Ars Fabula Narrative Event Ontology
//! 
//! This module implements the formal narrative event ontology as described in the 
//! Ars Fabula architectural blueprint. It provides a comprehensive, machine-readable
//! specification of narrative events that serves as the quantum of story.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use uuid::Uuid;
use validator::Validate;


/// EventModality represents the reality status of an event in the narrative
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EventModality {
    /// Part of the ground-truth Fabula (objective reality)
    Actual,
    /// Part of a plan or possibility space
    Hypothetical,
    /// What could have happened (counterfactual)
    Counterfactual,
    /// Believed to be true by a specific agent (subjective belief)
    #[serde(rename = "BELIEVED_BY")]
    BelievedBy(Uuid), // Agent ID who believes this
}

impl<'de> Deserialize<'de> for EventModality {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_uppercase().as_str() {
            "ACTUAL" => Ok(EventModality::Actual),
            "HYPOTHETICAL" => Ok(EventModality::Hypothetical),
            "COUNTERFACTUAL" => Ok(EventModality::Counterfactual),
            _ => {
                // Handle BELIEVED_BY variant with UUID
                if s.to_uppercase().starts_with("BELIEVED_BY") {
                    // Extract UUID from "BELIEVED_BY(uuid)" or "BELIEVED_BY:uuid" format
                    let uuid_str = if let Some(start) = s.find('(') {
                        if let Some(end) = s.rfind(')') {
                            &s[start + 1..end]
                        } else {
                            return Err(serde::de::Error::custom("Invalid BELIEVED_BY format: missing closing parenthesis"));
                        }
                    } else if let Some(colon_pos) = s.find(':') {
                        &s[colon_pos + 1..]
                    } else {
                        return Err(serde::de::Error::custom("Invalid BELIEVED_BY format: missing UUID"));
                    };
                    
                    match Uuid::parse_str(uuid_str.trim()) {
                        Ok(uuid) => Ok(EventModality::BelievedBy(uuid)),
                        Err(_) => Err(serde::de::Error::custom(format!("Invalid UUID in BELIEVED_BY: {}", uuid_str))),
                    }
                } else {
                    Err(serde::de::Error::unknown_variant(
                        &s,
                        &["ACTUAL", "HYPOTHETICAL", "COUNTERFACTUAL", "BELIEVED_BY"],
                    ))
                }
            }
        }
    }
}

impl Default for EventModality {
    fn default() -> Self {
        EventModality::Actual
    }
}

/// ActorRole defines the narrative function of participants in an event
/// Based on Vladimir Propp's dramatis personae and semantic role theory
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ActorRole {
    /// The entity that initiates the action
    Agent,
    /// The entity being acted upon
    Patient,
    /// The entity that benefits from the action
    Beneficiary,
    /// The tool or means used to perform the action
    Instrument,
    /// The entity that helps the agent
    Helper,
    /// The entity that opposes the agent
    Opponent,
    /// Witnesses or observers without direct involvement
    Witness,
}

impl<'de> Deserialize<'de> for ActorRole {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_uppercase().as_str() {
            "AGENT" => Ok(ActorRole::Agent),
            "PATIENT" => Ok(ActorRole::Patient),
            "BENEFICIARY" => Ok(ActorRole::Beneficiary),
            "INSTRUMENT" => Ok(ActorRole::Instrument),
            "HELPER" => Ok(ActorRole::Helper),
            "OPPONENT" => Ok(ActorRole::Opponent),
            "WITNESS" => Ok(ActorRole::Witness),
            _ => Err(serde::de::Error::unknown_variant(
                &s,
                &["AGENT", "PATIENT", "BENEFICIARY", "INSTRUMENT", "HELPER", "OPPONENT", "WITNESS"],
            )),
        }
    }
}

/// EventActor represents an entity participating in a narrative event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventActor {
    /// Unique identifier of the entity
    pub entity_id: Uuid,
    /// The role this entity plays in the event
    pub role: ActorRole,
    /// Optional additional context about this actor's participation
    pub context: Option<String>,
}

/// EventContext captures the spatio-temporal and situational context
/// Analogous to Labov's "Orientation" phase in narrative structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventContext {
    /// Where the event took place
    pub location_id: Option<Uuid>,
    /// Specific area within the location
    pub sub_location: Option<String>,
    /// Time of day when event occurred
    pub time_of_day: Option<String>,
    /// Weather conditions
    pub weather: Option<String>,
    /// Social or cultural context
    pub social_context: Option<String>,
    /// Any other environmental factors
    pub environmental_factors: Option<HashMap<String, JsonValue>>,
}

/// EventCausality represents the causal relationships between events
/// Forms a directed acyclic graph (DAG) of cause and effect
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventCausality {
    /// Events that were necessary conditions for this event
    pub caused_by: Vec<Uuid>,
    /// Events that this event directly caused
    pub causes: Vec<Uuid>,
    /// Confidence level in these causal relationships (0.0-1.0)
    pub confidence: f32,
}

impl Default for EventCausality {
    fn default() -> Self {
        Self {
            caused_by: Vec::new(),
            causes: Vec::new(),
            confidence: 1.0,
        }
    }
}

/// ValenceType represents different types of emotional/relational impact
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ValenceType {
    /// Impact on trust relationships
    Trust,
    /// Impact on affection/liking
    Affection,
    /// Impact on respect/admiration
    Respect,
    /// Impact on fear/intimidation
    Fear,
    /// Impact on character power/influence
    Power,
    /// Impact on character knowledge/wisdom
    Knowledge,
    /// Impact on character wealth/resources
    Wealth,
    /// Impact on character health/wellbeing
    Health,
    /// Impact on character reputation
    Reputation,
    /// Custom/domain-specific valence
    #[serde(rename = "CUSTOM")]
    Custom(String),
}

impl<'de> Deserialize<'de> for ValenceType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_uppercase().as_str() {
            "TRUST" => Ok(ValenceType::Trust),
            "AFFECTION" => Ok(ValenceType::Affection),
            "RESPECT" => Ok(ValenceType::Respect),
            "FEAR" => Ok(ValenceType::Fear),
            "POWER" => Ok(ValenceType::Power),
            "KNOWLEDGE" => Ok(ValenceType::Knowledge),
            "WEALTH" => Ok(ValenceType::Wealth),
            "HEALTH" => Ok(ValenceType::Health),
            "REPUTATION" => Ok(ValenceType::Reputation),
            other => {
                // Handle custom valence types
                if other.starts_with("CUSTOM") {
                    let custom_value = if other == "CUSTOM" {
                        String::new()
                    } else if let Some(colon_pos) = other.find(':') {
                        other[colon_pos + 1..].to_string()
                    } else {
                        other.to_string()
                    };
                    Ok(ValenceType::Custom(custom_value))
                } else {
                    Err(serde::de::Error::unknown_variant(
                        &s,
                        &["TRUST", "AFFECTION", "RESPECT", "FEAR", "POWER", "KNOWLEDGE", 
                          "WEALTH", "HEALTH", "REPUTATION", "CUSTOM"],
                    ))
                }
            }
        }
    }
}

/// EventValence represents the emotional/relational impact of an event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventValence {
    /// The entity being impacted
    pub target: Uuid,
    /// Type of impact
    pub valence_type: ValenceType,
    /// Magnitude of change (-1.0 to 1.0, negative is harmful, positive is beneficial)
    pub change: f32,
    /// Optional context about the impact
    pub description: Option<String>,
}

/// Core action verbs that can occur in narrative events
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NarrativeAction {
    // Discovery and revelation actions
    Discovered,
    Revealed,
    Uncovered,
    Found,
    
    // Social and relationship actions
    Met,
    Befriended,
    Betrayed,
    Married,
    Divorced,
    
    // Conflict actions
    Attacked,
    Defended,
    Defeated,
    Fled,
    
    // Acquisition and loss actions
    Acquired,
    Lost,
    Gave,
    Stole,
    
    // Transformation actions
    Transformed,
    Evolved,
    Died,
    Resurrected,
    
    // Communication actions
    Told,
    Asked,
    Lied,
    Confessed,
    
    // Decision and commitment actions
    Decided,
    Committed,
    Refused,
    Abandoned,
    
    // Custom action for domain-specific verbs
    #[serde(rename = "CUSTOM")]
    Custom(String),
}

impl<'de> Deserialize<'de> for NarrativeAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_uppercase().as_str() {
            "DISCOVERED" => Ok(NarrativeAction::Discovered),
            "REVEALED" => Ok(NarrativeAction::Revealed),
            "UNCOVERED" => Ok(NarrativeAction::Uncovered),
            "FOUND" => Ok(NarrativeAction::Found),
            "MET" => Ok(NarrativeAction::Met),
            "BEFRIENDED" => Ok(NarrativeAction::Befriended),
            "BETRAYED" => Ok(NarrativeAction::Betrayed),
            "MARRIED" => Ok(NarrativeAction::Married),
            "DIVORCED" => Ok(NarrativeAction::Divorced),
            "ATTACKED" => Ok(NarrativeAction::Attacked),
            "DEFENDED" => Ok(NarrativeAction::Defended),
            "DEFEATED" => Ok(NarrativeAction::Defeated),
            "FLED" => Ok(NarrativeAction::Fled),
            "ACQUIRED" => Ok(NarrativeAction::Acquired),
            "LOST" => Ok(NarrativeAction::Lost),
            "GAVE" => Ok(NarrativeAction::Gave),
            "STOLE" => Ok(NarrativeAction::Stole),
            "TRANSFORMED" => Ok(NarrativeAction::Transformed),
            "EVOLVED" => Ok(NarrativeAction::Evolved),
            "DIED" => Ok(NarrativeAction::Died),
            "RESURRECTED" => Ok(NarrativeAction::Resurrected),
            "TOLD" => Ok(NarrativeAction::Told),
            "ASKED" => Ok(NarrativeAction::Asked),
            "LIED" => Ok(NarrativeAction::Lied),
            "CONFESSED" => Ok(NarrativeAction::Confessed),
            "DECIDED" => Ok(NarrativeAction::Decided),
            "COMMITTED" => Ok(NarrativeAction::Committed),
            "REFUSED" => Ok(NarrativeAction::Refused),
            "ABANDONED" => Ok(NarrativeAction::Abandoned),
            other => {
                // Handle custom actions by checking if it starts with "CUSTOM:"
                if other.starts_with("CUSTOM") {
                    let custom_value = if other == "CUSTOM" {
                        String::new()
                    } else if let Some(colon_pos) = other.find(':') {
                        other[colon_pos + 1..].to_string()
                    } else {
                        other.to_string()
                    };
                    Ok(NarrativeAction::Custom(custom_value))
                } else {
                    Err(serde::de::Error::unknown_variant(
                        &s,
                        &["DISCOVERED", "REVEALED", "UNCOVERED", "FOUND", "MET", "BEFRIENDED", 
                          "BETRAYED", "MARRIED", "DIVORCED", "ATTACKED", "DEFENDED", "DEFEATED", 
                          "FLED", "ACQUIRED", "LOST", "GAVE", "STOLE", "TRANSFORMED", "EVOLVED", 
                          "DIED", "RESURRECTED", "TOLD", "ASKED", "LIED", "CONFESSED", "DECIDED", 
                          "COMMITTED", "REFUSED", "ABANDONED", "CUSTOM"],
                    ))
                }
            }
        }
    }
}

/// Complete Ars Fabula narrative event structure
/// This is the "quantum of story" - the fundamental unit of narrative information
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct NarrativeEvent {
    /// Universally unique identifier for this event instance
    pub event_id: Uuid,
    
    /// ISO 8601 timestamp when the event concluded in the world
    pub timestamp: DateTime<Utc>,
    
    /// Hierarchical classification using dot-notation
    #[validate(length(min = 1, max = 200, message = "Event type must be between 1 and 200 characters"))]
    pub event_type: String,
    
    /// All entities participating in the event with their roles
    pub actors: Vec<EventActor>,
    
    /// The core action/verb of the event
    pub action: NarrativeAction,
    
    /// The primary entity being acted upon (if any)
    pub object: Option<Uuid>,
    
    /// Spatio-temporal and situational context
    pub context: Option<EventContext>,
    
    /// Causal relationships to other events
    pub causality: EventCausality,
    
    /// Emotional/relational impacts of the event
    pub valence: Vec<EventValence>,
    
    /// Reality status of the event
    pub modality: EventModality,
    
    /// Human-readable summary of what happened
    #[validate(length(min = 1, max = 5000, message = "Summary must be between 1 and 5000 characters"))]
    pub summary: String,
    
    /// Additional structured metadata
    pub metadata: Option<JsonValue>,
}

impl NarrativeEvent {
    /// Create a new narrative event with required fields
    pub fn new(
        event_type: String,
        action: NarrativeAction,
        summary: String,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            actors: Vec::new(),
            action,
            object: None,
            context: None,
            causality: EventCausality::default(),
            valence: Vec::new(),
            modality: EventModality::default(),
            summary,
            metadata: None,
        }
    }
    
    /// Add an actor to the event
    pub fn add_actor(mut self, entity_id: Uuid, role: ActorRole) -> Self {
        self.actors.push(EventActor {
            entity_id,
            role,
            context: None,
        });
        self
    }
    
    /// Add an actor with context
    pub fn add_actor_with_context(mut self, entity_id: Uuid, role: ActorRole, context: String) -> Self {
        self.actors.push(EventActor {
            entity_id,
            role,
            context: Some(context),
        });
        self
    }
    
    /// Set the object of the event
    pub fn with_object(mut self, object_id: Uuid) -> Self {
        self.object = Some(object_id);
        self
    }
    
    /// Set the context of the event
    pub fn with_context(mut self, context: EventContext) -> Self {
        self.context = Some(context);
        self
    }
    
    /// Add a causal relationship (this event was caused by another)
    pub fn caused_by(mut self, cause_event_id: Uuid) -> Self {
        self.causality.caused_by.push(cause_event_id);
        self
    }
    
    /// Add a valence (emotional/relational impact)
    pub fn add_valence(mut self, target: Uuid, valence_type: ValenceType, change: f32) -> Self {
        self.valence.push(EventValence {
            target,
            valence_type,
            change,
            description: None,
        });
        self
    }
    
    /// Set the modality (reality status)
    pub fn with_modality(mut self, modality: EventModality) -> Self {
        self.modality = modality;
        self
    }
    
    /// Get the primary agent (initiator) of the event
    pub fn get_primary_agent(&self) -> Option<&EventActor> {
        self.actors.iter().find(|actor| actor.role == ActorRole::Agent)
    }
    
    /// Get the primary patient (target) of the event
    pub fn get_primary_patient(&self) -> Option<&EventActor> {
        self.actors.iter().find(|actor| actor.role == ActorRole::Patient)
    }
    
    /// Get all actors with a specific role
    pub fn get_actors_by_role(&self, role: &ActorRole) -> Vec<&EventActor> {
        self.actors.iter().filter(|actor| &actor.role == role).collect()
    }
    
    /// Check if an entity participated in this event
    pub fn involves_entity(&self, entity_id: &Uuid) -> bool {
        self.actors.iter().any(|actor| &actor.entity_id == entity_id) ||
        self.object.as_ref() == Some(entity_id)
    }
    
    /// Get the emotional impact on a specific entity
    pub fn get_valence_for_entity(&self, entity_id: &Uuid) -> Vec<&EventValence> {
        self.valence.iter().filter(|v| &v.target == entity_id).collect()
    }
}

/// Builder for constructing complex narrative events
pub struct NarrativeEventBuilder {
    event: NarrativeEvent,
}

impl NarrativeEventBuilder {
    pub fn new(event_type: String, action: NarrativeAction, summary: String) -> Self {
        Self {
            event: NarrativeEvent::new(event_type, action, summary),
        }
    }
    
    pub fn agent(self, entity_id: Uuid) -> Self {
        self.add_actor(entity_id, ActorRole::Agent)
    }
    
    pub fn patient(self, entity_id: Uuid) -> Self {
        self.add_actor(entity_id, ActorRole::Patient)
    }
    
    pub fn helper(self, entity_id: Uuid) -> Self {
        self.add_actor(entity_id, ActorRole::Helper)
    }
    
    pub fn opponent(self, entity_id: Uuid) -> Self {
        self.add_actor(entity_id, ActorRole::Opponent)
    }
    
    pub fn witness(self, entity_id: Uuid) -> Self {
        self.add_actor(entity_id, ActorRole::Witness)
    }
    
    pub fn add_actor(mut self, entity_id: Uuid, role: ActorRole) -> Self {
        self.event = self.event.add_actor(entity_id, role);
        self
    }
    
    pub fn object(mut self, object_id: Uuid) -> Self {
        self.event = self.event.with_object(object_id);
        self
    }
    
    pub fn at_location(mut self, location_id: Uuid) -> Self {
        let context = self.event.context.get_or_insert_with(|| EventContext {
            location_id: None,
            sub_location: None,
            time_of_day: None,
            weather: None,
            social_context: None,
            environmental_factors: None,
        });
        context.location_id = Some(location_id);
        self
    }
    
    pub fn at_time(mut self, time_of_day: String) -> Self {
        let context = self.event.context.get_or_insert_with(|| EventContext {
            location_id: None,
            sub_location: None,
            time_of_day: None,
            weather: None,
            social_context: None,
            environmental_factors: None,
        });
        context.time_of_day = Some(time_of_day);
        self
    }
    
    pub fn caused_by(mut self, cause_event_id: Uuid) -> Self {
        self.event = self.event.caused_by(cause_event_id);
        self
    }
    
    pub fn impacts_trust(mut self, target: Uuid, change: f32) -> Self {
        self.event = self.event.add_valence(target, ValenceType::Trust, change);
        self
    }
    
    pub fn impacts_affection(mut self, target: Uuid, change: f32) -> Self {
        self.event = self.event.add_valence(target, ValenceType::Affection, change);
        self
    }
    
    pub fn impacts_respect(mut self, target: Uuid, change: f32) -> Self {
        self.event = self.event.add_valence(target, ValenceType::Respect, change);
        self
    }
    
    pub fn believed_by(mut self, agent_id: Uuid) -> Self {
        self.event = self.event.with_modality(EventModality::BelievedBy(agent_id));
        self
    }
    
    pub fn hypothetical(mut self) -> Self {
        self.event = self.event.with_modality(EventModality::Hypothetical);
        self
    }
    
    pub fn build(self) -> NarrativeEvent {
        self.event
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_narrative_event_creation() {
        let event = NarrativeEvent::new(
            "CHARACTER.DEVELOPMENT.SKILL_GAINED".to_string(),
            NarrativeAction::Acquired,
            "The hero learned the art of swordplay".to_string(),
        );
        
        assert!(!event.event_id.is_nil());
        assert_eq!(event.event_type, "CHARACTER.DEVELOPMENT.SKILL_GAINED");
        assert_eq!(event.action, NarrativeAction::Acquired);
        assert_eq!(event.summary, "The hero learned the art of swordplay");
        assert_eq!(event.modality, EventModality::Actual);
    }
    
    #[test]
    fn test_narrative_event_builder() {
        let hero_id = Uuid::new_v4();
        let mentor_id = Uuid::new_v4();
        let location_id = Uuid::new_v4();
        
        let event = NarrativeEventBuilder::new(
            "RELATIONSHIP.FORMATION.MENTORSHIP".to_string(),
            NarrativeAction::Met,
            "The hero met their future mentor".to_string(),
        )
        .agent(hero_id)
        .patient(mentor_id)
        .at_location(location_id)
        .at_time("Dawn".to_string())
        .impacts_trust(hero_id, 0.3)
        .impacts_respect(hero_id, 0.5)
        .build();
        
        assert_eq!(event.actors.len(), 2);
        assert_eq!(event.get_primary_agent().unwrap().entity_id, hero_id);
        assert_eq!(event.get_primary_patient().unwrap().entity_id, mentor_id);
        assert!(event.involves_entity(&hero_id));
        assert!(event.involves_entity(&mentor_id));
        assert_eq!(event.context.as_ref().unwrap().location_id, Some(location_id));
        assert_eq!(event.context.as_ref().unwrap().time_of_day, Some("Dawn".to_string()));
        assert_eq!(event.valence.len(), 2);
    }
    
    #[test]
    fn test_event_modality() {
        let agent_id = Uuid::new_v4();
        
        let actual_event = NarrativeEvent::new(
            "WORLD.DISCOVERY.LOCATION".to_string(),
            NarrativeAction::Discovered,
            "A new cave was found".to_string(),
        );
        assert_eq!(actual_event.modality, EventModality::Actual);
        
        let believed_event = NarrativeEvent::new(
            "WORLD.DISCOVERY.LOCATION".to_string(),
            NarrativeAction::Discovered,
            "A new cave was found".to_string(),
        ).with_modality(EventModality::BelievedBy(agent_id));
        assert_eq!(believed_event.modality, EventModality::BelievedBy(agent_id));
    }

    #[test]
    fn test_actor_role_case_insensitive_deserialization() {
        // Test uppercase (standard format)
        let uppercase = serde_json::from_str::<ActorRole>("\"AGENT\"").unwrap();
        assert_eq!(uppercase, ActorRole::Agent);

        // Test Pascal case (what AI might return)
        let pascal_case = serde_json::from_str::<ActorRole>("\"Agent\"").unwrap();
        assert_eq!(pascal_case, ActorRole::Agent);

        // Test lowercase
        let lowercase = serde_json::from_str::<ActorRole>("\"agent\"").unwrap();
        assert_eq!(lowercase, ActorRole::Agent);

        // Test other roles
        let patient = serde_json::from_str::<ActorRole>("\"Patient\"").unwrap();
        assert_eq!(patient, ActorRole::Patient);

        let beneficiary = serde_json::from_str::<ActorRole>("\"beneficiary\"").unwrap();
        assert_eq!(beneficiary, ActorRole::Beneficiary);
    }

    #[test]
    fn test_narrative_action_case_insensitive_deserialization() {
        // Test uppercase (standard format)
        let uppercase = serde_json::from_str::<NarrativeAction>("\"DISCOVERED\"").unwrap();
        assert_eq!(uppercase, NarrativeAction::Discovered);

        // Test Pascal case (what AI might return)
        let pascal_case = serde_json::from_str::<NarrativeAction>("\"Discovered\"").unwrap();
        assert_eq!(pascal_case, NarrativeAction::Discovered);

        // Test lowercase
        let lowercase = serde_json::from_str::<NarrativeAction>("\"discovered\"").unwrap();
        assert_eq!(lowercase, NarrativeAction::Discovered);

        // Test other actions
        let met = serde_json::from_str::<NarrativeAction>("\"Met\"").unwrap();
        assert_eq!(met, NarrativeAction::Met);

        let betrayed = serde_json::from_str::<NarrativeAction>("\"betrayed\"").unwrap();
        assert_eq!(betrayed, NarrativeAction::Betrayed);
    }

    #[test]
    fn test_valence_type_case_insensitive_deserialization() {
        // Test uppercase (standard format)
        let uppercase = serde_json::from_str::<ValenceType>("\"TRUST\"").unwrap();
        assert_eq!(uppercase, ValenceType::Trust);

        // Test Pascal case (what AI might return)
        let pascal_case = serde_json::from_str::<ValenceType>("\"Trust\"").unwrap();
        assert_eq!(pascal_case, ValenceType::Trust);

        // Test lowercase
        let lowercase = serde_json::from_str::<ValenceType>("\"trust\"").unwrap();
        assert_eq!(lowercase, ValenceType::Trust);

        // Test other valence types
        let affection = serde_json::from_str::<ValenceType>("\"Affection\"").unwrap();
        assert_eq!(affection, ValenceType::Affection);

        let power = serde_json::from_str::<ValenceType>("\"POWER\"").unwrap();
        assert_eq!(power, ValenceType::Power);
    }

    #[test]
    fn test_event_modality_case_insensitive_deserialization() {
        // Test uppercase (standard format)
        let uppercase = serde_json::from_str::<EventModality>("\"ACTUAL\"").unwrap();
        assert_eq!(uppercase, EventModality::Actual);

        // Test Pascal case (what AI might return)
        let pascal_case = serde_json::from_str::<EventModality>("\"Actual\"").unwrap();
        assert_eq!(pascal_case, EventModality::Actual);

        // Test lowercase
        let lowercase = serde_json::from_str::<EventModality>("\"actual\"").unwrap();
        assert_eq!(lowercase, EventModality::Actual);

        // Test other modalities
        let hypothetical = serde_json::from_str::<EventModality>("\"Hypothetical\"").unwrap();
        assert_eq!(hypothetical, EventModality::Hypothetical);

        let counterfactual = serde_json::from_str::<EventModality>("\"COUNTERFACTUAL\"").unwrap();
        assert_eq!(counterfactual, EventModality::Counterfactual);
    }
}