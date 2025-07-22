use serde::{Deserialize, Serialize};

/// Shared types for the hierarchical agent framework

/// Strategic directive type from the Strategic Agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategicDirective {
    pub directive_type: DirectiveType,
    pub emotional_tone: String,
    pub narrative_focus: String,
    pub character_motivation: String,
    pub scene_context: String,
    pub suggested_complications: Vec<String>,
    pub pacing_guidance: String,
}

/// Directive types for strategic planning
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DirectiveType {
    DramaticEscalation,
    EmotionalRevelation,
    MysteryIntroduction,
    CharacterDevelopment,
    WorldBuilding,
    TensionRelease,
    RelationshipEvolution,
    PlotAdvancement,
    AtmosphericImmersion,
    ConflictResolution,
    InternalStruggle,
    ExternalChallenge,
}

/// Enriched context from the Tactical Agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedContext {
    pub immediate_focus: String,
    pub relevant_world_elements: Vec<WorldElement>,
    pub character_relationships: Vec<CharacterRelationship>,
    pub environmental_factors: Vec<String>,
    pub available_actions: Vec<String>,
    pub hidden_information: Vec<String>,
    pub narrative_constraints: Vec<String>,
    pub opportunity_spaces: Vec<String>,
}

/// World element for tactical enrichment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorldElement {
    pub element_name: String,
    pub element_type: String,
    pub relevance: String,
    pub interaction_potential: String,
}

/// Character relationship for tactical enrichment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CharacterRelationship {
    pub character_name: String,
    pub relationship_type: String,
    pub current_status: String,
    pub emotional_weight: String,
}