use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::errors::AppError;

/// Structured output schema for Strategic Agent (Director layer)
/// Ensures AI generates valid strategic directives with proper types

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategicDirectiveOutput {
    pub directive_type: String, // Must be one of the valid directive types
    pub emotional_tone: String, // The emotional tone to set
    pub narrative_focus: String, // Key narrative elements to emphasize  
    pub character_motivation: String, // Character's primary motivation
    pub scene_context: String, // Context about the current scene
    pub suggested_complications: Vec<String>, // Potential narrative complications
    pub pacing_guidance: String, // Guidance on narrative pacing
    pub plot_significance: Option<String>, // Optional: Major, Moderate, Minor, Trivial
    pub world_impact_level: Option<String>, // Optional: Global, Regional, Local, Personal
}

/// Helper function to create the JSON schema for strategic directive generation
pub fn get_strategic_directive_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "directive_type": {
                "type": "string",
                "enum": [
                    "Dramatic Escalation",
                    "Emotional Revelation",
                    "Mystery Introduction",
                    "Character Development",
                    "World Building",
                    "Tension Release",
                    "Relationship Evolution",
                    "Plot Advancement",
                    "Atmospheric Immersion",
                    "Conflict Resolution",
                    "Internal Struggle",
                    "External Challenge"
                ],
                "description": "The type of narrative direction to pursue. Must be one of the exact values listed."
            },
            "emotional_tone": {
                "type": "string",
                "description": "The emotional tone to establish (e.g., 'tense and foreboding', 'warm and hopeful', 'melancholic nostalgia')"
            },
            "narrative_focus": {
                "type": "string",
                "description": "Key narrative elements to emphasize in this interaction"
            },
            "character_motivation": {
                "type": "string",
                "description": "The character's primary motivation driving their actions"
            },
            "scene_context": {
                "type": "string",
                "description": "Important context about the current scene or situation"
            },
            "suggested_complications": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": "Potential complications or twists to introduce"
            },
            "pacing_guidance": {
                "type": "string",
                "description": "Guidance on narrative pacing (e.g., 'slow burn reveal', 'rapid action sequence', 'contemplative pause')"
            },
            "plot_significance": {
                "type": "string",
                "enum": ["Major", "Moderate", "Minor", "Trivial"],
                "description": "The narrative significance level of current events"
            },
            "world_impact_level": {
                "type": "string",
                "enum": ["Global", "Regional", "Local", "Personal"],
                "description": "The scope of impact that current events will have"
            }
        },
        "required": [
            "directive_type",
            "emotional_tone",
            "narrative_focus",
            "character_motivation",
            "scene_context",
            "suggested_complications",
            "pacing_guidance"
        ]
    })
}

/// Convert structured output to internal StrategicDirective type
impl StrategicDirectiveOutput {
    pub fn to_strategic_directive(&self) -> Result<crate::services::context_assembly_engine::StrategicDirective, AppError> {
        use crate::services::context_assembly_engine::{StrategicDirective, PlotSignificance, WorldImpactLevel};
        
        // Validate directive type is from our allowed list
        let valid_types = [
            "Dramatic Escalation", "Emotional Revelation", "Mystery Introduction",
            "Character Development", "World Building", "Tension Release",
            "Relationship Evolution", "Plot Advancement", "Atmospheric Immersion",
            "Conflict Resolution", "Internal Struggle", "External Challenge"
        ];
        
        if !valid_types.contains(&self.directive_type.as_str()) {
            return Err(AppError::InvalidInput(
                format!("Invalid directive type: {}", self.directive_type)
            ));
        }
        
        // Parse plot significance if provided
        let plot_significance = if let Some(ref sig) = self.plot_significance {
            match sig.as_str() {
                "Major" => PlotSignificance::Major,
                "Moderate" => PlotSignificance::Moderate,
                "Minor" => PlotSignificance::Minor,
                "Trivial" => PlotSignificance::Trivial,
                _ => PlotSignificance::Moderate,
            }
        } else {
            PlotSignificance::Moderate
        };
        
        // Parse world impact level if provided
        let world_impact_level = if let Some(ref impact) = self.world_impact_level {
            match impact.as_str() {
                "Global" => WorldImpactLevel::Global,
                "Regional" => WorldImpactLevel::Regional,
                "Local" => WorldImpactLevel::Local,
                "Personal" => WorldImpactLevel::Personal,
                _ => WorldImpactLevel::Local,
            }
        } else {
            WorldImpactLevel::Local
        };
        
        // Extract character focus from narrative focus and character motivation
        let character_focus = vec![]; // Will be populated by the strategic agent if needed
        
        Ok(StrategicDirective {
            directive_id: Uuid::new_v4(),
            directive_type: self.directive_type.clone(),
            narrative_arc: self.narrative_focus.clone(), // Using narrative_focus as narrative_arc
            plot_significance,
            emotional_tone: self.emotional_tone.clone(),
            character_focus,
            world_impact_level,
        })
    }
}

/// Validation for structured output
impl StrategicDirectiveOutput {
    pub fn validate(&self) -> Result<(), AppError> {
        // Validate directive type
        let valid_types = [
            "Dramatic Escalation", "Emotional Revelation", "Mystery Introduction",
            "Character Development", "World Building", "Tension Release",
            "Relationship Evolution", "Plot Advancement", "Atmospheric Immersion",
            "Conflict Resolution", "Internal Struggle", "External Challenge"
        ];
        
        if !valid_types.contains(&self.directive_type.as_str()) {
            return Err(AppError::InvalidInput(
                format!("Invalid directive type: {}", self.directive_type)
            ));
        }
        
        // Validate required fields are not empty
        if self.emotional_tone.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "Emotional tone cannot be empty".to_string()
            ));
        }
        
        if self.narrative_focus.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "Narrative focus cannot be empty".to_string()
            ));
        }
        
        if self.character_motivation.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "Character motivation cannot be empty".to_string()
            ));
        }
        
        if self.scene_context.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "Scene context cannot be empty".to_string()
            ));
        }
        
        if self.pacing_guidance.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "Pacing guidance cannot be empty".to_string()
            ));
        }
        
        // Ensure at least one complication is suggested
        if self.suggested_complications.is_empty() {
            return Err(AppError::InvalidInput(
                "At least one suggested complication is required".to_string()
            ));
        }
        
        Ok(())
    }
}