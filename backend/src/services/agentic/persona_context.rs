// backend/src/services/agentic/persona_context.rs

use uuid::Uuid;
use serde::{Deserialize, Serialize};
use crate::models::user_personas::UserPersonaDataForClient;

/// Context information about a user's persona for narrative intelligence processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPersonaContext {
    /// The persona ID
    pub id: Uuid,
    /// The name of the persona (e.g., "Lucas")
    pub name: String,
    /// Detailed description of the persona
    pub description: Option<String>,
    /// Personality traits and characteristics
    pub personality: Option<String>,
    /// Current scenario or context
    pub scenario: Option<String>,
}

impl UserPersonaContext {
    /// Create a new UserPersonaContext
    pub fn new(
        id: Uuid,
        name: String,
        description: Option<String>,
        personality: Option<String>,
        scenario: Option<String>,
    ) -> Self {
        Self {
            id,
            name,
            description,
            personality,
            scenario,
        }
    }

    /// Get a formatted string for use in AI prompts
    pub fn to_prompt_context(&self) -> String {
        let mut context = format!("USER PERSONA: {}\n", self.name);
        
        if let Some(description) = &self.description {
            context.push_str(&format!("Description: {}\n", description));
        }
        
        if let Some(personality) = &self.personality {
            context.push_str(&format!("Personality: {}\n", personality));
        }
        
        if let Some(scenario) = &self.scenario {
            context.push_str(&format!("Scenario: {}\n", scenario));
        }
        
        context
    }

    /// Get the persona name for template substitution (replaces {{user}} placeholders)
    pub fn get_name_for_substitution(&self) -> String {
        self.name.clone()
    }
}

impl From<UserPersonaDataForClient> for UserPersonaContext {
    fn from(persona: UserPersonaDataForClient) -> Self {
        Self {
            id: persona.id,
            name: persona.name,
            description: Some(persona.description),
            personality: persona.personality,
            scenario: persona.scenario,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persona_context_creation() {
        let persona_id = Uuid::new_v4();
        let context = UserPersonaContext::new(
            persona_id,
            "Lucas".to_string(),
            Some("A 27-year-old Australian cybersecurity expert".to_string()),
            Some("Hardened, cynical, yet idealistic".to_string()),
            Some("Cosmic awakening scenario".to_string()),
        );

        assert_eq!(context.id, persona_id);
        assert_eq!(context.name, "Lucas");
        assert!(context.description.is_some());
    }

    #[test]
    fn test_to_prompt_context() {
        let context = UserPersonaContext::new(
            Uuid::new_v4(),
            "Lucas".to_string(),
            Some("A cybersecurity expert".to_string()),
            Some("Idealistic yet cynical".to_string()),
            None,
        );

        let prompt = context.to_prompt_context();
        
        assert!(prompt.contains("USER PERSONA: Lucas"));
        assert!(prompt.contains("Description: A cybersecurity expert"));
        assert!(prompt.contains("Personality: Idealistic yet cynical"));
        assert!(!prompt.contains("Scenario:"));
    }

    #[test]
    fn test_from_user_persona_data() {
        let persona_data = UserPersonaDataForClient {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "TestUser".to_string(),
            description: "Test description".to_string(),
            spec: None,
            spec_version: None,
            personality: Some("Test personality".to_string()),
            scenario: Some("Test scenario".to_string()),
            first_mes: None,
            mes_example: None,
            system_prompt: None,
            post_history_instructions: None,
            tags: None,
            avatar: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let context: UserPersonaContext = persona_data.into();
        
        assert_eq!(context.name, "TestUser");
        assert_eq!(context.description, Some("Test description".to_string()));
    }

    #[test]
    fn test_get_name_for_substitution() {
        let context = UserPersonaContext::new(
            Uuid::new_v4(),
            "Lucas".to_string(),
            None,
            None,
            None,
        );

        assert_eq!(context.get_name_for_substitution(), "Lucas");
    }
}