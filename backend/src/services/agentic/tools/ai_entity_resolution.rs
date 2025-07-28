// AI-Powered Entity Resolution Functions
//
// This module provides AI-driven entity resolution capabilities that replace
// hardcoded logic with intelligent, context-aware decision making using Flash/Flash-Lite.

use std::sync::Arc;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument};
use genai::chat::{SafetySetting, HarmCategory, HarmBlockThreshold};

use crate::{
    state::AppState,
    services::agentic::entity_resolution_tool::{NarrativeContext, ResolvedEntity},
};

use super::structured_output::{
    get_component_suggestion_schema_gemini,
    get_semantic_match_schema_gemini,
};

/// AI-powered component suggestion that replaces hardcoded entity type matching
pub struct AiComponentSuggester {
    app_state: Arc<AppState>,
}

impl AiComponentSuggester {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }

    /// Build prompt for AI-driven component suggestion
    fn build_component_suggestion_prompt(
        &self,
        entity: &ResolvedEntity,
        context: &NarrativeContext,
    ) -> String {
        format!(
            r#"You are an intelligent ECS component suggester for a dynamic narrative world.

Analyze this entity and its narrative context to suggest appropriate components.

ENTITY DETAILS:
- Name: {}
- Type: {}
- Properties: {:?}
- Context: {}
- Confidence: {}
- Is New: {}

NARRATIVE CONTEXT:
- Spatial Context: {:?}
- Temporal Context: {:?}
- Social Context: {:?}
- Actions/Events: {:?}

AVAILABLE COMPONENT TYPES:
- Name: Entity identification (always included)
- Position: Spatial location and coordinates
- Health: Current/max health, injuries, status
- Relationships: Social connections and dynamics
- Inventory: Items and possessions
- Description: Physical/narrative description
- Properties: Custom attributes and states
- SpatialRelationships: Containment and proximity
- SocialRelationships: Social bonds and tensions
- Skills: Abilities and competencies
- MedicalStatus: Injuries, conditions, treatments
- EmotionalState: Mood and mental state
- Equipment: Worn/wielded items
- Faction: Organizational affiliations
- Rank: Hierarchical position
- History: Past events and experiences

Your task:
1. Analyze the entity and its context deeply
2. Suggest components that match the narrative reality
3. Don't just match on entity type - consider what the narrative reveals
4. A "wounded soldier" needs Health AND MedicalStatus, not just Health
5. An entity with relationships mentioned needs Relationships component
6. Consider scale - cosmic entities might need different components than intimate ones

Be intelligent and context-aware. A "CHARACTER" type isn't just Health+Position - 
it's whatever the narrative suggests they need."#,
            entity.name,
            entity.entity_type,
            entity.properties,
            entity.context.as_deref().unwrap_or("No specific context"),
            entity.confidence,
            entity.is_new,
            context.spatial_context,
            context.temporal_context,
            context.social_context,
            context.actions_and_events
        )
    }

    /// Suggest components using AI analysis instead of hardcoded rules
    #[instrument(skip(self, entity, context))]
    pub async fn suggest_components(
        &self,
        entity: &ResolvedEntity,
        context: &NarrativeContext,
    ) -> Result<Vec<String>, String> {
        debug!("AI-powered component suggestion for entity: {}", entity.name);

        let prompt = self.build_component_suggestion_prompt(entity, context);

        // Use Flash-Lite for intelligent component analysis with structured output
        let chat_request = genai::chat::ChatRequest::from_user(prompt);
        
        // Configure safety settings
        let safety_settings = vec![
            SafetySetting {
                category: HarmCategory::HateSpeech,
                threshold: HarmBlockThreshold::BlockMediumAndAbove,
            },
            SafetySetting {
                category: HarmCategory::DangerousContent,
                threshold: HarmBlockThreshold::BlockMediumAndAbove,
            },
        ];
        
        let schema = get_component_suggestion_schema_gemini();
        let chat_options = genai::chat::ChatOptions {
            max_tokens: Some(800),
            temperature: Some(0.3), // Low-medium temperature for creative but consistent suggestions
            response_format: Some(genai::chat::ChatResponseFormat::JsonSchemaSpec(
                genai::chat::JsonSchemaSpec { schema }
            )),
            safety_settings: Some(safety_settings),
            ..Default::default()
        };

        let response = self.app_state.ai_client
            .exec_chat(&self.app_state.config.fast_model, chat_request, Some(chat_options))
            .await
            .map_err(|e| format!("AI component suggestion failed: {}", e))?;

        // Extract response text
        let response_text = response.contents
            .iter()
            .find_map(|content| {
                if let genai::chat::MessageContent::Text(text) = content {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .ok_or("No text response from AI")?;

        // Parse AI response using structured output
        let suggestion_result: ComponentSuggestionResult = serde_json::from_str(&response_text)
            .map_err(|e| format!("Failed to parse structured AI response: {}", e))?;

        info!(
            "AI suggested {} components for {}: {}",
            suggestion_result.suggested_components.len(),
            entity.name,
            suggestion_result.reasoning
        );

        Ok(suggestion_result.suggested_components)
    }
}

/// Result of AI component suggestion
#[derive(Debug, Serialize, Deserialize)]
struct ComponentSuggestionResult {
    pub suggested_components: Vec<String>,
    pub reasoning: String,
    pub contextual_insights: String,
}

/// AI-powered semantic entity matcher that replaces simple string comparison
pub struct AiSemanticMatcher {
    app_state: Arc<AppState>,
}

impl AiSemanticMatcher {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }

    /// Build prompt for semantic entity matching
    fn build_matching_prompt(
        &self,
        mention_name: &str,
        mention_context: &str,
        candidate_names: &[String],
        candidate_contexts: &[String],
    ) -> String {
        let candidates: Vec<String> = candidate_names.iter()
            .zip(candidate_contexts.iter())
            .enumerate()
            .map(|(i, (name, context))| {
                format!("{}. Name: '{}', Context: '{}'", i + 1, name, context)
            })
            .collect();

        format!(
            r#"You are an intelligent entity matcher for a narrative roleplay system.

Your task is to determine if a mentioned entity matches any existing entities using semantic understanding.

MENTIONED ENTITY:
- Name/Reference: "{}"
- Context: "{}"

EXISTING ENTITIES:
{}

MATCHING RULES:
1. **Exact matches**: "John" == "John" (always match)
2. **Role references**: "the captain" == "Captain Smith" (if context confirms)
3. **Descriptive references**: "the wounded soldier" == "Private Johnson" (if Johnson is wounded)
4. **Partial names**: "Smith" == "Captain Smith" (if no ambiguity)
5. **Contextual identity**: "the bartender" == "Sam the Bartender" (if same location/role)
6. **Pronouns**: "he/she/they" matches recent relevant entity
7. **Titles/nicknames**: "Doc" == "Doctor Williams"

IMPORTANT:
- Consider narrative context, not just string similarity
- "John the merchant" ≠ "John the guard" (different people)
- Be conservative - only match if reasonably confident
- If multiple candidates could match, pick the most contextually relevant

Analyze carefully and match semantically, not just syntactically."#,
            mention_name,
            mention_context,
            candidates.join("\n")
        )
    }

    /// Perform semantic matching using AI instead of simple string comparison
    #[instrument(skip(self, existing_entities))]
    pub async fn find_semantic_match(
        &self,
        mention_name: &str,
        mention_context: &str,
        existing_entities: &[(String, String)], // (name, context)
    ) -> Result<Option<(usize, f32)>, String> {
        if existing_entities.is_empty() {
            return Ok(None);
        }

        debug!("AI semantic matching for '{}' against {} candidates", mention_name, existing_entities.len());

        let candidate_names: Vec<String> = existing_entities.iter().map(|(name, _)| name.clone()).collect();
        let candidate_contexts: Vec<String> = existing_entities.iter().map(|(_, context)| context.clone()).collect();

        let prompt = self.build_matching_prompt(
            mention_name,
            mention_context,
            &candidate_names,
            &candidate_contexts,
        );

        // Use Flash for intelligent semantic matching with structured output
        let chat_request = genai::chat::ChatRequest::from_user(prompt);
        
        // Configure safety settings
        let safety_settings = vec![
            SafetySetting {
                category: HarmCategory::HateSpeech,
                threshold: HarmBlockThreshold::BlockMediumAndAbove,
            },
            SafetySetting {
                category: HarmCategory::DangerousContent,
                threshold: HarmBlockThreshold::BlockMediumAndAbove,
            },
        ];
        
        let schema = get_semantic_match_schema_gemini();
        let chat_options = genai::chat::ChatOptions {
            max_tokens: Some(600),
            temperature: Some(0.1), // Very low temperature for consistent matching
            response_format: Some(genai::chat::ChatResponseFormat::JsonSchemaSpec(
                genai::chat::JsonSchemaSpec { schema }
            )),
            safety_settings: Some(safety_settings),
            ..Default::default()
        };

        let response = self.app_state.ai_client
            .exec_chat(&self.app_state.config.fast_model, chat_request, Some(chat_options))
            .await
            .map_err(|e| format!("AI semantic matching failed: {}", e))?;

        // Extract response text
        let response_text = response.contents
            .iter()
            .find_map(|content| {
                if let genai::chat::MessageContent::Text(text) = content {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .ok_or("No text response from AI")?;

        // Parse AI response using structured output
        let match_result: SemanticMatchResult = serde_json::from_str(&response_text)
            .map_err(|e| format!("Failed to parse structured AI response: {}", e))?;

        if match_result.match_found {
            if let Some(index) = match_result.matched_index {
                info!(
                    "AI found semantic match: '{}' == '{}' (confidence: {})",
                    mention_name,
                    match_result.matched_name.as_deref().unwrap_or("unknown"),
                    match_result.confidence
                );
                Ok(Some((index, match_result.confidence)))
            } else {
                Ok(None)
            }
        } else {
            info!("AI found no semantic match for '{}': {}", mention_name, match_result.reasoning);
            Ok(None)
        }
    }
}

/// Result of AI semantic matching
#[derive(Debug, Serialize, Deserialize)]
struct SemanticMatchResult {
    pub match_found: bool,
    pub matched_index: Option<usize>,
    pub matched_name: Option<String>,
    pub confidence: f32,
    pub reasoning: String,
}

/// AI-powered entity context extractor
pub struct AiContextExtractor {
    _app_state: Arc<AppState>, // TODO: Will be used for AI-enhanced context extraction
}

impl AiContextExtractor {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { _app_state: app_state }
    }

    /// Extract rich narrative context using AI instead of hardcoded patterns
    pub async fn extract_narrative_context(
        &self,
        _narrative_text: &str,
    ) -> Result<NarrativeContext, String> {
        // This is already well-implemented in the original entity_resolution_tool.rs
        // We'll reuse that implementation but ensure it uses the proper AI abstraction
        // The existing implementation already uses AI properly, so no changes needed here
        Err("Use existing extract_narrative_context implementation".to_string())
    }
}

#[cfg(test)]
mod tests {
    // Tests will be implemented as part of the comprehensive test suite
}