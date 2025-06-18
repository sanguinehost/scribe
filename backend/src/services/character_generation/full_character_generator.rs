use std::sync::Arc;
use std::time::Instant;
use tracing::{info, instrument};

use crate::{
    AppState,
    errors::AppError,
};

use super::{
    types::*,
    field_generator::FieldGenerator,
};

/// Service for generating complete characters from concepts
pub struct FullCharacterGenerator {
    state: Arc<AppState>,
    field_generator: FieldGenerator,
}

impl FullCharacterGenerator {
    pub fn new(state: Arc<AppState>) -> Self {
        let field_generator = FieldGenerator::new(state.clone());
        Self { state, field_generator }
    }

    /// Generate a complete character from a concept
    #[instrument(skip_all)]
    pub async fn generate_character(&self, request: FullCharacterRequest, user_id: uuid::Uuid) -> Result<FullCharacterResult, AppError> {
        let start_time = Instant::now();
        
        info!("Starting full character generation for concept: {}", request.concept);

        // For now, implement a simple approach that generates fields sequentially
        // In the future, this could be enhanced with a single structured output call
        // that generates all fields at once, or with parallel generation

        // First, generate the core description based on the concept
        let description_request = FieldGenerationRequest {
            field: CharacterField::Description,
            style: request.style_preferences
                .as_ref()
                .and_then(|sp| sp.description_style.clone()),
            user_prompt: request.concept.clone(),
            character_context: None,
            generation_options: request.generation_options.clone(),
            lorebook_id: None, // Full character generation doesn't use lorebook by default
        };

        let description_result = self.field_generator.generate_field(description_request, user_id).await?;

        // Extract character name from description or generate one
        let character_name = self.extract_or_generate_name(&description_result.content, &request.concept, user_id).await?;

        // Build character context for subsequent generations
        let character_context = CharacterContext {
            name: Some(character_name.clone()),
            description: Some(description_result.content.clone()),
            personality: None,
            scenario: None,
            first_mes: None,
            tags: None,
            mes_example: None,
            system_prompt: None,
            depth_prompt: None,
            alternate_greetings: None,
            lorebook_entries: None,
            associated_persona: None,
        };

        // Generate personality
        let personality_request = FieldGenerationRequest {
            field: CharacterField::Personality,
            style: None, // Use auto for personality
            user_prompt: format!("Generate a personality that fits this character: {}", request.concept),
            character_context: Some(character_context.clone()),
            generation_options: request.generation_options.clone(),
            lorebook_id: None,
        };

        let personality_result = self.field_generator.generate_field(personality_request, user_id).await?;

        // Update context with personality
        let character_context = CharacterContext {
            personality: Some(personality_result.content.clone()),
            ..character_context
        };

        // Generate first message
        let first_mes_request = FieldGenerationRequest {
            field: CharacterField::FirstMes,
            style: None,
            user_prompt: format!("Generate an engaging first message for this character: {}", request.concept),
            character_context: Some(character_context.clone()),
            generation_options: request.generation_options.clone(),
            lorebook_id: None,
        };

        let first_mes_result = self.field_generator.generate_field(first_mes_request, user_id).await?;

        // Generate basic scenario
        let scenario_request = FieldGenerationRequest {
            field: CharacterField::Scenario,
            style: None,
            user_prompt: format!("Generate a scenario/setting for this character: {}", request.concept),
            character_context: Some(character_context.clone()),
            generation_options: request.generation_options.clone(),
            lorebook_id: None,
        };

        let scenario_result = self.field_generator.generate_field(scenario_request, user_id).await?;

        // Generate tags
        let tags_request = FieldGenerationRequest {
            field: CharacterField::Tags,
            style: None,
            user_prompt: format!("Generate relevant tags for this character: {}", request.concept),
            character_context: Some(character_context),
            generation_options: request.generation_options.clone(),
            lorebook_id: None,
        };

        let tags_result = self.field_generator.generate_field(tags_request, user_id).await?;
        let tags = self.parse_tags(&tags_result.content);

        // Calculate total generation time and tokens
        let generation_time = start_time.elapsed();
        let total_tokens = description_result.metadata.tokens_used
            + personality_result.metadata.tokens_used
            + first_mes_result.metadata.tokens_used
            + scenario_result.metadata.tokens_used
            + tags_result.metadata.tokens_used;

        let metadata = GenerationMetadata {
            tokens_used: total_tokens,
            generation_time_ms: generation_time.as_millis() as u64,
            style_detected: Some(description_result.style_used),
            model_used: self.state.config.token_counter_default_model.clone(),
            timestamp: chrono::Utc::now(),
            debug_info: None, // No debug info for full character generation yet
        };

        info!(
            "Full character generation completed in {}ms, {} total tokens used",
            generation_time.as_millis(),
            total_tokens
        );

        Ok(FullCharacterResult {
            name: character_name,
            description: description_result.content,
            personality: Some(personality_result.content),
            scenario: Some(scenario_result.content),
            first_mes: first_mes_result.content,
            mes_example: None, // Optional field for basic generation
            system_prompt: None, // Optional field for basic generation
            depth_prompt: None, // Optional field for basic generation
            tags,
            metadata,
        })
    }

    /// Extract character name from description or generate one
    async fn extract_or_generate_name(&self, description: &str, concept: &str, user_id: uuid::Uuid) -> Result<String, AppError> {
        // Simple name extraction - look for common patterns
        // This could be enhanced with better NLP or structured generation
        
        // Try to find name patterns in description
        let patterns = [
            r"(?:Name:|name:|called|named)\s+([A-Z][a-z]+)",
            r"^([A-Z][a-z]+)\s+(?:is|was|stands|sits)",
            r"([A-Z][a-z]+),?\s+(?:a|an|the)",
        ];

        for pattern in &patterns {
            if let Ok(regex) = regex::Regex::new(pattern) {
                if let Some(captures) = regex.captures(description) {
                    if let Some(name_match) = captures.get(1) {
                        return Ok(name_match.as_str().to_string());
                    }
                }
            }
        }

        // If no name found in description, generate one based on concept
        let name_request = FieldGenerationRequest {
            field: CharacterField::Description, // Reuse description field for name generation
            style: None,
            user_prompt: format!("Generate just a name (first name only) for a character described as: {}", concept),
            character_context: None,
            generation_options: Some(GenerationOptions {
                creativity_level: Some("medium".to_string()),
                max_length: Some(20),
                ..Default::default()
            }),
            lorebook_id: None,
        };

        let name_result = self.field_generator.generate_field(name_request, user_id).await?;
        
        // Extract just the name from the generated content
        let name = name_result.content
            .lines()
            .next()
            .unwrap_or(&name_result.content)
            .trim()
            .split_whitespace()
            .next()
            .unwrap_or("Character")
            .to_string();

        Ok(name)
    }

    /// Parse tags from generated content
    fn parse_tags(&self, tags_content: &str) -> Vec<String> {
        // Handle different tag formats
        if tags_content.trim().starts_with('[') {
            // JSON array format
            if let Ok(json_tags) = serde_json::from_str::<Vec<String>>(tags_content) {
                return json_tags;
            }
        }

        // Comma-separated format
        tags_content
            .split(',')
            .map(|tag| tag.trim().to_string())
            .filter(|tag| !tag.is_empty())
            .collect()
    }
}

impl Default for GenerationOptions {
    fn default() -> Self {
        Self {
            creativity_level: None,
            include_metadata: None,
            max_length: None,
            temperature: None,
        }
    }
}