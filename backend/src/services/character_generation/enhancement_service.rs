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

/// Service for enhancing existing character content
pub struct EnhancementService {
    state: Arc<AppState>,
    field_generator: FieldGenerator,
}

impl EnhancementService {
    pub fn new(state: Arc<AppState>) -> Self {
        let field_generator = FieldGenerator::new(state.clone());
        Self { state, field_generator }
    }

    /// Enhance existing character field content
    #[instrument(skip_all, fields(field = ?request.field))]
    pub async fn enhance_field(&self, request: EnhancementRequest, user_id: uuid::Uuid) -> Result<EnhancementResult, AppError> {
        let start_time = Instant::now();
        
        info!("Starting enhancement for {:?} field", request.field);

        // Build enhancement prompt that focuses on improving existing content
        let enhancement_prompt = format!(
            "Enhance this existing {} content based on the following instructions: {}\n\nCurrent content:\n{}",
            request.field.display_name().to_lowercase(),
            request.enhancement_instructions,
            request.current_content
        );

        // Use the field generator with enhancement-specific prompt
        let field_request = FieldGenerationRequest {
            field: request.field.clone(),
            style: None, // Let it maintain the existing style
            user_prompt: enhancement_prompt,
            character_context: request.character_context.clone(),
            generation_options: request.generation_options.clone(),
            lorebook_id: None, // Enhancement doesn't use lorebook context for now
        };

        let generation_result = self.field_generator.generate_field(field_request, user_id).await?;

        // Analyze what changes were made (simplified approach)
        let changes_made = self.analyze_changes(&request.current_content, &generation_result.content);

        let generation_time = start_time.elapsed();

        let metadata = GenerationMetadata {
            tokens_used: generation_result.metadata.tokens_used,
            generation_time_ms: generation_time.as_millis() as u64,
            style_detected: Some(generation_result.style_used),
            model_used: self.state.config.token_counter_default_model.clone(),
            timestamp: chrono::Utc::now(),
            debug_info: None, // No debug info for enhancement yet
        };

        info!(
            "Enhancement completed in {}ms, {} changes identified",
            generation_time.as_millis(),
            changes_made.len()
        );

        Ok(EnhancementResult {
            enhanced_content: generation_result.content,
            changes_made,
            metadata,
        })
    }

    /// Analyze what changes were made between original and enhanced content
    fn analyze_changes(&self, original: &str, enhanced: &str) -> Vec<String> {
        let mut changes = Vec::new();

        // Basic change detection - this could be enhanced with more sophisticated diff analysis
        if enhanced.len() > (original.len() as f64 * 1.2) as usize {
            changes.push("Significantly expanded content".to_string());
        } else if enhanced.len() > (original.len() as f64 * 1.1) as usize {
            changes.push("Added more detail".to_string());
        }

        if enhanced.chars().count() != original.chars().count() {
            changes.push("Modified text structure".to_string());
        }

        // Check for new descriptive elements (simplified)
        let original_lower = original.to_lowercase();
        let original_words: std::collections::HashSet<_> = original_lower
            .split_whitespace()
            .collect();
        let enhanced_lower = enhanced.to_lowercase();
        let enhanced_words: std::collections::HashSet<_> = enhanced_lower
            .split_whitespace()
            .collect();

        let new_words: Vec<_> = enhanced_words
            .difference(&original_words)
            .take(5) // Limit to avoid spam
            .collect();

        if !new_words.is_empty() {
            changes.push(format!("Added new descriptive elements: {}", 
                new_words.iter().map(|w| w.to_string()).collect::<Vec<_>>().join(", ")));
        }

        if changes.is_empty() {
            changes.push("Refined and improved existing content".to_string());
        }

        changes
    }
}