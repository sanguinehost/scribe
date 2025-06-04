use crate::{
    config::Config,
    errors::AppError,
    models::characters::CharacterMetadata,
    services::{
        embedding_pipeline::RetrievedChunk,
        hybrid_token_counter::{CountingMode, HybridTokenCounter},
    },
};
use genai::chat::ChatMessage as GenAiChatMessage;
use std::fmt::Write;
use genai::chat::ContentPart as Part; // This is the Part type from the genai crate
use genai::chat::MessageContent; // This is an enum from the genai crate
use std::sync::Arc;
use tracing::{debug, warn};

/// Assembles the character-specific part of the system prompt.
/// RAG context is handled by the calling service and prepended to the user message.
///
/// # Errors
/// Returns `AppError` if character description processing fails
pub fn build_prompt_with_rag(
    // Renaming to build_system_prompt_character_info might be clearer later
    character: Option<&CharacterMetadata>,
) -> Result<String, AppError> {
    // No longer async, no AppState needed

    let mut prompt = String::new();

    if let Some(char_data) = character {
        if let Some(description_vec) = &char_data.description {
            if description_vec.is_empty() {
                // No description, return empty string (no character persona to instruct on)
                return Ok(String::new());
            }
            writeln!(prompt, "Character Name: {}", char_data.name).unwrap();
            writeln!(prompt, "Description: {}", String::from_utf8_lossy(description_vec)).unwrap();
            prompt.push('\n');
            // Only add static instruction if there's a character description
            prompt.push_str("---\nInstruction:\nContinue the chat based on the conversation history. Stay in character.\n---\n\n");
        } else {
            // No description, return empty string
            return Ok(String::new());
        }
    } else {
        // No character, return empty string
        return Ok(String::new());
    }

    Ok(prompt)
}

/// Builds the character-specific information string for the system prompt.
fn build_character_info_string(character_metadata: Option<&CharacterMetadata>) -> String {
    if let Some(char_data) = character_metadata {
        if let Some(description_vec) = &char_data.description {
            if !description_vec.is_empty() {
                let mut char_prompt_part = String::new();
                writeln!(char_prompt_part, "Character Name: {}", char_data.name).unwrap();
                writeln!(char_prompt_part, "Description: {}", String::from_utf8_lossy(description_vec)).unwrap();
                // Static instruction for character-based interaction
                char_prompt_part.push_str("\n---\nInstruction:\nContinue the chat based on the conversation history. Stay in character.\n---\n\n");
                return char_prompt_part;
            }
        }
    }
    String::new()
}

/// Counts tokens for a single `GenAiChatMessage`.
async fn count_tokens_for_genai_message(
    message: &GenAiChatMessage,
    token_counter: &HybridTokenCounter,
    model_name: &str,
) -> Result<usize, AppError> {
    let mut total_tokens = 0;
    // genai::chat::ChatMessage has a `content: MessageContent` field.
    // genai::chat::MessageContent is an enum. We need to match its variants.
    match &message.content {
        MessageContent::Text(text) => {
            total_tokens += token_counter
                .count_tokens(text, CountingMode::LocalOnly, Some(model_name))
                .await?
                .total;
        }
        MessageContent::Parts(parts_vec) => {
            // parts_vec is Vec<genai::types::Part>
            for part in parts_vec {
                if let Part::Text(text) = part {
                    // part is &genai::types::Part
                    total_tokens += token_counter
                        .count_tokens(text, CountingMode::LocalOnly, Some(model_name))
                        .await?
                        .total;
                }
                // TODO: Consider other Part variants if they contribute to token count (e.g., InlineData)
            }
        }
        // Handle other potential variants of MessageContent if they exist and are relevant
        _ => {
            warn!(
                "Encountered unhandled MessageContent variant while counting tokens for message."
            );
        }
    }
    Ok(total_tokens)
}

/// Parameters for building the final LLM prompt.
pub struct PromptBuildParams<'a> {
    pub config: Arc<Config>,
    pub token_counter: Arc<HybridTokenCounter>,
    pub recent_history: Vec<GenAiChatMessage>,
    pub rag_items: Vec<RetrievedChunk>,
    pub system_prompt_base: Option<String>, // From Persona/Override
    pub raw_character_system_prompt: Option<String>, // Directly from Character.system_prompt
    pub character_metadata: Option<&'a CharacterMetadata>, // For name/description
    pub current_user_message: GenAiChatMessage,
    pub model_name: String,
}

/// Builds the meta system prompt template with character name substitution
///
/// # Errors
/// Returns `AppError` if token counting fails
async fn build_meta_system_prompt(
    character_metadata: Option<&CharacterMetadata>,
    token_counter: &HybridTokenCounter,
    model_name: &str,
) -> Result<(String, usize), AppError> {
    let char_name_placeholder =
        character_metadata.map_or_else(|| "{{character_name}}".to_string(), |cm| cm.name.clone());
    
    let meta_system_prompt_template = format!(
        "You are the Narrator and supporting characters in a collaborative storytelling experience with a Human player. The Human controls a character (referred to as 'the User'). Your primary role is to describe the world, events, and the actions and dialogue of all characters *except* the User.\n\n\
        You will be provided with the following structured information to guide your responses:\n\
        1. <persona_override_prompt>: Specific instructions or style preferences from the User (if any).\n\
        2. <character_definition>: The core definition and personality of the character '{char_name_placeholder}'.\n\
        3. <character_details>: Additional descriptive information about '{char_name_placeholder}'.\n\
        4. <lorebook_entries>: Relevant background information about the world, other characters, or plot points.\n\
        5. <story_so_far>: The existing dialogue and narration.\n\n\
        Key Writing Principles:\n\
        - Focus on the direct consequences of the User's actions.\n\
        - Describe newly encountered people, places, or significant objects only once. The Human will remember.\n\
        - Maintain character believability. Characters have their own motivations and will not always agree with the User. They should react realistically based on their personalities and the situation.\n\
        - End your responses with action or dialogue to maintain active immersion. Avoid summarization or out-of-character commentary.\n\n\
        [System Instructions End]\n\
        Based on all the above and the story so far, write the next part of the story as the narrator and any relevant non-player characters. Ensure your response is engaging and moves the story forward.",
    );

    let meta_system_prompt_tokens = token_counter
        .count_tokens(
            &meta_system_prompt_template,
            CountingMode::LocalOnly,
            Some(model_name),
        )
        .await?
        .total;

    Ok((meta_system_prompt_template, meta_system_prompt_tokens))
}

/// Calculates token counts for all prompt components
///
/// # Errors
/// Returns `AppError` if token counting fails
async fn calculate_component_tokens(
    system_prompt_base: Option<&str>,
    raw_character_system_prompt: Option<&str>,
    character_metadata: Option<&CharacterMetadata>,
    current_user_message: &GenAiChatMessage,
    token_counter: &HybridTokenCounter,
    model_name: &str,
) -> Result<((String, usize), (String, usize), (String, usize), usize), AppError> {
    let persona_override_prompt_str = system_prompt_base.unwrap_or_default();
    let persona_override_prompt_tokens = if persona_override_prompt_str.is_empty() {
        0
    } else {
        token_counter
            .count_tokens(
                persona_override_prompt_str,
                CountingMode::LocalOnly,
                Some(model_name),
            )
            .await?
            .total
    };

    let character_definition_str = raw_character_system_prompt.unwrap_or_default();
    let character_definition_tokens = if character_definition_str.is_empty() {
        0
    } else {
        token_counter
            .count_tokens(
                character_definition_str,
                CountingMode::LocalOnly,
                Some(model_name),
            )
            .await?
            .total
    };

    let character_details_str = build_character_info_string(character_metadata);
    let character_details_tokens = if character_details_str.is_empty() {
        0
    } else {
        token_counter
            .count_tokens(
                &character_details_str,
                CountingMode::LocalOnly,
                Some(model_name),
            )
            .await?
            .total
    };

    let current_user_message_tokens =
        count_tokens_for_genai_message(current_user_message, token_counter, model_name).await?;

    Ok((
        (persona_override_prompt_str.to_string(), persona_override_prompt_tokens),
        (character_definition_str.to_string(), character_definition_tokens),
        (character_details_str, character_details_tokens),
        current_user_message_tokens,
    ))
}

/// Calculates tokens for RAG items and chat history
///
/// # Errors
/// Returns `AppError` if token counting fails
async fn calculate_content_tokens(
    rag_items: &[RetrievedChunk],
    recent_history: &[GenAiChatMessage],
    token_counter: &HybridTokenCounter,
    model_name: &str,
) -> Result<(Vec<(RetrievedChunk, usize)>, Vec<(GenAiChatMessage, usize)>), AppError> {
    let mut rag_items_with_tokens: Vec<(RetrievedChunk, usize)> = Vec::new();
    for item in rag_items {
        let tokens = token_counter
            .count_tokens(&item.text, CountingMode::LocalOnly, Some(model_name))
            .await?
            .total;
        rag_items_with_tokens.push((item.clone(), tokens));
    }

    let mut recent_history_with_tokens: Vec<(GenAiChatMessage, usize)> = Vec::new();
    for msg in recent_history {
        let tokens = count_tokens_for_genai_message(msg, token_counter, model_name).await?;
        recent_history_with_tokens.push((msg.clone(), tokens));
    }

    Ok((rag_items_with_tokens, recent_history_with_tokens))
}

struct TokenCalculation {
    meta_system_prompt_template: String,
    meta_system_prompt_tokens: usize,
    persona_override_prompt_str: String,
    persona_override_prompt_tokens: usize,
    character_definition_str: String,
    character_definition_tokens: usize,
    character_details_str: String,
    character_details_tokens: usize,
    current_user_message_tokens: usize,
    rag_items_with_tokens: Vec<(RetrievedChunk, usize)>,
    recent_history_with_tokens: Vec<(GenAiChatMessage, usize)>,
}

async fn perform_initial_token_calculation(
    params: &PromptBuildParams<'_>,
) -> Result<TokenCalculation, AppError> {
    let PromptBuildParams {
        token_counter,
        recent_history,
        rag_items,
        system_prompt_base,
        raw_character_system_prompt,
        character_metadata,
        current_user_message,
        model_name,
        ..
    } = params;

    // 1. Build meta system prompt and calculate its tokens
    let (meta_system_prompt_template, meta_system_prompt_tokens) = 
        build_meta_system_prompt(*character_metadata, token_counter, model_name).await?;

    // 2. Calculate tokens for all components
    let ((persona_override_prompt_str, persona_override_prompt_tokens), (character_definition_str, character_definition_tokens), (character_details_str, character_details_tokens), current_user_message_tokens) = 
        calculate_component_tokens(
            system_prompt_base.as_deref(),
            raw_character_system_prompt.as_deref(),
            *character_metadata,
            current_user_message,
            token_counter,
            model_name,
        ).await?;

    // 3. Calculate tokens for RAG items and recent history
    let (rag_items_with_tokens, recent_history_with_tokens) = 
        calculate_content_tokens(rag_items, recent_history, token_counter, model_name).await?;

    Ok(TokenCalculation {
        meta_system_prompt_template,
        meta_system_prompt_tokens,
        persona_override_prompt_str,
        persona_override_prompt_tokens,
        character_definition_str,
        character_definition_tokens,
        character_details_str,
        character_details_tokens,
        current_user_message_tokens,
        rag_items_with_tokens,
        recent_history_with_tokens,
    })
}

/// Calculates the total token count for all components
fn calculate_total_tokens(calculation: &TokenCalculation) -> usize {
    calculation.meta_system_prompt_tokens
        + calculation.persona_override_prompt_tokens
        + calculation.character_definition_tokens
        + calculation.character_details_tokens
        + calculation.current_user_message_tokens
        + calculation.rag_items_with_tokens.iter().map(|(_, t)| t).sum::<usize>()
        + calculation.recent_history_with_tokens
            .iter()
            .map(|(_, t)| t)
            .sum::<usize>()
}

/// Logs the initial token calculation breakdown
fn log_initial_token_calculation(calculation: &TokenCalculation, current_total_tokens: usize, max_allowed_tokens: usize) {
    debug!(
        current_total_tokens,
        max_allowed_tokens,
        calculation.meta_system_prompt_tokens,
        calculation.persona_override_prompt_tokens,
        calculation.character_definition_tokens,
        calculation.character_details_tokens,
        calculation.current_user_message_tokens,
        rag_tokens = calculation.rag_items_with_tokens.iter().map(|(_, t)| t).sum::<usize>(),
        history_tokens = calculation.recent_history_with_tokens
            .iter()
            .map(|(_, t)| t)
            .sum::<usize>(),
        "Initial token calculation for prompt building."
    );
}

/// Truncates RAG items to reduce token count
fn truncate_rag_context(calculation: &mut TokenCalculation, current_total_tokens: &mut usize, max_allowed_tokens: usize) {
    if *current_total_tokens <= max_allowed_tokens {
        return;
    }

    debug!("Attempting to reduce tokens by truncating RAG context.");
    while !calculation.rag_items_with_tokens.is_empty() && *current_total_tokens > max_allowed_tokens {
        if let Some((_, tokens)) = calculation.rag_items_with_tokens.pop() {
            *current_total_tokens -= tokens;
        }
    }
    debug!(
        current_total_tokens = *current_total_tokens,
        max_allowed_tokens,
        "RAG context truncated."
    );
}

/// Truncates recent history to reduce token count
fn truncate_recent_history(calculation: &mut TokenCalculation, current_total_tokens: &mut usize, max_allowed_tokens: usize) {
    if *current_total_tokens <= max_allowed_tokens {
        return;
    }

    debug!("Attempting to reduce tokens by truncating recent history.");
    while !calculation.recent_history_with_tokens.is_empty() && *current_total_tokens > max_allowed_tokens {
        // Remove from the oldest (front of the vector)
        let (_, tokens) = calculation.recent_history_with_tokens.remove(0);
        *current_total_tokens -= tokens;
    }
    debug!(
        current_total_tokens = *current_total_tokens,
        max_allowed_tokens,
        "Recent history truncated."
    );
}

/// Logs a warning if token limit is still exceeded after truncation
fn warn_if_over_limit(current_total_tokens: usize, max_allowed_tokens: usize) {
    if current_total_tokens > max_allowed_tokens {
        warn!(
            current_total_tokens,
            max_allowed_tokens,
            "Token limit exceeded even after truncation."
        );
    }
}

fn apply_token_limits(mut calculation: TokenCalculation, config: &Arc<Config>) -> TokenCalculation {
    let mut current_total_tokens = calculate_total_tokens(&calculation);
    let max_allowed_tokens = config.context_total_token_limit;
    
    log_initial_token_calculation(&calculation, current_total_tokens, max_allowed_tokens);
    
    truncate_rag_context(&mut calculation, &mut current_total_tokens, max_allowed_tokens);
    truncate_recent_history(&mut calculation, &mut current_total_tokens, max_allowed_tokens);
    warn_if_over_limit(current_total_tokens, max_allowed_tokens);

    calculation
}

fn build_final_prompt_strings(
    calculation: &TokenCalculation,
    current_user_message: &GenAiChatMessage,
) -> (String, Vec<GenAiChatMessage>) {
    // Assemble the final system prompt
    let mut final_system_prompt = calculation.meta_system_prompt_template.clone();

    if !calculation.persona_override_prompt_str.is_empty() {
        final_system_prompt.push_str(&calculation.persona_override_prompt_str);
    }

    if !calculation.character_definition_str.is_empty() {
        final_system_prompt.push_str(&calculation.character_definition_str);
    }

    if !calculation.character_details_str.is_empty() {
        final_system_prompt.push_str(&calculation.character_details_str);
    }

    // Assemble the final message list
    let mut final_message_list = Vec::new();

    // Add recent history messages
    for (history_msg, _) in &calculation.recent_history_with_tokens {
        final_message_list.push(history_msg.clone());
    }

    // Add the current user message with RAG context prepended if available
    let final_user_message = if calculation.rag_items_with_tokens.is_empty() {
        current_user_message.clone()
    } else {
        // Build RAG context string
        let mut rag_context = String::from("---\nRelevant Context:\n");
        for (rag_item, _) in &calculation.rag_items_with_tokens {
            // Add each RAG item with appropriate formatting
            match &rag_item.metadata {
                crate::services::embedding_pipeline::RetrievedMetadata::Chat(chat_meta) => {
                    writeln!(rag_context, "- Chat (Speaker: {}): {}", chat_meta.speaker, rag_item.text.trim()).unwrap();
                },
                crate::services::embedding_pipeline::RetrievedMetadata::Lorebook(lorebook_meta) => {
                    // Format with both keywords and content for better context
                    if let Some(title) = &lorebook_meta.entry_title {
                        if let Some(keywords) = &lorebook_meta.keywords {
                            if !keywords.is_empty() {
                                let keywords_str = keywords.join(", ");
                                writeln!(rag_context, "- Lorebook Entry \"{title}\" (Keywords: {keywords_str}): {}", rag_item.text.trim()).unwrap();
                            } else {
                                writeln!(rag_context, "- Lorebook Entry \"{title}\": {}", rag_item.text.trim()).unwrap();
                            }
                        } else {
                            writeln!(rag_context, "- Lorebook Entry \"{title}\": {}", rag_item.text.trim()).unwrap();
                        }
                    } else {
                        // Fall back to the original format for backwards compatibility
                        writeln!(rag_context, "- Lorebook ({}): {}", lorebook_meta.lorebook_id, rag_item.text.trim()).unwrap();
                    }
                }
            }
        }
        rag_context.push_str("---\n\n");
        
        // Create new user message with RAG context prepended
        let original_content = match &current_user_message.content {
            MessageContent::Text(text) => text.clone(),
            MessageContent::Parts(parts) => {
                // For parts, extract text parts and concatenate
                parts.iter()
                    .filter_map(|part| match part {
                        Part::Text(text) => Some(text.as_str()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            }
            _ => String::new(),
        };
        
        let enhanced_content = format!("{rag_context}{original_content}");
        
        GenAiChatMessage {
            role: current_user_message.role.clone(),
            content: MessageContent::Text(enhanced_content),
            options: None,
        }
    };
    
    final_message_list.push(final_user_message);

    (final_system_prompt, final_message_list)
}

/// Builds the final LLM prompt, managing token limits by truncating RAG context and recent history if necessary.
///
/// # Errors
/// Returns `AppError` if token counting fails, prompt building encounters errors, or character metadata processing fails
pub async fn build_final_llm_prompt(
    params: PromptBuildParams<'_>,
) -> Result<(String, Vec<GenAiChatMessage>), AppError> {
    // Perform initial token calculations for all components
    let mut calculation = perform_initial_token_calculation(&params).await?;

    // Apply token limits by truncating RAG and history if necessary
    calculation = apply_token_limits(calculation, &params.config);

    // Build final prompt strings
    let (final_system_prompt, final_message_list) = build_final_prompt_strings(&calculation, &params.current_user_message);

    let final_total_tokens = calculation.meta_system_prompt_tokens
        + calculation.persona_override_prompt_tokens
        + calculation.character_definition_tokens
        + calculation.character_details_tokens
        + calculation.current_user_message_tokens
        + calculation.rag_items_with_tokens.iter().map(|(_, t)| t).sum::<usize>()
        + calculation.recent_history_with_tokens
            .iter()
            .map(|(_, t)| t)
            .sum::<usize>();

    debug!(
        final_system_prompt_len = final_system_prompt.len(),
        final_message_list_len = final_message_list.len(),
        final_total_tokens,
        "Final prompt constructed."
    );

    Ok((final_system_prompt, final_message_list))
}

// --- Unit Tests ---
#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::characters::CharacterMetadata;
    use chrono::Utc;
    use uuid::Uuid;

    const EXPECTED_STATIC_INSTRUCTION: &str = "---\nInstruction:\nContinue the chat based on the conversation history. Stay in character.\n---\n\n";

    #[test]
    fn test_build_prompt_no_character() {
        let prompt = build_prompt_with_rag(None);
        assert!(
            prompt.is_empty(),
            "Expected empty prompt when no character is provided, got: {prompt}"
        );
    }

    #[test]
    fn test_build_prompt_character_with_description() {
        let char_meta = CharacterMetadata {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "Test Bot".to_string(),
            description: Some(b"A friendly test bot.".to_vec()),
            description_nonce: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            first_mes: Some(b"Bot greeting".to_vec()),
        };

        let prompt = build_prompt_with_rag(Some(&char_meta));
        assert!(
            prompt.contains("Test Bot"),
            "Expected prompt to contain character name, got: {prompt}"
        );
        assert!(
            prompt.contains("A friendly test bot."),
            "Expected prompt to contain character description, got: {prompt}"
        );
        assert!(
            prompt.contains(EXPECTED_STATIC_INSTRUCTION),
            "Expected prompt to contain static instruction, got: {prompt}"
        );
    }

    #[test]
    fn test_build_prompt_character_no_description() {
        let char_meta = CharacterMetadata {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "Minimal Bot".to_string(),
            description: None, // No description
            description_nonce: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            first_mes: None,
        };

        let prompt = build_prompt_with_rag(Some(&char_meta));
        // When description is None, we expect an empty string
        assert!(
            prompt.is_empty(),
            "Expected empty prompt when character has no description, got: {prompt}"
        );
    }

    #[test]
    fn test_build_prompt_character_empty_description() {
        let char_meta = CharacterMetadata {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "Silent Bot".to_string(),
            description: Some(b"".to_vec()), // Empty description
            description_nonce: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            first_mes: None,
        };

        let prompt = build_prompt_with_rag(Some(&char_meta));
        // When description is empty, we expect an empty string
        assert!(
            prompt.is_empty(),
            "Expected empty prompt when character has empty description, got: {prompt}"
        );
    }

    fn build_prompt_with_rag(character_metadata: Option<&CharacterMetadata>) -> String {
        build_character_info_string(character_metadata)
    }
}
