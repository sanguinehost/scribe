use crate::{
    config::Config,
    errors::AppError,
    models::characters::CharacterMetadata,
    services::{
        embedding_pipeline::{RetrievedChunk, RetrievedMetadata},
        hybrid_token_counter::{CountingMode, HybridTokenCounter},
    },
};
use genai::chat::ChatMessage as GenAiChatMessage;
use genai::chat::ContentPart as Part; // This is the Part type from the genai crate
use genai::chat::MessageContent; // This is an enum from the genai crate
use std::sync::Arc;
use tracing::{debug, error, warn}; // Added error

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
            prompt.push_str(&format!("Character Name: {}\n", char_data.name));
            prompt.push_str(&format!(
                "Description: {}\n",
                String::from_utf8_lossy(description_vec)
            ));
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
                char_prompt_part.push_str(&format!("Character Name: {}\n", char_data.name));
                char_prompt_part.push_str(&format!(
                    "Description: {}\n",
                    String::from_utf8_lossy(description_vec)
                ));
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

/// Builds the final LLM prompt, managing token limits by truncating RAG context and recent history if necessary.
///
/// # Errors
/// Returns `AppError` if token counting fails, prompt building encounters errors, or character metadata processing fails
#[allow(clippy::too_many_lines)]
pub async fn build_final_llm_prompt(
    params: PromptBuildParams<'_>,
) -> Result<(String, Vec<GenAiChatMessage>), AppError> {
    let PromptBuildParams {
        config,
        token_counter,
        recent_history,
        rag_items,
        system_prompt_base,
        raw_character_system_prompt,
        character_metadata,
        current_user_message,
        model_name,
    } = params;

    // 1. Build meta system prompt and calculate its tokens
    let (meta_system_prompt_template, meta_system_prompt_tokens) = 
        build_meta_system_prompt(character_metadata, &token_counter, &model_name).await?;

    // 2. Calculate tokens for all components
    let ((persona_override_prompt_str, persona_override_prompt_tokens), (character_definition_str, character_definition_tokens), (character_details_str, character_details_tokens), current_user_message_tokens) = 
        calculate_component_tokens(
            system_prompt_base.as_deref(),
            raw_character_system_prompt.as_deref(),
            character_metadata,
            &current_user_message,
            &token_counter,
            &model_name,
        ).await?;

    // 3. Calculate tokens for RAG items and recent history
    let (rag_items_with_tokens, recent_history_with_tokens) = 
        calculate_content_tokens(&rag_items, &recent_history, &token_counter, &model_name).await?;

    // 2. Calculate initial total tokens
    let mut current_total_tokens = meta_system_prompt_tokens
        + persona_override_prompt_tokens
        + character_definition_tokens
        + character_details_tokens
        + current_user_message_tokens
        + rag_items_with_tokens.iter().map(|(_, t)| t).sum::<usize>()
        + recent_history_with_tokens
            .iter()
            .map(|(_, t)| t)
            .sum::<usize>();

    let max_allowed_tokens = config.context_total_token_limit;
    debug!(
        current_total_tokens,
        max_allowed_tokens,
        meta_system_prompt_tokens,
        persona_override_prompt_tokens,
        character_definition_tokens,
        character_details_tokens,
        current_user_message_tokens,
        rag_tokens = rag_items_with_tokens.iter().map(|(_, t)| t).sum::<usize>(),
        history_tokens = recent_history_with_tokens
            .iter()
            .map(|(_, t)| t)
            .sum::<usize>(),
        "Initial token calculation for prompt building."
    );

    // 3. Truncate RAG context if over budget
    let mut final_rag_items_with_tokens = rag_items_with_tokens;
    if current_total_tokens > max_allowed_tokens {
        debug!("Total tokens exceed limit. Attempting to truncate RAG context.");
        while current_total_tokens > max_allowed_tokens && !final_rag_items_with_tokens.is_empty() {
            if let Some((removed_item, removed_tokens)) = final_rag_items_with_tokens.pop() {
                current_total_tokens -= removed_tokens;
                warn!(
                    "Truncated RAG item (text: '{}...', tokens: {}) to fit token limit. Remaining total: {}",
                    removed_item.text.chars().take(50).collect::<String>(),
                    removed_tokens,
                    current_total_tokens
                );
            }
        }
    }

    // 4. Truncate recent history if still over budget
    let mut final_recent_history_with_tokens = recent_history_with_tokens;
    if current_total_tokens > max_allowed_tokens {
        debug!(
            "Total tokens still exceed limit after RAG truncation. Attempting to truncate recent history."
        );
        while current_total_tokens > max_allowed_tokens
            && !final_recent_history_with_tokens.is_empty()
        {
            // Remove from the oldest (front of the vector)
            let (removed_msg, removed_tokens) = final_recent_history_with_tokens.remove(0);
            current_total_tokens -= removed_tokens;
            let msg_preview = match &removed_msg.content {
                MessageContent::Text(text) => text.chars().take(50).collect::<String>(),
                MessageContent::Parts(parts_vec) => parts_vec
                    .iter()
                    .find_map(|part| {
                        if let Part::Text(text) = part {
                            Some(text.chars().take(50).collect::<String>())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| "[Non-text content]".to_string()),
                _ => "[Unknown content type]".to_string(),
            };
            warn!(
                "Truncated history message (preview: '{}...', tokens: {}) to fit token limit. Remaining total: {}",
                msg_preview.chars().take(50).collect::<String>(),
                removed_tokens,
                current_total_tokens
            );
        }
    }

    // 5. Final check: if still over budget, it's an error
    if current_total_tokens > max_allowed_tokens {
        error!(
            current_total_tokens,
            max_allowed_tokens,
            "Prompt and user message exceed token limit even after full RAG and history truncation."
        );
        return Err(AppError::BadRequest(
            "User message and system prompts are too long to fit within the token limit."
                .to_string(),
        ));
    }

    // 6. Assemble final system prompt string
    let mut final_system_prompt_parts: Vec<String> = vec![meta_system_prompt_template]; // Start with the meta prompt

    if !persona_override_prompt_str.is_empty() {
        final_system_prompt_parts.push(format!(
            "<persona_override_prompt>\n{persona_override_prompt_str}\n</persona_override_prompt>"
        ));
    }
    if !character_definition_str.is_empty() {
        final_system_prompt_parts.push(format!(
            "<character_definition>\n{character_definition_str}\n</character_definition>"
        ));
    }
    if !character_details_str.is_empty() {
        // build_character_info_string already includes "Character Name: ..." and "Description: ..."
        // We might want to refine build_character_info_string to return just the description if name is already in meta prompt.
        // For now, let's wrap what it returns.
        final_system_prompt_parts.push(format!(
            "<character_details>\n{character_details_str}\n</character_details>"
        ));
    }
    // Note: RAG items are handled separately and prepended to the user message, not part of the system prompt string here.

    let final_rag_texts: Vec<String> = final_rag_items_with_tokens
        .into_iter()
        .map(|(item, _)| {
            // item is RetrievedChunk
            match item.metadata {
                RetrievedMetadata::Chat(chat_meta) => {
                    format!("- Chat (Speaker: {}): {}", chat_meta.speaker, item.text)
                }
                RetrievedMetadata::Lorebook(lore_meta) => {
                    let title = lore_meta.entry_title.as_deref().unwrap_or("Untitled Entry");
                    let keywords_str = lore_meta
                        .keywords
                        .as_ref()
                        .filter(|kws| !kws.is_empty()).map_or_else(|| "No Keywords".to_string(), |kws| kws.join(", "));
                    format!("- Lorebook ({} - {}): {}", title, keywords_str, item.text)
                }
            }
        })
        .collect();

    // RAG context is now added to the user message, not the system prompt.
    // final_rag_texts (Vec<String>) was already prepared from truncated RAG items.

    // Join with a more distinct separator if multiple parts exist.
    // If only one part, no separator needed. If no parts, empty string.
    let final_system_prompt = if final_system_prompt_parts.len() > 1 {
        final_system_prompt_parts.join("\n\n---\n\n")
    } else {
        final_system_prompt_parts.join("") // Effectively takes the first element or empty if no elements
    };

    // Prepare current user message, potentially prepending RAG context
    let mut user_message_for_llm = current_user_message; // current_user_message is moved here

    if !final_rag_texts.is_empty() {
        let rag_context_for_user_message = format!(
            "---\nRelevant Context:\n{}\n---", // Matches test assertion header
            final_rag_texts.join("\n\n")       // Use the already prepared final_rag_texts
        );

        match &mut user_message_for_llm.content {
            MessageContent::Text(original_text) => {
                let mut new_text = rag_context_for_user_message;
                new_text.push_str("\n\n"); // Separator between RAG and original query
                new_text.push_str(original_text);
                *original_text = new_text; // Update the text content
            }
            MessageContent::Parts(parts_vec) => {
                // This case is more complex. For now, let's assume simple text content
                // based on how GenerateChatRequest is typically formed for new messages.
                warn!(
                    "Prepending RAG context to a multi-part user message. Current implementation converts to full text."
                );
                let mut combined_text = rag_context_for_user_message;
                combined_text.push_str("\n\n");
                for part in parts_vec.iter() {
                    // Iterate over original parts
                    if let Part::Text(text) = part {
                        combined_text.push_str(text);
                    }
                    // Consider logging or preserving other part types if they are expected here.
                }
                user_message_for_llm.content = MessageContent::Text(combined_text);
            }
            _ => {
                error!(
                    "Cannot prepend RAG context to user_message_for_llm with unsupported content type: {:?}",
                    user_message_for_llm.content
                );
                // The message will be sent without RAG context prepended in this case.
            }
        }
    }

    // 7. Assemble final message list
    let mut final_message_list: Vec<GenAiChatMessage> = final_recent_history_with_tokens
        .into_iter()
        .map(|(msg, _)| msg)
        .collect();
    final_message_list.push(user_message_for_llm); // Push the (potentially modified) user message

    debug!(
        final_system_prompt_len = final_system_prompt.len(),
        final_message_list_len = final_message_list.len(),
        final_total_tokens = current_total_tokens,
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
        let prompt = build_prompt_with_rag(None).unwrap();
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

        let prompt = build_prompt_with_rag(Some(&char_meta)).unwrap();

        assert!(
            prompt.contains("Character Name: Test Bot"),
            "Prompt missing character name. Got: '{prompt}'"
        );
        assert!(
            prompt.contains("Description: A friendly test bot."),
            "Prompt missing character description. Got: '{prompt}'"
        );
        assert!(
            prompt.contains(EXPECTED_STATIC_INSTRUCTION),
            "Prompt missing static instruction. Got: '{prompt}'"
        );
        assert!(
            !prompt.contains("Relevant Context:"),
            "Prompt should not contain RAG context. Got: '{prompt}'"
        );
        assert!(
            !prompt.contains("---\nHistory:\n"),
            "Prompt should not contain History. Got: '{prompt}'"
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

        let prompt = build_prompt_with_rag(Some(&char_meta)).unwrap();

        assert!(
            prompt.is_empty(),
            "Expected empty prompt for char without description, got: {prompt}"
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

        let prompt = build_prompt_with_rag(Some(&char_meta)).unwrap();

        assert!(
            prompt.is_empty(),
            "Expected empty prompt for char with empty description, got: {prompt}"
        );
    }
}
