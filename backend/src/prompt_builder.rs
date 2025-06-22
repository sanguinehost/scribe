use crate::{
    config::Config,
    errors::AppError,
    models::characters::CharacterMetadata,
    services::{
        embeddings::RetrievedChunk,
        hybrid_token_counter::{CountingMode, HybridTokenCounter},
    },
};
use genai::chat::ChatMessage as GenAiChatMessage;
use genai::chat::ContentPart as Part; // This is the Part type from the genai crate
use genai::chat::MessageContent; // This is an enum from the genai crate
use secrecy::ExposeSecret;
use std::fmt::Write;
use std::sync::Arc;
use tracing::{debug, warn};

/// Escapes text for safe inclusion in XML
fn escape_xml(text: &str) -> String {
    text.replace('&', "&")
        .replace('<', "<")
        .replace('>', ">")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Replaces template variables {{char}} and {{user}} with actual names
fn replace_template_variables(
    text: &str,
    character_name: Option<&str>,
    user_persona_name: Option<&str>,
) -> String {
    let mut result = text.to_string();

    // Replace {{char}} with character name
    if let Some(char_name) = character_name {
        result = result.replace("{{char}}", char_name);
    }

    // Replace {{user}} with user persona name or default
    let user_name = user_persona_name.unwrap_or("User");
    result = result.replace("{{user}}", user_name);

    result
}

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
            writeln!(
                prompt,
                "Description: {}",
                String::from_utf8_lossy(description_vec)
            )
            .unwrap();
            prompt.push('\n');
            // Only add static instruction if there's a character description
            prompt.push_str("---\\nInstruction:\\nContinue the chat based on the conversation history. Stay in character.\\n---\\n\\n");
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
fn build_character_info_string(
    character_metadata: Option<&CharacterMetadata>,
    dek: Option<&secrecy::SecretBox<Vec<u8>>>,
    user_persona_name: Option<&str>,
) -> String {
    let Some(char_data) = character_metadata else {
        return String::new();
    };

    let mut char_prompt_part = String::new();
    let mut has_content;

    // Helper to decrypt a field and append it to the prompt string
    let append_decrypted_field = |field_name: &str,
                                  ciphertext: &Option<Vec<u8>>,
                                  nonce: &Option<Vec<u8>>,
                                  char_prompt_part: &mut String,
                                  has_content: &mut bool| {
        if let (Some(ct), Some(n)) = (ciphertext, nonce) {
            if !ct.is_empty() {
                match crate::crypto::decrypt_gcm(ct, n, dek.unwrap()) {
                    Ok(plaintext_bytes) => {
                        let plaintext = String::from_utf8_lossy(plaintext_bytes.expose_secret());
                        if !plaintext.is_empty() {
                            let substituted_text = replace_template_variables(
                                &plaintext,
                                Some(&char_data.name),
                                user_persona_name,
                            );
                            writeln!(char_prompt_part, "**{}:** {}", field_name, substituted_text)
                                .unwrap();
                            *has_content = true;
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to decrypt character field \"{}\": {}",
                            field_name,
                            e
                        );
                    }
                }
            }
        }
    };

    // Always add name if we have a character
    writeln!(char_prompt_part, "**Character Name:** {}", char_data.name).unwrap();
    has_content = true;

    append_decrypted_field(
        "Description",
        &char_data.description,
        &char_data.description_nonce,
        &mut char_prompt_part,
        &mut has_content,
    );
    append_decrypted_field(
        "Personality",
        &char_data.personality,
        &char_data.personality_nonce,
        &mut char_prompt_part,
        &mut has_content,
    );
    append_decrypted_field(
        "Scenario",
        &char_data.scenario,
        &char_data.scenario_nonce,
        &mut char_prompt_part,
        &mut has_content,
    );
    append_decrypted_field(
        "Example Dialogue",
        &char_data.mes_example,
        &char_data.mes_example_nonce,
        &mut char_prompt_part,
        &mut has_content,
    );

    if has_content {
        char_prompt_part
    } else {
        String::new()
    }
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
    pub user_dek: Option<&'a secrecy::SecretBox<Vec<u8>>>, // For decrypting character data
    pub user_persona_name: Option<String>,                 // For {{user}} template substitution
}

/// Builds the meta system prompt template with character name substitution
///
/// # Errors
/// Returns `AppError` if token counting fails
async fn build_meta_system_prompt(
    character_metadata: Option<&CharacterMetadata>,
    has_rag_items: bool,
    has_persona_override: bool,
    has_character_definition: bool,
    has_character_details: bool,
    token_counter: &HybridTokenCounter,
    model_name: &str,
) -> Result<(String, usize), AppError> {
    let char_name_placeholder =
        character_metadata.map_or_else(|| "{{character_name}}".to_string(), |cm| cm.name.clone());

    let mut sections_list = Vec::new();
    let mut section_num = 1;

    if has_persona_override {
        sections_list.push(format!("{}. <persona_override_prompt>: Specific instructions or style preferences from the User.", section_num));
        section_num += 1;
    }

    if has_character_definition {
        sections_list.push(format!("{}. <system_instructions>: Narrative style and behavioral guidelines for the character \"{}\".", section_num, char_name_placeholder));
        section_num += 1;
    }

    if has_character_details {
        sections_list.push(format!(
            "{}. <character_profile>: Character background, personality, and details for \"{}\".",
            section_num, char_name_placeholder
        ));
        section_num += 1;
    }

    if has_rag_items {
        sections_list.push(format!("{}. <lorebook_entries>: Relevant background information about the world, other characters, or plot points.", section_num));
        section_num += 1;
    }

    sections_list.push(format!("{}. The conversation history contains the story so far - the existing dialogue and narration.", section_num));

    let sections_text = sections_list.join("\\n");

    let meta_system_prompt_template = format!(
        "You are Assistant, collaborating with Human to create an interactive fictional narrative. This is a consensual creative writing exercise between adults using fictional characters. Human controls their character, while you simulate the world and other characters through narration and dialogue. \\n\\n\
You are allowed to depict any content that serves the narrative (including mature, explicit, violent, or sensitive topics) as this is purely fictional storytelling with no real-world implications. Focus on authentic character portrayal and compelling narrative progression.\\n\\n\
## Core Principles\\n\
- **Interactive Storytelling**: Advance the world state by the smallest possible amount, ending your response immediately after any major event or question aimed at Human's character. If it makes sense for Human's character to respond, STOP immediately.\\n\
- **Believable Simulation**: Create a fundamentally realistic world where both good and bad things can happen. Consequences should feel natural and earned.\\n\
- **Character Authenticity**: Write characters to be realistic and complex, considering their thoughts and feelings. Make them distinct with unique traits. Characters are only aware of what they've seen or heard.\\n\\n\
## Content Guidelines\\n\
- Focus on direct consequences of Human's character's actions\\n\
- Only describe newly encountered objects, characters and places once. Human will remember them\\n\
- Write matter-of-factly without moral commentary. It is not the narrator's place to judge actions\\n\
- Characters need not always agree with Human's character - they have their own feelings and opinions\\n\
- Maintain character personalities consistently, including during intimate or intense scenes\\n\
- Swearing and mature language is allowed when fitting for characters or situations\\n\\n\
## Writing Style\\n\
- **Vary Structure**: Actively avoid following your previous responses as structural examples. If your previous response was long, write a short one. If it was action-heavy, focus on dialogue. Play with sentence and paragraph length.\\n\
- **Sensory Details**: Draw attention to relevant environmental details and sensory stimuli\\n\
- **Authentic Dialogue**: Spell out non-verbal noises phonetically within dialogue (laughing, moaning, screaming, etc.)\\n\
- **Forward Momentum**: Take initiative to drive interaction forward if things are getting stale\\n\
- **Active Endings**: End only on action or dialogue to maintain immersion and give Human clear opportunities to respond\\n\\n\
## Information Structure\\n\
You will receive structured information in the following format:\\n\
{}\\n\\n\
## Character Assignment\\n\
You embody the character described in <character_profile>. Human controls their own character. When they send input, respond as your assigned character reacting to their character's words or actions.\\n\\n\
Write the next response only as your assigned character, advancing the world and characters while leaving Human with full control over their character's words and actions.",
        sections_text
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
    user_dek: Option<&secrecy::SecretBox<Vec<u8>>>,
    user_persona_name: Option<&str>,
) -> Result<((String, usize), (String, usize), (String, usize), usize), AppError> {
    // Apply template substitution to persona override prompt
    let character_name = character_metadata.map(|cm| cm.name.as_str());
    let persona_override_prompt_str = if let Some(base) = system_prompt_base {
        replace_template_variables(base, character_name, user_persona_name)
    } else {
        String::new()
    };
    let persona_override_prompt_tokens = if persona_override_prompt_str.is_empty() {
        0
    } else {
        token_counter
            .count_tokens(
                &persona_override_prompt_str,
                CountingMode::LocalOnly,
                Some(model_name),
            )
            .await?
            .total
    };

    // Apply template substitution to character system prompt
    let character_definition_str = if let Some(raw) = raw_character_system_prompt {
        replace_template_variables(raw, character_name, user_persona_name)
    } else {
        String::new()
    };
    let character_definition_tokens = if character_definition_str.is_empty() {
        0
    } else {
        token_counter
            .count_tokens(
                &character_definition_str,
                CountingMode::LocalOnly,
                Some(model_name),
            )
            .await?
            .total
    };

    let character_details_str =
        build_character_info_string(character_metadata, user_dek, user_persona_name);
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
        (
            persona_override_prompt_str.to_string(),
            persona_override_prompt_tokens,
        ),
        (
            character_definition_str.to_string(),
            character_definition_tokens,
        ),
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
        user_persona_name,
        ..
    } = params;

    // 1. Build meta system prompt and calculate its tokens
    // Note: We'll rebuild this later with the final RAG items after truncation
    let (_meta_system_prompt_template, meta_system_prompt_tokens) = build_meta_system_prompt(
        *character_metadata,
        !rag_items.is_empty(),
        system_prompt_base.is_some() && !system_prompt_base.as_ref().unwrap().is_empty(),
        raw_character_system_prompt.is_some()
            && !raw_character_system_prompt.as_ref().unwrap().is_empty(),
        character_metadata.is_some(),
        token_counter,
        model_name,
    )
    .await?;

    // 2. Calculate tokens for all components
    let (
        (persona_override_prompt_str, persona_override_prompt_tokens),
        (character_definition_str, character_definition_tokens),
        (character_details_str, character_details_tokens),
        current_user_message_tokens,
    ) = calculate_component_tokens(
        system_prompt_base.as_deref(),
        raw_character_system_prompt.as_deref(),
        *character_metadata,
        current_user_message,
        token_counter,
        model_name,
        params.user_dek,
        user_persona_name.as_deref(),
    )
    .await?;

    // 3. Calculate tokens for RAG items and recent history
    let (rag_items_with_tokens, recent_history_with_tokens) =
        calculate_content_tokens(rag_items, recent_history, token_counter, model_name).await?;

    Ok(TokenCalculation {
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
        + calculation
            .rag_items_with_tokens
            .iter()
            .map(|(_, t)| t)
            .sum::<usize>()
        + calculation
            .recent_history_with_tokens
            .iter()
            .map(|(_, t)| t)
            .sum::<usize>()
}

/// Logs the initial token calculation breakdown
fn log_initial_token_calculation(
    calculation: &TokenCalculation,
    current_total_tokens: usize,
    max_allowed_tokens: usize,
) {
    debug!(
        current_total_tokens,
        max_allowed_tokens,
        calculation.meta_system_prompt_tokens,
        calculation.persona_override_prompt_tokens,
        calculation.character_definition_tokens,
        calculation.character_details_tokens,
        calculation.current_user_message_tokens,
        rag_tokens = calculation
            .rag_items_with_tokens
            .iter()
            .map(|(_, t)| t)
            .sum::<usize>(),
        history_tokens = calculation
            .recent_history_with_tokens
            .iter()
            .map(|(_, t)| t)
            .sum::<usize>(),
        "Initial token calculation for prompt building."
    );
}

/// Truncates RAG items to reduce token count
fn truncate_rag_context(
    calculation: &mut TokenCalculation,
    current_total_tokens: &mut usize,
    max_allowed_tokens: usize,
) {
    if *current_total_tokens <= max_allowed_tokens {
        return;
    }

    debug!("Attempting to reduce tokens by truncating RAG context.");
    while !calculation.rag_items_with_tokens.is_empty()
        && *current_total_tokens > max_allowed_tokens
    {
        if let Some((_, tokens)) = calculation.rag_items_with_tokens.pop() {
            *current_total_tokens -= tokens;
        }
    }
    debug!(
        current_total_tokens = *current_total_tokens,
        max_allowed_tokens, "RAG context truncated."
    );
}

/// Truncates recent history to reduce token count
fn truncate_recent_history(
    calculation: &mut TokenCalculation,
    current_total_tokens: &mut usize,
    max_allowed_tokens: usize,
) {
    if *current_total_tokens <= max_allowed_tokens {
        return;
    }

    debug!("Attempting to reduce tokens by truncating recent history.");
    while !calculation.recent_history_with_tokens.is_empty()
        && *current_total_tokens > max_allowed_tokens
    {
        // Remove from the oldest (front of the vector)
        let (_, tokens) = calculation.recent_history_with_tokens.remove(0);
        *current_total_tokens -= tokens;
    }
    debug!(
        current_total_tokens = *current_total_tokens,
        max_allowed_tokens, "Recent history truncated."
    );
}

/// Logs a warning if token limit is still exceeded after truncation
fn warn_if_over_limit(current_total_tokens: usize, max_allowed_tokens: usize) {
    if current_total_tokens > max_allowed_tokens {
        warn!(
            current_total_tokens,
            max_allowed_tokens, "Token limit exceeded even after truncation."
        );
    }
}

fn apply_token_limits(mut calculation: TokenCalculation, config: &Arc<Config>) -> TokenCalculation {
    let mut current_total_tokens = calculate_total_tokens(&calculation);
    let max_allowed_tokens = config.context_total_token_limit;

    log_initial_token_calculation(&calculation, current_total_tokens, max_allowed_tokens);

    truncate_rag_context(
        &mut calculation,
        &mut current_total_tokens,
        max_allowed_tokens,
    );
    truncate_recent_history(
        &mut calculation,
        &mut current_total_tokens,
        max_allowed_tokens,
    );
    warn_if_over_limit(current_total_tokens, max_allowed_tokens);

    calculation
}

async fn build_final_prompt_strings(
    calculation: &TokenCalculation,
    current_user_message: &GenAiChatMessage,
    character_metadata: Option<&CharacterMetadata>,
    token_counter: &HybridTokenCounter,
    model_name: &str,
) -> Result<(String, Vec<GenAiChatMessage>), AppError> {
    // Rebuild the meta system prompt based on final RAG items after truncation
    let has_final_rag_items = !calculation.rag_items_with_tokens.is_empty();
    let has_persona_override = !calculation.persona_override_prompt_str.is_empty();
    let has_character_definition = !calculation.character_definition_str.is_empty();
    let has_character_details = !calculation.character_details_str.is_empty();

    let (final_meta_system_prompt, _) = build_meta_system_prompt(
        character_metadata,
        has_final_rag_items,
        has_persona_override,
        has_character_definition,
        has_character_details,
        token_counter,
        model_name,
    )
    .await?;

    // Assemble the final system prompt with structured sections as promised
    let mut final_system_prompt = final_meta_system_prompt;

    // Add persona override prompt if present
    if !calculation.persona_override_prompt_str.is_empty() {
        final_system_prompt.push_str("\n\n<persona_override_prompt>\n");
        final_system_prompt.push_str(&calculation.persona_override_prompt_str);
        final_system_prompt.push_str("\n</persona_override_prompt>");
    }

    // Add system instructions if present
    if !calculation.character_definition_str.is_empty() {
        final_system_prompt.push_str("\n\n<system_instructions>\n");
        final_system_prompt.push_str(&calculation.character_definition_str);
        final_system_prompt.push_str("\n</system_instructions>");
    }

    // Add character profile if present
    if !calculation.character_details_str.is_empty() {
        final_system_prompt.push_str("\n\n<character_profile>\n");
        final_system_prompt.push_str(&calculation.character_details_str);
        final_system_prompt.push_str("\n</character_profile>");
    }

    // End system prompt cleanly
    final_system_prompt.push_str("\n");

    // Assemble the final message list
    let mut final_message_list = Vec::new();

    // Add recent history messages
    for (history_msg, _) in &calculation.recent_history_with_tokens {
        final_message_list.push(history_msg.clone());
    }

    // Prepend RAG context to the current user message
    let mut rag_context_for_user_message = String::new();
    if !calculation.rag_items_with_tokens.is_empty() {
        // Separate chronicle events and other RAG items
        let mut chronicle_events = Vec::new();
        let mut other_rag_items = Vec::new();
        
        for (rag_item, tokens) in &calculation.rag_items_with_tokens {
            match &rag_item.metadata {
                crate::services::embeddings::RetrievedMetadata::Chronicle(_) => {
                    chronicle_events.push((rag_item, tokens));
                }
                _ => {
                    other_rag_items.push((rag_item, tokens));
                }
            }
        }
        
        // Add chronicle events in a long_term_memory section
        if !chronicle_events.is_empty() {
            rag_context_for_user_message.push_str("<long_term_memory>\n");
            for (rag_item, _) in &chronicle_events {
                if let crate::services::embeddings::RetrievedMetadata::Chronicle(chronicle_meta) = &rag_item.metadata {
                    writeln!(
                        rag_context_for_user_message,
                        "<chronicle_event type=\"{}\" timestamp=\"{}\">{}</chronicle_event>",
                        escape_xml(&chronicle_meta.event_type),
                        chronicle_meta.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
                        escape_xml(rag_item.text.trim())
                    )
                    .unwrap();
                }
            }
            rag_context_for_user_message.push_str("</long_term_memory>\n\n");
        }
        
        // Add regular RAG items (lorebooks and chat history) in lorebook_entries section
        if !other_rag_items.is_empty() {
            rag_context_for_user_message.push_str("<lorebook_entries>\n");
            
            for (rag_item, _) in &other_rag_items {
                match &rag_item.metadata {
                    crate::services::embeddings::RetrievedMetadata::Chat(chat_meta) => {
                        writeln!(
                            rag_context_for_user_message,
                            "<chat_history speaker=\"{}\">{}</chat_history>",
                            escape_xml(&chat_meta.speaker),
                            escape_xml(rag_item.text.trim())
                        )
                        .unwrap();
                    }
                    crate::services::embeddings::RetrievedMetadata::Lorebook(lorebook_meta) => {
                        write!(rag_context_for_user_message, "<lorebook_entry").unwrap();

                        if let Some(title) = &lorebook_meta.entry_title {
                            write!(
                                rag_context_for_user_message,
                                " title=\"{}\"",
                                escape_xml(title)
                            )
                            .unwrap();
                        }

                        if let Some(keywords) = &lorebook_meta.keywords {
                            if !keywords.is_empty() {
                                let keywords_str = keywords.join(", ");
                                write!(
                                    rag_context_for_user_message,
                                    " keywords=\"{}\"",
                                    escape_xml(&keywords_str)
                                )
                                .unwrap();
                            }
                        }

                        writeln!(
                            rag_context_for_user_message,
                            ">{}</lorebook_entry>",
                            escape_xml(rag_item.text.trim())
                        )
                        .unwrap();
                    }
                    crate::services::embeddings::RetrievedMetadata::Chronicle(_) => {
                        // Already handled above
                    }
                }
            }
            
            rag_context_for_user_message.push_str("</lorebook_entries>\n\n");
        }
    }

    // Combine RAG context with the current user message
    let mut final_user_message = current_user_message.clone();
    if let MessageContent::Text(text_content) = final_user_message.content {
        let formatted_content = if !rag_context_for_user_message.is_empty() {
            format!(
                "{}**[User Input]**\n{}",
                rag_context_for_user_message, text_content
            )
        } else {
            format!("**[User Input]**\n{}", text_content)
        };
        final_user_message.content = MessageContent::Text(formatted_content);
    } else {
        // Handle other MessageContent variants if necessary, or log a warning
        warn!("User message is not plain text, RAG context not prepended.");
    }

    final_message_list.push(final_user_message);

    Ok((final_system_prompt, final_message_list))
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
    let (final_system_prompt, final_message_list) = build_final_prompt_strings(
        &calculation,
        &params.current_user_message,
        params.character_metadata,
        &params.token_counter,
        &params.model_name,
    )
    .await?;

    let final_total_tokens = calculation.meta_system_prompt_tokens
        + calculation.persona_override_prompt_tokens
        + calculation.character_definition_tokens
        + calculation.character_details_tokens
        + calculation.current_user_message_tokens
        + calculation
            .rag_items_with_tokens
            .iter()
            .map(|(_, t)| t)
            .sum::<usize>()
        + calculation
            .recent_history_with_tokens
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

    use crate::models::characters::CharacterMetadata;
    use chrono::Utc;
    use uuid::Uuid;

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
            personality: None,
            personality_nonce: None,
            scenario: None,
            scenario_nonce: None,
            mes_example: None,
            mes_example_nonce: None,
            creator_comment: None,
            creator_comment_nonce: None,
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
        // Note: Static instruction section was removed as it was redundant
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
            personality: None,
            personality_nonce: None,
            scenario: None,
            scenario_nonce: None,
            mes_example: None,
            mes_example_nonce: None,
            creator_comment: None,
            creator_comment_nonce: None,
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
            personality: None,
            personality_nonce: None,
            scenario: None,
            scenario_nonce: None,
            mes_example: None,
            mes_example_nonce: None,
            creator_comment: None,
            creator_comment_nonce: None,
        };

        let prompt = build_prompt_with_rag(Some(&char_meta));
        // When description is empty, we expect an empty string
        assert!(
            prompt.is_empty(),
            "Expected empty prompt when character has empty description, got: {prompt}"
        );
    }

    fn build_prompt_with_rag(character_metadata: Option<&CharacterMetadata>) -> String {
        super::build_prompt_with_rag(character_metadata).unwrap()
    }

    #[test]
    fn test_replace_template_variables() {
        // Test with both character and user names
        let result = super::replace_template_variables(
            "{{char}} is talking to {{user}} about something",
            Some("Alice"),
            Some("Bob"),
        );
        assert_eq!(result, "Alice is talking to Bob about something");

        // Test with no character name
        let result =
            super::replace_template_variables("{{char}} is talking to {{user}}", None, Some("Bob"));
        assert_eq!(result, "{{char}} is talking to Bob");

        // Test with no user name (should default to "User")
        let result = super::replace_template_variables(
            "{{char}} is talking to {{user}}",
            Some("Alice"),
            None,
        );
        assert_eq!(result, "Alice is talking to User");

        // Test with no template variables
        let result =
            super::replace_template_variables("This is a normal text", Some("Alice"), Some("Bob"));
        assert_eq!(result, "This is a normal text");

        // Test with multiple occurrences
        let result = super::replace_template_variables(
            "{{char}} says hello to {{user}}. {{char}} is friendly and {{user}} responds.",
            Some("Alice"),
            Some("Bob"),
        );
        assert_eq!(
            result,
            "Alice says hello to Bob. Alice is friendly and Bob responds."
        );

        // Test empty string
        let result = super::replace_template_variables("", Some("Alice"), Some("Bob"));
        assert_eq!(result, "");
    }
}
