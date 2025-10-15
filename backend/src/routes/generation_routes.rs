// backend/src/routes/generation_routes.rs
//! Routes for AI-powered content generation (characters, lorebooks, assistant)
//!
//! This module provides HTTP endpoints for the character generation service,
//! exposing field generation, complete character creation, enhancement, and
//! lorebook entry generation capabilities.

#![allow(clippy::unused_async)]

use crate::auth::session_dek::SessionDek;
use crate::auth::user_store::Backend as AuthBackend;
use crate::errors::AppError;
use crate::services::character_generation::{
    ApiGenerationChunk, ApiGenerationMetadata, ApiGenerationRequest, ApiGenerationResponse,
    AssistantMessage, BatchLorebookGenerationRequest, BatchLorebookGenerationResponse,
    EnhancementRequest, EnhancementResult, FieldGenerationRequest, FieldGenerationResult,
    FieldGenerator, FullCharacterGenerator, FullCharacterRequest, FullCharacterResult,
    LorebookGenerationRequest, LorebookGenerationResponse, ScribeAssistantRequest,
    ScribeAssistantResponse, structured_output::*,
};
use crate::state::AppState;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::{
    Router, extract::State, http::StatusCode, response::IntoResponse, response::Json, routing::post,
};
use axum_login::AuthSession;
use futures::StreamExt;
use std::sync::Arc;
use tracing::{error, info, instrument};

// Define the type alias for the auth session
type CurrentAuthSession = AuthSession<AuthBackend>;

/// Create the generation router with all endpoints
pub fn router() -> Router<AppState> {
    Router::new()
        // Character generation endpoints
        .route("/character/field", post(generate_character_field_handler))
        .route(
            "/character/field/stream",
            post(generate_character_field_stream_handler),
        )
        .route(
            "/character/complete",
            post(generate_complete_character_handler),
        )
        .route("/character/enhance", post(enhance_character_handler))
        // Lorebook generation endpoints
        .route("/lorebook/entries", post(generate_lorebook_entries_handler))
        .route("/lorebook/entry", post(generate_lorebook_entry_handler))
        // Scribe assistant endpoint
        .route("/scribe-assistant", post(scribe_assistant_handler))
}

// ============================================================================
// Character Generation Handlers
// ============================================================================

/// POST /api/generation/character/field
///
/// Generate or enhance a specific character field (description, personality, etc.)
/// Supports multiple generation modes: create, enhance, rewrite, expand
///
/// This endpoint accepts requests in character-editor's API format (camelCase)
/// and converts them to internal format for processing
#[instrument(skip_all, fields(field = ?payload.field_name, mode = ?payload.mode))]
pub async fn generate_character_field_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    dek: SessionDek, // SECURITY: SessionDek required for decrypting lorebook content
    Json(payload): Json<ApiGenerationRequest>,
) -> Result<Json<ApiGenerationResponse>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    info!(
        "Generating field {} for user {} (mode: {})",
        payload.field_name,
        user.id,
        payload.mode.as_str()
    );

    // Convert API request to internal format
    let internal_request = payload
        .to_field_generation_request()
        .map_err(|e| AppError::BadRequest(e))?;

    // Generate the field
    let field_generator = FieldGenerator::new(Arc::new(state));
    let result = field_generator
        .generate_field(internal_request, user.id, Some(&dek))
        .await?;

    // Convert internal result to API format
    let api_response = ApiGenerationResponse {
        content: result.content,
        metadata: ApiGenerationMetadata::from(&result.metadata),
    };

    Ok(Json(api_response))
}

/// POST /api/generation/character/field/stream
///
/// Generate or enhance a specific character field with Server-Sent Events streaming
/// Supports multiple generation modes: create, enhance, rewrite, expand
///
/// This endpoint accepts requests in character-editor's API format (camelCase)
/// and streams the generation as it happens
///
/// Note: Streaming mode uses a simpler generation path without lorebook querying
/// for faster response times. Use the non-streaming endpoint for full context enrichment.
#[instrument(skip_all, fields(field = ?payload.field_name, mode = ?payload.mode))]
pub async fn generate_character_field_stream_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    _dek: SessionDek, // DEK available if needed in future
    Json(payload): Json<ApiGenerationRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    info!(
        "Streaming field generation: {} for user {} (mode: {})",
        payload.field_name,
        user.id,
        payload.mode.as_str()
    );

    // Convert API request to internal format
    let internal_request = payload
        .to_field_generation_request()
        .map_err(|e| AppError::BadRequest(e))?;

    // Clone data needed for the stream
    let state_arc = Arc::new(state);

    // Use FieldGenerator to build comprehensive system prompt with style support
    // This ensures streaming matches non-streaming behavior for style handling
    let field_generator = FieldGenerator::new(state_arc.clone());
    let system_prompt = field_generator.build_field_generation_system_prompt(
        &internal_request.field,
        &internal_request.mode,
        &internal_request
            .style
            .clone()
            .unwrap_or(crate::services::character_generation::types::DescriptionStyle::Auto),
    );

    // Create the SSE stream
    let stream = async_stream::stream! {
        let start_time = std::time::Instant::now();

        use genai::chat::{ChatMessage as GenAiChatMessage, ChatOptions, ChatRequest, ChatRole, MessageContent};

        // Create the chat request for streaming
        let chat_request = ChatRequest::new(vec![GenAiChatMessage {
            role: ChatRole::User,
            content: MessageContent::from_text(internal_request.user_prompt.clone()),
            options: None,
        }])
        .with_system(system_prompt);

        // Set up chat options
        let mut chat_options = ChatOptions::default();
        if let Some(temp) = internal_request.generation_options.as_ref().and_then(|o| o.temperature) {
            chat_options = chat_options.with_temperature(temp.into());
        }
        if let Some(max_len) = internal_request.generation_options.as_ref().and_then(|o| o.max_length) {
            if let Ok(max_tokens) = u32::try_from(max_len) {
                chat_options = chat_options.with_max_tokens(max_tokens);
            }
        }

        // Get the AI client and stream
        let model_name = "gemini-2.5-flash"; // TODO: Make configurable

        match state_arc.ai_client.stream_chat(model_name, chat_request, Some(chat_options)).await {
            Ok(mut chat_stream) => {
                let mut _full_content = String::new();
                let mut prompt_tokens_count = 0;
                let mut completion_tokens_count = 0;

                // Stream the content chunks
                while let Some(event_result) = chat_stream.next().await {
                    match event_result {
                        Ok(stream_event) => {
                            use genai::chat::ChatStreamEvent;
                            match stream_event {
                                ChatStreamEvent::Start => {
                                    // Stream started, no content yet
                                }
                                ChatStreamEvent::Chunk(chunk) => {
                                    _full_content.push_str(&chunk.content);

                                    // Yield content chunk
                                    let chunk_data = serde_json::json!({
                                        "content": chunk.content,
                                        "done": false
                                    });
                                    yield Ok::<_, AppError>(Event::default()
                                        .event("chunk")
                                        .data(chunk_data.to_string()));
                                }
                                ChatStreamEvent::End(_end_data) => {
                                    // StreamEnd doesn't contain token counts in the genai crate
                                    // Use accumulated counts from chunks if available, or estimate
                                    let total_tokens = prompt_tokens_count + completion_tokens_count;

                                    let generation_time_ms = start_time.elapsed().as_millis() as u64;

                                    // Create metadata
                                    let metadata = ApiGenerationMetadata {
                                        model: model_name.to_string(),
                                        tokens_used: total_tokens,
                                        cost: 0.0, // TODO: Calculate based on token pricing
                                        generation_time_ms,
                                        finish_reason: Some("stop".to_string()), // Default finish reason for streaming
                                        style_detected: internal_request.style.clone(),
                                        system_prompt: None, // Don't include in streaming response
                                        user_prompt: None,
                                        lorebook_context_included: Some(false),
                                        lorebook_entries_count: Some(0),
                                        query_text_used: None,
                                    };

                                    // Yield final chunk with metadata
                                    let final_chunk = ApiGenerationChunk {
                                        content: String::new(),
                                        done: true,
                                        metadata: Some(metadata),
                                    };

                                    let final_data = serde_json::to_string(&final_chunk).unwrap_or_default();
                                    yield Ok(Event::default()
                                        .event("done")
                                        .data(final_data));
                                }
                                _ => {
                                    // Ignore other event types (ReasoningChunk, ToolCall, etc.)
                                }
                            }
                        }
                        Err(e) => {
                            error!("Stream error: {:?}", e);
                            let error_msg = format!("Generation error: {}", e);
                            yield Ok(Event::default().event("error").data(error_msg));
                            return;
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to create stream: {:?}", e);
                let error_msg = format!("Failed to start generation: {}", e);
                yield Ok(Event::default().event("error").data(error_msg));
            }
        }
    };

    Ok(Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
        .into_response())
}

/// POST /api/generation/character/complete
///
/// Generate a complete character from a high-level concept/prompt
#[instrument(skip_all)]
pub async fn generate_complete_character_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    Json(payload): Json<FullCharacterRequest>,
) -> Result<Json<FullCharacterResult>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    info!(
        "Generating complete character for user {} from concept: {}",
        user.id, payload.concept
    );

    let full_generator = FullCharacterGenerator::new(Arc::new(state));
    let result = full_generator.generate_character(payload, user.id).await?;

    Ok(Json(result))
}

/// POST /api/generation/character/enhance
///
/// Enhance existing character content with AI improvements
#[instrument(skip_all, fields(field = ?payload.field))]
pub async fn enhance_character_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    Json(payload): Json<EnhancementRequest>,
) -> Result<Json<EnhancementResult>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    info!(
        "Enhancing character field {} for user {}",
        payload.field.display_name(),
        user.id
    );

    use genai::chat::{
        ChatMessage as GenAiChatMessage, ChatOptions as GenAiChatOptions, ChatRequest,
        ChatResponseFormat, ChatRole, JsonSchemaSpec, MessageContent,
    };

    // Build system prompt for enhancement
    let system_prompt = format!(
        r#"You are an AI assistant specialized in enhancing character content for interactive storytelling and roleplay.

Your task is to improve the existing {} content while maintaining the character's core identity and personality. Follow these guidelines:

1. **Preserve Core Elements**: Keep the fundamental character traits, relationships, and backstory intact
2. **Enhance Quality**: Improve clarity, depth, and engagement without changing the essential meaning
3. **Add Detail**: Expand on existing ideas with richer descriptions and nuance
4. **Maintain Consistency**: Ensure the enhanced content aligns with the character context
5. **Follow Instructions**: Apply the specific enhancement instructions provided by the user

You must respond with a JSON object containing:
- **enhanced_content**: The improved version of the content
- **changes_made**: A list of specific improvements you made
- **improvement_reasoning**: Explanation of why these improvements enhance the content
- **quality_improvement**: Your assessment (1-10) of how much better the content is

Be thoughtful and preserve the creator's original vision while elevating the quality."#,
        payload.field.display_name()
    );

    // Build user message with current content and enhancement instructions
    let mut user_message = format!(
        "**Field Being Enhanced:** {}\n\n**Current Content:**\n{}\n\n",
        payload.field.display_name(),
        payload.current_content
    );

    user_message.push_str(&format!(
        "**Enhancement Instructions:**\n{}\n\n",
        payload.enhancement_instructions
    ));

    if let Some(character_context) = &payload.character_context {
        user_message.push_str("**Character Context:**\n");
        if let Some(name) = &character_context.name {
            user_message.push_str(&format!("- Name: {}\n", name));
        }
        if let Some(description) = &character_context.description {
            user_message.push_str(&format!("- Description: {}\n", description));
        }
        if let Some(personality) = &character_context.personality {
            user_message.push_str(&format!("- Personality: {}\n", personality));
        }
        if let Some(scenario) = &character_context.scenario {
            user_message.push_str(&format!("- Scenario: {}\n", scenario));
        }
        user_message.push('\n');
    }

    user_message.push_str(
        "Please enhance the content according to the instructions while maintaining consistency with the character context.",
    );

    // Create messages for generation
    let messages = vec![GenAiChatMessage {
        role: ChatRole::User,
        content: MessageContent::Text(user_message),
        options: None,
    }];

    // Set up chat options with structured output
    let mut chat_options = GenAiChatOptions::default();

    // Apply user-provided generation options if available
    if let Some(gen_options) = &payload.generation_options {
        if let Some(temp) = gen_options.temperature {
            chat_options = chat_options.with_temperature(temp.into());
        }
        if let Some(max_len) = gen_options.max_length {
            if let Ok(max_tokens) = u32::try_from(max_len) {
                chat_options = chat_options.with_max_tokens(max_tokens);
            }
        }
    } else {
        // Default: moderate temperature for balanced enhancement
        chat_options = chat_options.with_temperature(0.7);
        chat_options = chat_options.with_max_tokens(2048);
    }

    // Enable structured output using JSON schema
    let json_schema_spec = JsonSchemaSpec::new(get_enhancement_schema());
    let response_format = ChatResponseFormat::JsonSchemaSpec(json_schema_spec);
    chat_options = chat_options.with_response_format(response_format);

    // Create chat request
    let chat_request = ChatRequest::new(messages).with_system(&system_prompt);

    // Execute generation
    let start_time = std::time::Instant::now();
    let response = state
        .ai_client
        .exec_chat(
            &state.config.token_counter_default_model,
            chat_request,
            Some(chat_options),
        )
        .await
        .map_err(|e| AppError::GeminiError(format!("Enhancement failed: {}", e)))?;

    // Extract and parse the response
    let response_text = response
        .contents
        .into_iter()
        .next()
        .and_then(|content| match content {
            MessageContent::Text(text) => Some(text),
            _ => None,
        })
        .ok_or_else(|| AppError::GeminiError("No content in response".to_string()))?;

    let enhancement_output: EnhancementOutput =
        serde_json::from_str(&response_text).map_err(|e| {
            AppError::InternalServerErrorGeneric(format!(
                "Failed to parse enhancement output: {}",
                e
            ))
        })?;

    // Calculate generation time
    let generation_time_ms = start_time.elapsed().as_millis() as u64;

    // Create metadata
    let metadata = crate::services::character_generation::types::GenerationMetadata {
        tokens_used: 0, // TODO: Calculate token usage
        generation_time_ms,
        style_detected: None,
        model_used: state.config.token_counter_default_model.clone(),
        timestamp: chrono::Utc::now(),
        debug_info: None,
    };

    // Create result
    let result = EnhancementResult {
        enhanced_content: enhancement_output.enhanced_content,
        changes_made: enhancement_output.changes_made,
        metadata,
    };

    info!(
        "Successfully enhanced {} in {}ms (quality improvement: {:?})",
        payload.field.display_name(),
        generation_time_ms,
        enhancement_output.quality_improvement
    );

    Ok(Json(result))
}

// ============================================================================
// Lorebook Generation Handlers
// ============================================================================

pub async fn generate_lorebook_entries_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    dek: SessionDek, // SECURITY: SessionDek for potential lorebook context
    Json(payload): Json<BatchLorebookGenerationRequest>,
) -> Result<Json<BatchLorebookGenerationResponse>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    info!(
        "Generating {} lorebook entries for user {}",
        payload.count, user.id
    );

    use crate::services::character_generation::types::{
        CharacterField, DescriptionStyle, GenerationMode,
    };
    use genai::chat::{
        ChatMessage as GenAiChatMessage, ChatOptions as GenAiChatOptions, ChatRequest,
        ChatResponseFormat, ChatRole, JsonSchemaSpec, MessageContent,
    };

    // Use FieldGenerator for comprehensive prompt engineering
    let field_generator = FieldGenerator::new(Arc::new(state.clone()));

    // Get mode and style from payload or use defaults
    let mode = payload.mode.clone().unwrap_or(GenerationMode::Create);
    let style = payload.style.clone().unwrap_or(DescriptionStyle::Profile);

    // Build FieldGenerationRequest for entry content with mode support
    let content_request = FieldGenerationRequest {
        field: CharacterField::EntryContent,
        mode: mode.clone(),
        style: Some(style.clone()),
        user_prompt: payload.prompt.clone(),
        character_context: payload.character_context.clone(),
        generation_options: None,
        lorebook_id: payload.lorebook_id,
    };

    // Use FieldGenerator's system prompt building for comprehensive prompt engineering
    // This gives us the same BASE_SYSTEM_PROMPT + MODE_INSTRUCTIONS + FIELD_CONTEXT + STYLE_PROMPT + FINAL_GUIDELINES
    // that character-editor uses
    let system_prompt = field_generator.build_field_generation_system_prompt(
        &content_request.field,
        &content_request.mode,
        &content_request
            .style
            .clone()
            .unwrap_or(DescriptionStyle::Auto),
    );

    // Build user message with batch context
    let mut user_message = format!(
        "**Generation Request:** Generate {} lorebook entries based on: {}\n\n",
        payload.count, payload.prompt
    );

    if let Some(character_context) = &payload.character_context {
        user_message.push_str("**Character Context:**\n");
        if let Some(name) = &character_context.name {
            user_message.push_str(&format!("- Name: {}\n", name));
        }
        if let Some(description) = &character_context.description {
            user_message.push_str(&format!("- Description: {}\n", description));
        }
        if let Some(scenario) = &character_context.scenario {
            user_message.push_str(&format!("- Scenario: {}\n", scenario));
        }
        user_message.push('\n');
    }

    if let Some(world_context) = &payload.world_context {
        user_message.push_str(&format!("**World Context:**\n{}\n\n", world_context));
    }

    user_message.push_str(&format!(
        "Generate {} detailed, engaging lorebook entries that enrich the world and maintain consistency with the provided context. \
        Ensure the entries are related and complement each other without being redundant.",
        payload.count
    ));

    // Create messages for generation
    let messages = vec![GenAiChatMessage {
        role: ChatRole::User,
        content: MessageContent::Text(user_message),
        options: None,
    }];

    // Set up chat options with structured output
    let mut chat_options = GenAiChatOptions::default();

    // Apply temperature from payload or use default
    if let Some(temp) = payload.temperature {
        chat_options = chat_options.with_temperature(temp as f64);
    } else {
        chat_options = chat_options.with_temperature(0.8); // Creative generation
    }

    // Increase max tokens for batch generation
    let max_tokens = if let Some(max) = payload.max_tokens {
        max
    } else {
        (payload.count * 800).min(8192) as u32
    };
    chat_options = chat_options.with_max_tokens(max_tokens);

    // Enable structured output using JSON schema for batch entries
    let json_schema_spec = JsonSchemaSpec::new(get_batch_lorebook_entries_schema());
    let response_format = ChatResponseFormat::JsonSchemaSpec(json_schema_spec);
    chat_options = chat_options.with_response_format(response_format);

    // Create chat request with comprehensive system prompt from FieldGenerator
    let chat_request = ChatRequest::new(messages).with_system(&system_prompt);

    // Execute generation
    let start_time = std::time::Instant::now();
    let response = state
        .ai_client
        .exec_chat(
            &state.config.token_counter_default_model,
            chat_request,
            Some(chat_options),
        )
        .await
        .map_err(|e| AppError::GeminiError(format!("Batch lorebook generation failed: {}", e)))?;

    // Extract and parse the response
    let response_text = response
        .contents
        .into_iter()
        .next()
        .and_then(|content| match content {
            MessageContent::Text(text) => Some(text),
            _ => None,
        })
        .ok_or_else(|| AppError::GeminiError("No content in response".to_string()))?;

    let batch_output: BatchLorebookEntriesOutput =
        serde_json::from_str(&response_text).map_err(|e| {
            AppError::InternalServerErrorGeneric(format!(
                "Failed to parse batch lorebook entries output: {}",
                e
            ))
        })?;

    // Validate the output
    batch_output.validate()?;

    // Calculate generation time
    let generation_time_ms = start_time.elapsed().as_millis() as u64;

    // Create metadata with mode and style information
    let metadata = ApiGenerationMetadata {
        model: state.config.token_counter_default_model.clone(),
        tokens_used: 0, // TODO: Calculate token usage
        cost: 0.0,      // TODO: Calculate cost
        generation_time_ms,
        finish_reason: Some("stop".to_string()),
        style_detected: Some(style.clone()),
        system_prompt: None,
        user_prompt: None,
        lorebook_context_included: Some(payload.lorebook_id.is_some()),
        lorebook_entries_count: Some(batch_output.entries.len()),
        query_text_used: None,
    };

    // Convert to response format
    let entries: Vec<LorebookGenerationResponse> = batch_output
        .entries
        .into_iter()
        .map(|entry| LorebookGenerationResponse {
            name: entry.name,
            content: entry.content,
            keys: entry.keys,
            category: entry.category,
            metadata: metadata.clone(),
        })
        .collect();

    let response = BatchLorebookGenerationResponse { entries, metadata };

    info!(
        "Successfully generated {} lorebook entries in {}ms (mode: {}, style: {:?})",
        payload.count,
        generation_time_ms,
        mode.as_str(),
        style
    );

    Ok(Json(response))
}

/// POST /api/generation/lorebook/entry
///
/// Generate a single lorebook entry from a prompt using comprehensive prompt engineering
#[instrument(skip_all)]
pub async fn generate_lorebook_entry_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    dek: SessionDek, // SECURITY: SessionDek for potential lorebook context
    Json(payload): Json<LorebookGenerationRequest>,
) -> Result<Json<LorebookGenerationResponse>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    info!("Generating single lorebook entry for user {}", user.id);

    use crate::services::character_generation::types::{
        CharacterField, DescriptionStyle, GenerationMode,
    };
    use genai::chat::{
        ChatMessage as GenAiChatMessage, ChatOptions as GenAiChatOptions, ChatRequest,
        ChatResponseFormat, ChatRole, JsonSchemaSpec, MessageContent,
    };

    // Use FieldGenerator for comprehensive prompt engineering
    let field_generator = FieldGenerator::new(Arc::new(state.clone()));

    // Build FieldGenerationRequest for entry content with mode support
    let mode = payload.mode.clone().unwrap_or(GenerationMode::Create);
    let style = payload.style.clone().unwrap_or(DescriptionStyle::Profile);

    let content_request = FieldGenerationRequest {
        field: CharacterField::EntryContent,
        mode: mode.clone(),
        style: Some(style.clone()),
        user_prompt: payload.prompt.clone(),
        character_context: payload.character_context.clone(),
        generation_options: None,
        lorebook_id: payload.lorebook_id,
    };

    // Use FieldGenerator's system prompt building for entry content
    // This gives us the comprehensive prompt engineering from character-editor
    let system_prompt = field_generator.build_field_generation_system_prompt(
        &content_request.field,
        &content_request.mode,
        &content_request
            .style
            .clone()
            .unwrap_or(DescriptionStyle::Auto),
    );

    // Build user message using FieldGenerator's message building
    // (This is a simplified version - we'll need to access the method)
    let mut user_message = format!("**Generation Request:** {}\n\n", payload.prompt);

    if let Some(character_context) = &payload.character_context {
        user_message.push_str("**Character Context:**\n");
        if let Some(name) = &character_context.name {
            user_message.push_str(&format!("- Name: {}\n", name));
        }
        if let Some(description) = &character_context.description {
            user_message.push_str(&format!("- Description: {}\n", description));
        }
        if let Some(scenario) = &character_context.scenario {
            user_message.push_str(&format!("- Scenario: {}\n", scenario));
        }
        user_message.push('\n');
    }

    if let Some(world_context) = &payload.world_context {
        user_message.push_str(&format!("**World Context:**\n{}\n\n", world_context));
    }

    user_message.push_str("Generate a detailed, engaging lorebook entry that enriches the world and maintains consistency with the provided context.");

    // Create messages for generation
    let messages = vec![GenAiChatMessage {
        role: ChatRole::User,
        content: MessageContent::Text(user_message),
        options: None,
    }];

    // Set up chat options with structured output
    let mut chat_options = GenAiChatOptions::default();

    // Apply temperature from payload or use default
    if let Some(temp) = payload.temperature {
        chat_options = chat_options.with_temperature(temp as f64);
    } else {
        chat_options = chat_options.with_temperature(0.8); // Creative generation
    }

    // Apply max_tokens from payload or use default
    if let Some(max_tokens) = payload.max_tokens {
        chat_options = chat_options.with_max_tokens(max_tokens);
    } else {
        chat_options = chat_options.with_max_tokens(2048); // Reasonable length for lorebook entries
    }

    // Enable structured output using JSON schema
    let json_schema_spec = JsonSchemaSpec::new(get_lorebook_entry_schema());
    let response_format = ChatResponseFormat::JsonSchemaSpec(json_schema_spec);
    chat_options = chat_options.with_response_format(response_format);

    // Create chat request with comprehensive system prompt from FieldGenerator
    let chat_request = ChatRequest::new(messages).with_system(&system_prompt);

    // Execute generation
    let start_time = std::time::Instant::now();
    let response = state
        .ai_client
        .exec_chat(
            &state.config.token_counter_default_model,
            chat_request,
            Some(chat_options),
        )
        .await
        .map_err(|e| AppError::GeminiError(format!("Lorebook generation failed: {}", e)))?;

    // Extract and parse the response
    let response_text = response
        .contents
        .into_iter()
        .next()
        .and_then(|content| match content {
            MessageContent::Text(text) => Some(text),
            _ => None,
        })
        .ok_or_else(|| AppError::GeminiError("No content in response".to_string()))?;

    let entry_output: LorebookEntryOutput = serde_json::from_str(&response_text).map_err(|e| {
        AppError::InternalServerErrorGeneric(format!(
            "Failed to parse lorebook entry output: {}",
            e
        ))
    })?;

    // Validate the output
    entry_output.validate()?;

    // Calculate generation time
    let generation_time_ms = start_time.elapsed().as_millis() as u64;

    // Create metadata
    let metadata = ApiGenerationMetadata {
        model: state.config.token_counter_default_model.clone(),
        tokens_used: 0, // TODO: Calculate token usage
        cost: 0.0,      // TODO: Calculate cost
        generation_time_ms,
        finish_reason: Some("stop".to_string()),
        style_detected: Some(style.clone()),
        system_prompt: None,
        user_prompt: None,
        lorebook_context_included: Some(payload.lorebook_id.is_some()),
        lorebook_entries_count: Some(1),
        query_text_used: None,
    };

    // Create response
    let response = LorebookGenerationResponse {
        name: entry_output.name,
        content: entry_output.content,
        keys: entry_output.keys,
        category: entry_output.category,
        metadata,
    };

    info!(
        "Successfully generated lorebook entry in {}ms (mode: {}, style: {:?})",
        generation_time_ms,
        mode.as_str(),
        style
    );

    Ok(Json(response))
}

// ============================================================================
// Scribe Assistant Handler
// ============================================================================

/// POST /api/generation/scribe-assistant
///
/// Interactive AI assistant for content creation and ideation
/// Provides a conversational interface for brainstorming, asking questions,
/// and getting help with character creation and storytelling
#[instrument(skip_all)]
pub async fn scribe_assistant_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    Json(payload): Json<ScribeAssistantRequest>,
) -> Result<Json<ScribeAssistantResponse>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    info!("Scribe assistant chat request from user {}", user.id);

    use genai::chat::{
        ChatMessage as GenAiChatMessage, ChatOptions as GenAiChatOptions, ChatRequest, ChatRole,
        MessageContent,
    };

    // Build system prompt for Scribe assistant
    let system_prompt = r#"You are Scribe, an AI assistant specialized in helping creators develop compelling characters for interactive storytelling, roleplay, and creative writing.

Your role is to:
- Help brainstorm character concepts and traits
- Provide guidance on character development and consistency
- Suggest ways to enhance character descriptions and personalities
- Answer questions about storytelling techniques and character creation
- Offer creative ideas while respecting the user's vision
- Provide constructive feedback on character content

Guidelines:
- Be encouraging and supportive of the creator's ideas
- Ask clarifying questions to better understand their goals
- Provide specific, actionable suggestions
- Maintain consistency with any character context provided
- Balance creativity with practicality
- Keep responses concise but helpful

You have access to character context when provided, which helps you give more relevant advice."#;

    // Build conversation messages
    let mut messages = Vec::new();

    // Add conversation history if provided
    if let Some(history) = &payload.conversation_history {
        for msg in history {
            let role = match msg.role.as_str() {
                "user" => ChatRole::User,
                "assistant" => ChatRole::Assistant,
                _ => continue, // Skip unknown roles
            };
            messages.push(GenAiChatMessage {
                role,
                content: MessageContent::Text(msg.content.clone()),
                options: None,
            });
        }
    }

    // Build the current user message with optional character context
    let mut user_message = payload.message.clone();

    if let Some(character_context) = &payload.character_context {
        // Append character context to help the assistant provide better responses
        user_message.push_str("\n\n**Character Context:**\n");
        if let Some(name) = &character_context.name {
            user_message.push_str(&format!("- Name: {}\n", name));
        }
        if let Some(description) = &character_context.description {
            user_message.push_str(&format!("- Description: {}\n", description));
        }
        if let Some(personality) = &character_context.personality {
            user_message.push_str(&format!("- Personality: {}\n", personality));
        }
        if let Some(scenario) = &character_context.scenario {
            user_message.push_str(&format!("- Scenario: {}\n", scenario));
        }
    }

    // Add current user message
    messages.push(GenAiChatMessage {
        role: ChatRole::User,
        content: MessageContent::Text(user_message),
        options: None,
    });

    // Set up chat options
    let mut chat_options = GenAiChatOptions::default();

    // Apply user-provided options
    if let Some(temp) = payload.temperature {
        chat_options = chat_options.with_temperature(temp.into());
    } else {
        // Default: balanced creativity for helpful assistant
        chat_options = chat_options.with_temperature(0.7);
    }

    if let Some(max_tokens) = payload.max_tokens {
        chat_options = chat_options.with_max_tokens(max_tokens);
    } else {
        // Default: reasonable response length
        chat_options = chat_options.with_max_tokens(1024);
    }

    // Create chat request
    let chat_request = ChatRequest::new(messages).with_system(system_prompt);

    // Execute chat
    let start_time = std::time::Instant::now();
    let response = state
        .ai_client
        .exec_chat(
            &state.config.token_counter_default_model,
            chat_request,
            Some(chat_options),
        )
        .await
        .map_err(|e| AppError::GeminiError(format!("Scribe assistant failed: {}", e)))?;

    // Extract response text
    let response_text = response
        .contents
        .into_iter()
        .next()
        .and_then(|content| match content {
            MessageContent::Text(text) => Some(text),
            _ => None,
        })
        .ok_or_else(|| AppError::GeminiError("No content in response".to_string()))?;

    // Calculate generation time
    let generation_time_ms = start_time.elapsed().as_millis() as u64;

    // Create metadata
    let metadata = ApiGenerationMetadata {
        model: state.config.token_counter_default_model.clone(),
        tokens_used: 0, // TODO: Calculate token usage
        cost: 0.0,      // TODO: Calculate cost
        generation_time_ms,
        finish_reason: Some("stop".to_string()),
        style_detected: None,
        system_prompt: None, // Don't expose system prompt to user
        user_prompt: None,
        lorebook_context_included: Some(false),
        lorebook_entries_count: Some(0),
        query_text_used: None,
    };

    // Create response
    let response = ScribeAssistantResponse {
        message: response_text,
        metadata,
    };

    info!("Scribe assistant responded in {}ms", generation_time_ms);

    Ok(Json(response))
}
