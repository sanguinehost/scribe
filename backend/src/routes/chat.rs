// backend/src/routes/chat.rs

use crate::auth::session_dek::SessionDek;
use crate::auth::user_store::Backend as AuthBackend;
use crate::errors::AppError;
use crate::models::agent_context_analysis::{AgentContextAnalysis, AnalysisType};
use crate::models::characters::{Character, CharacterMetadata}; // Added Character
use crate::models::chat_override::{CharacterOverrideDto, ChatCharacterOverride};
use crate::models::chats::CreateChatSessionPayload;
use crate::models::chats::{
    Chat,
    ChatMode,
    CreateMessageVariantPayload,
    ExpandTextRequest,
    ExpandTextResponse,
    GenerateChatRequest,
    ImpersonateRequest,
    ImpersonateResponse,
    MessageRole,
    MessageVariantDto,
    SuggestedActionItem,
    SuggestedActionsRequest,
    SuggestedActionsResponse, // Corrected DbChatMessage to ChatMessage
};
use crate::prompt_builder;
use crate::routes::chats::{get_chat_settings_handler, update_chat_settings_handler};
use crate::schema::{self as app_schema, chat_sessions}; // Added app_schema for characters table
use crate::services::chat;
use crate::services::chat::types::ScribeSseEvent;
use crate::services::hybrid_token_counter::CountingMode;
use crate::services::agentic::{
    context_enrichment_agent::{ContextEnrichmentAgent, EnrichmentMode},
    narrative_tools::SearchKnowledgeBaseTool,
};
use crate::services::ChronicleService;
use secrecy::ExposeSecret; // Added for ExposeSecret
// RetrievedMetadata is no longer directly used in this file for RAG string construction
// use crate::services::embedding_pipeline::RetrievedMetadata;
// RetrievedChunk is used by prompt_builder, not directly here.
// use crate::services::embedding_pipeline::RetrievedChunk;
use crate::state::AppState;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        IntoResponse, Sse,
        sse::{Event, KeepAlive},
    },
    routing::{get, post},
};
use axum_login::AuthSession;
use bigdecimal::ToPrimitive;
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper, prelude::*};
use futures_util::StreamExt;
use genai::chat::{
    ChatMessage as GenAiChatMessage, ChatOptions, ChatRequest, ChatResponseFormat, ChatRole,
    JsonSchemaSpec, MessageContent, ReasoningEffort,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::field;
use tracing::{debug, error, info, instrument, trace, warn};
use uuid::Uuid;
use validator::Validate;

// Define CurrentAuthSession type alias
type CurrentAuthSession = AuthSession<AuthBackend>;

// const RAG_CHUNK_LIMIT: u64 = 7; // No longer needed here, handled by prompt_builder

// Placeholder for response struct if it was missing
// Removed unused struct PlaceholderResponse
// #[derive(Serialize)]
// struct PlaceholderResponse { message: String }

#[derive(Deserialize, Debug)]
pub struct ChatGenerateQueryParams {
    #[serde(default)]
    request_thinking: bool,
}

#[derive(Serialize, Debug)] // Added derive Debug
pub struct ChatSessionWithDekResponse {
    // Made pub
    pub id: Uuid,
    pub user_id: Uuid,
    pub character_id: Option<Uuid>,
    pub title: Option<String>,
    pub dek_present: bool, // Simpler representation of DEK presence
}

#[derive(Deserialize, Validate, Debug)]
pub struct TokenCountRequest {
    pub text: String,
    pub model: Option<String>,
    #[serde(default)]
    pub use_api_counting: bool,
}

#[derive(Serialize, Debug)]
pub struct TokenCountResponse {
    pub total: usize,
    pub text: usize,
    pub images: usize,
    pub video: usize,
    pub audio: usize,
    pub is_estimate: bool,
    pub model_used: String,
    pub counting_method: String,
}

/// Response DTO for agent context analysis data
#[derive(Serialize, Debug)]
pub struct AgentAnalysisResponse {
    pub id: Uuid,
    pub chat_session_id: Uuid,
    pub analysis_type: String,
    pub agent_reasoning: Option<String>,
    pub planned_searches: Option<serde_json::Value>,
    pub execution_log: Option<serde_json::Value>,
    pub retrieved_context: Option<String>,
    pub analysis_summary: Option<String>,
    pub total_tokens_used: Option<i32>,
    pub execution_time_ms: Option<i32>,
    pub model_used: Option<String>,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub message_id: Option<Uuid>, // Link to specific message this analysis is for
    pub status: String,
    pub error_message: Option<String>,
    pub retry_count: i32,
}

#[instrument(skip_all, fields(user_id = field::Empty, character_id = field::Empty))]
pub async fn create_chat_session_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    session_dek: SessionDek, // Renamed from _session_dek as it will be used
    Json(payload): Json<CreateChatSessionPayload>,
) -> Result<(StatusCode, Json<Chat>), AppError> {
    info!("Attempting to create new chat session");

    let user = auth_session.user.as_ref().ok_or_else(|| {
        error!("User not found in session during chat creation");
        AppError::Unauthorized("User not found in session".to_string())
    })?;
    let user_id = user.id;
    tracing::Span::current().record("user_id", tracing::field::display(user_id));
    if let Some(character_id) = payload.character_id {
        tracing::Span::current().record(
            "character_id",
            tracing::field::display(character_id),
        );
    }
    if let Some(persona_id) = payload.active_custom_persona_id {
        tracing::Span::current().record(
            "active_custom_persona_id",
            tracing::field::display(persona_id),
        );
    }

    debug!(user_id = %user_id, character_id = ?payload.character_id, active_custom_persona_id=?payload.active_custom_persona_id, "User, character, and persona ID extracted");

    // Call the service function to create the chat session
    // Character-associated lorebooks are now handled implicitly by the lorebook service
    // and should not be explicitly associated at the chat session creation.
    let created_chat_session = chat::session_management::create_session_and_maybe_first_message(
        state.into(),
        user_id,
        payload.character_id,
        payload.chat_mode.unwrap_or(ChatMode::Character),
        payload.active_custom_persona_id, // Pass the new field
        None, // Do NOT pass character-derived lorebook IDs here; they are handled implicitly.
        Some(Arc::new(session_dek.0)), // Pass the DEK, wrapped in Arc for the service
    )
    .await?;

    info!(chat_id = %created_chat_session.id, "Chat session created successfully via service");
    Ok((StatusCode::CREATED, Json(created_chat_session)))
}

#[instrument(skip_all, fields(session_id = %session_id_str, user_id = field::Empty, chat_id = field::Empty, message_id = field::Empty))]
pub async fn generate_chat_response(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    session_dek: SessionDek,
    Path(session_id_str): Path<String>,
    Query(query_params): Query<ChatGenerateQueryParams>,
    headers: HeaderMap,
    Json(payload): Json<GenerateChatRequest>,
) -> Result<impl IntoResponse, AppError> {
    info!("Received request to generate chat response with history");
    payload.validate()?;
    trace!(payload = ?payload, query_params = ?query_params, "Received validated payload and query params");

    let state_arc = Arc::new(state);

    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("User not found in session".to_string()))?;

    tracing::debug!(user_id = %user.id, user_dek_from_auth_session_is_some = user.dek.is_some(), "generate_chat_response: Checked user.dek from auth_session (expected None or unused).");

    let user_id_value = user.id;
    let session_dek_arc = Arc::new(session_dek.0); // MODIFIED: Create Arc for SessionDek

    debug!(%user_id_value, "Using SessionDek from extractor (now in Arc) for chat generation.");

    let session_id = Uuid::parse_str(&session_id_str)
        .map_err(|_| AppError::BadRequest("Invalid session UUID format".to_string()))?;
    debug!(%session_id, "Parsed session ID");

    // Fetch chat session owner ID for authorization check
    let chat_session_owner_id = state_arc
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .select(chat_sessions::user_id)
                .first::<Uuid>(conn)
            // .map_err(AppError::from) // Let the outer error handling manage this
        })
        .await
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!(
                "Interact dispatch error checking session owner: {e}"
            ))
        })? // Handle interact error
        .map_err(|e_db| match e_db {
            // Handle DB error from the closure
            diesel::result::Error::NotFound => {
                AppError::NotFound(format!("Chat session {session_id} not found."))
            }
            _ => AppError::DatabaseQueryError(format!(
                "Failed to query chat session owner for {session_id}: {e_db}"
            )),
        })?;

    if chat_session_owner_id != user_id_value {
        error!(%session_id, expected_owner = %user_id_value, actual_owner = %chat_session_owner_id, "User forbidden from accessing chat session.");
        return Err(AppError::Forbidden(
            "Access denied to chat session".to_string(),
        ));
    }
    debug!(%session_id, "User authorized for chat session");

    // Extract the current user message content from the payload
    let current_user_api_message = payload.history.last().cloned().ok_or_else(|| {
        error!(%session_id, "Payload history is empty, cannot extract current user message.");
        AppError::BadRequest("Request payload must contain at least one message.".to_string())
    })?;

    if current_user_api_message.role.to_lowercase() != "user" {
        error!(%session_id, "Last message in payload history is not from user.");
        return Err(AppError::BadRequest(
            "The last message in the payload's history must be from the 'user'.".to_string(),
        ));
    }
    let current_user_content = current_user_api_message.content;
    trace!(%session_id, "Extracted current user message content for generation.");

    // Get comprehensive data for generation from chat_service
    let (
        managed_db_history,               // 0: Vec<DbChatMessage>
        system_prompt_from_service,       // 1: Option<String> (persona/override only)
        _active_lorebook_ids_for_search,  // 2: Option<Vec<Uuid>> - Now handled by prompt_builder
        session_character_id,             // 3: Uuid
        raw_character_system_prompt, // 4: Option<String> (NEW - from character_db.system_prompt)
        gen_temperature,             // 5: Option<BigDecimal> (was 4)
        gen_max_output_tokens,       // 6: Option<i32> (was 5)
        gen_frequency_penalty,       // 7: Option<BigDecimal> (was 6)
        gen_presence_penalty,        // 8: Option<BigDecimal> (was 7)
        gen_top_k,                   // 9: Option<i32> (was 8)
        gen_top_p,                   // 10: Option<BigDecimal> (was 9)
        gen_seed,                    // 11: Option<i32> (was 13)
        gen_model_name_from_service, // 12: String (was 15)
        gen_model_provider_from_service, // 13: Option<String> (NEW)
        gen_gemini_thinking_budget,  // 14: Option<i32> (was 16)
        gen_gemini_enable_code_execution, // 15: Option<bool> (was 17)
        user_message_struct_to_save, // 16: DbInsertableChatMessage (was 18)
        // -- New RAG related fields --
        _actual_recent_history_tokens_from_service, // 17: usize (NEW) - Handled by prompt_builder (was 19)
        rag_context_items_from_service, // 18: Vec<RetrievedChunk> (NEW) - Passed to prompt_builder (was 20)
        // -- Original history management settings --
        _hist_management_strategy, // 19: String (was 21)
        _hist_management_limit,    // 20: i32 (was 22)
        user_persona_name,         // 21: Option<String> (NEW)
        player_chronicle_id,       // 22: Option<Uuid> (NEW) - Add this field
        agent_mode,                // 23: Option<String> (NEW) - Agent mode for context enrichment
    ) = chat::generation::get_session_data_for_generation(
        state_arc.clone(),
        user_id_value,
        session_id,
        current_user_content.clone(),
        Some(session_dek_arc.clone()), // Use Arc clone
        // If payload.history only contains the current message, use database history instead
        if payload.history.len() <= 1 {
            None
        } else {
            Some(payload.history)
        },
    )
    .await?;

    debug!(
        %session_id,
        system_prompt_len = system_prompt_from_service.as_ref().map_or(0, String::len),
        gen_temp = ?gen_temperature,
        gen_max_tokens = ?gen_max_output_tokens,
        gen_top_p = ?gen_top_p,
        gen_model_name = %gen_model_name_from_service,
        rag_items_count = rag_context_items_from_service.len(),
        ?session_character_id,
        "Retrieved data for generation from chat_service."
    );

    // Fetch Character model from DB (only for character-based chats)
    let char_id = session_character_id.ok_or_else(|| {
        AppError::BadRequest("Character-based generation endpoints not supported for non-character chat modes".to_string())
    })?;
    let character_db_model = state_arc
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            app_schema::characters::table
                .filter(app_schema::characters::id.eq(char_id))
                .filter(app_schema::characters::user_id.eq(user_id_value))
                .select(Character::as_select())
                .first::<Character>(conn)
        })
        .await
        .map_err(|e| {
            error!(error = %e, "Interact dispatch error fetching character model");
            AppError::InternalServerErrorGeneric(format!(
                "Interact dispatch error fetching character: {e}"
            ))
        })?
        .map_err(|e_db| {
            if e_db == diesel::result::Error::NotFound {
                error!(character_id = %char_id, %user_id_value, "Character not found for user");
                AppError::NotFound(format!(
                    "Character {} not found for user {}", char_id, user_id_value
                ))
            } else {
                error!(error = %e_db, character_id = %char_id, "Failed to query character");
                AppError::DatabaseQueryError(format!(
                    "Failed to query character {}: {}", char_id, e_db
                ))
            }
        })?;

    let character_metadata_for_prompt_builder = CharacterMetadata {
        id: character_db_model.id,
        user_id: character_db_model.user_id,
        name: character_db_model.name.clone(),
        description: character_db_model.description.clone(),
        description_nonce: character_db_model.description_nonce.clone(),
        personality: character_db_model.personality.clone(),
        personality_nonce: character_db_model.personality_nonce.clone(),
        scenario: character_db_model.scenario.clone(),
        scenario_nonce: character_db_model.scenario_nonce.clone(),
        mes_example: character_db_model.mes_example.clone(),
        mes_example_nonce: character_db_model.mes_example_nonce.clone(),
        creator_comment: character_db_model.creator_comment.clone(),
        creator_comment_nonce: character_db_model.creator_comment_nonce.clone(),
        first_mes: character_db_model.first_mes.clone(),
        created_at: character_db_model.created_at,
        updated_at: character_db_model.updated_at,
    };
    trace!(%session_id, character_id = %character_metadata_for_prompt_builder.id, "Constructed CharacterMetadata for prompt builder.");

    let model_to_use = payload
        .model
        .clone()
        .unwrap_or_else(|| gen_model_name_from_service.clone());
    debug!(%model_to_use, "Determined final model to use for AI calls.");

    // Convert DbChatMessage history to GenAiChatMessage history
    let mut gen_ai_recent_history: Vec<GenAiChatMessage> = Vec::new();
    for db_msg in managed_db_history {
        // managed_db_history is Vec<DbChatMessage>
        // Content in managed_db_history from get_session_data_for_generation should already be decrypted
        let content_str = String::from_utf8_lossy(&db_msg.content).into_owned();
        let chat_role = match db_msg.message_type {
            MessageRole::User => ChatRole::User,
            MessageRole::Assistant => ChatRole::Assistant,
            MessageRole::System => ChatRole::System, // Should not happen in recent history
        };
        gen_ai_recent_history.push(GenAiChatMessage {
            role: chat_role,
            content: MessageContent::from_text(content_str),
            options: None,
        });
    }

    // Extract text for later use in saving to DB
    let current_user_content_text = current_user_content.clone();

    // Prepare current user message as GenAiChatMessage
    let current_user_genai_message = GenAiChatMessage {
        role: ChatRole::User,
        content: MessageContent::from_text(current_user_content),
        options: None,
    };

    // Before saving new messages, supersede any failed or partial messages from this session
    // This handles retry scenarios where the user might be retrying after an error
    {
        let pool = state_arc.pool.clone();
        let conn = pool.get().await?;
        let session_id_for_cleanup = session_id;
        
        if let Err(e) = conn.interact(move |conn| {
            // Supersede messages that are failed or partial in this session
            // We use a timestamp from 1 minute ago to avoid superseding very recent messages
            let cutoff_time = chrono::Utc::now() - chrono::Duration::seconds(60);
            crate::models::chats::ChatMessage::supersede_failed_messages(conn, session_id_for_cleanup, cutoff_time)
        }).await? {
            // Log the error but don't fail the request - cleanup is not critical
            warn!(error = ?e, session_id = %session_id, "Failed to supersede old failed/partial messages, continuing anyway");
        }
    }

    // Save the user message first to get its ID for agent analysis association
    let saved_user_message = match chat::message_handling::save_message(chat::message_handling::SaveMessageParams {
        state: state_arc.clone(),
        session_id,
        user_id: user_id_value,
        message_type_enum: MessageRole::User,
        content: &current_user_content_text,
        role_str: user_message_struct_to_save.role.clone(),
        parts: user_message_struct_to_save.parts.clone(),
        attachments: user_message_struct_to_save.attachments.clone(),
        user_dek_secret_box: Some(session_dek_arc.clone()),
        model_name: model_to_use.clone(),
        raw_prompt_debug: None, // User messages don't need raw prompt debug
        status: crate::models::chats::MessageStatus::Completed,
        error_message: None,
    })
    .await
    {
        Ok(saved_msg) => {
            debug!(message_id = %saved_msg.id, session_id = %session_id, message_status = ?saved_msg.status, "Successfully saved user message for agent analysis");
            saved_msg
        }
        Err(e) => {
            error!(error = ?e, session_id = %session_id, "Error saving user message");
            return Err(e);
        }
    };

    let user_message_id = saved_user_message.id;
    let user_message_status = saved_user_message.status.clone();

    // Check if we need to run pre-processing agent analysis
    // Now returns a tuple of (agent_context, analysis_id)
    // Handle the analysis_mode parameter from frontend for variant regeneration
    let should_skip_analysis = payload.analysis_mode.as_deref() == Some("skip");
    let should_refresh_analysis = payload.analysis_mode.as_deref() == Some("refresh");
    
    let (agent_context, pre_processing_analysis_id) = if should_skip_analysis {
        info!(%session_id, "Skipping agent analysis as requested (analysis_mode=skip)");
        (None, None)
    } else if let Some(mode) = &agent_mode {
        if mode == "pre_processing" {
            info!(%session_id, refresh = should_refresh_analysis, "Pre-processing agent mode enabled - checking for existing or running new analysis");
            
            // If refresh is requested, supersede existing analyses first
            if should_refresh_analysis {
                info!(%session_id, "Refresh requested - superseding existing analyses");
                let conn = state_arc.pool.get()
                    .await
                    .map_err(|e| AppError::DbPoolError(e.to_string()))?;
                
                let _ = conn.interact(move |conn| {
                    AgentContextAnalysis::supersede_failed_analyses(
                        conn,
                        session_id,
                        AnalysisType::PreProcessing,
                    )
                })
                .await
                .map_err(|e| {
                    warn!(%session_id, error = ?e, "Failed to supersede existing analyses");
                    AppError::InternalServerErrorGeneric(e.to_string())
                });
            }
            
            // Check if we have an existing analysis (unless refresh was requested)
            let existing_analysis = if !should_refresh_analysis {
                let conn = state_arc.pool.get()
                    .await
                    .map_err(|e| AppError::DbPoolError(e.to_string()))?;
                
                conn.interact(move |conn| {
                    AgentContextAnalysis::get_for_session(
                        conn,
                        session_id,
                        AnalysisType::PreProcessing,
                    )
                })
                .await
                .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))?
                ?  // Double ? to unwrap both Results
            } else {
                None
            };
            
            match existing_analysis {
                Some(analysis) if !should_refresh_analysis => {
                    // Use the model's built-in decryption method
                    match analysis.get_decrypted_summary(&session_dek_arc) {
                        Ok(summary) => {
                            info!(%session_id, "Using existing pre-processing agent analysis");
                            (Some(summary), Some(analysis.id))
                        }
                        Err(e) => {
                            warn!(%session_id, error = ?e, "Failed to decrypt pre-processing analysis");
                            (None, None)
                        }
                    }
                }
                _ => {
                    // No existing analysis or refresh requested, run the agent
                    info!(%session_id, "No existing pre-processing analysis found, running agent");
                    
                    // Create the agent with dependencies
                    let search_tool = Arc::new(SearchKnowledgeBaseTool::new(
                        state_arc.qdrant_service.clone(),
                        state_arc.embedding_client.clone(),
                        state_arc.clone(),
                    ));
                    
                    let chronicle_service = Arc::new(ChronicleService::new(
                        state_arc.pool.clone(),
                    ));
                    
                    let agent = ContextEnrichmentAgent::new(
                        state_arc.clone(),
                        search_tool,
                        chronicle_service,
                    );
                    
                    // Prepare messages for the agent (last 10 messages)
                    let recent_messages: Vec<(String, String)> = gen_ai_recent_history
                        .iter()
                        .take(10)
                        .map(|msg| {
                            let role = match msg.role {
                                ChatRole::User => "User".to_string(),
                                ChatRole::Assistant => "Assistant".to_string(),
                                _ => "System".to_string(),
                            };
                            let content = match &msg.content {
                                MessageContent::Text(text) => text.clone(),
                                _ => String::new(),
                            };
                            (role, content)
                        })
                        .collect();
                    
                    // Add the current user message
                    let mut messages_for_agent = recent_messages;
                    messages_for_agent.push(("User".to_string(), current_user_content_text.clone()));
                    
                    // Run the agent with the user message ID
                    match agent.enrich_context(
                        session_id,
                        user_id_value,
                        player_chronicle_id,  // Pass chronicle_id for scoped search
                        &messages_for_agent,
                        EnrichmentMode::PreProcessing,
                        session_dek_arc.expose_secret(),
                        user_message_id,  // Pass the user message ID for association (REQUIRED)
                    ).await {
                        Ok(result) => {
                            info!(%session_id, tokens_used = result.total_tokens_used, 
                                  "Pre-processing agent completed successfully");
                            (Some(result.analysis_summary), result.analysis_id)
                        }
                        Err(e) => {
                            warn!(%session_id, error = ?e, "Pre-processing agent failed");
                            (None, None)
                        }
                    }
                }
            }
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    // Clone gen_ai_recent_history before moving it, as we'll need it later for post-processing
    let gen_ai_recent_history_for_agent = gen_ai_recent_history.clone();
    
    // Call the new prompt builder
    let (final_system_prompt_str, final_genai_message_list) =
        match prompt_builder::build_final_llm_prompt(prompt_builder::PromptBuildParams {
            config: state_arc.config.clone(),
            token_counter: state_arc.token_counter.clone(),
            recent_history: gen_ai_recent_history,
            rag_items: rag_context_items_from_service,
            system_prompt_base: system_prompt_from_service, // This is the system_prompt_base (persona/override only)
            raw_character_system_prompt, // This is the new raw_character_system_prompt
            character_metadata: Some(&character_metadata_for_prompt_builder),
            current_user_message: current_user_genai_message,
            model_name: model_to_use.clone(),
            user_dek: Some(&*session_dek_arc), // Add DEK for character description decryption
            user_persona_name,                 // Pass user persona name for template substitution
            agent_context,                      // Pass agent context if available
        })
        .await
        {
            Ok(prompt_data) => prompt_data,
            Err(e) => {
                error!(%session_id, error = ?e, "Failed to build final LLM prompt");
                return Err(e);
            }
        };

    trace!(history_len = final_genai_message_list.len(), %session_id, "Prepared final message list for AI using new prompt builder.");

    let accept_header = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    let request_thinking = query_params.request_thinking;
    debug!(%session_id, %request_thinking, "request_thinking value from query parameters");

    // The system_prompt_from_service is now part of final_system_prompt_str
    // The old final_system_prompt logic is removed.

    match accept_header {
        v if v.contains(mime::TEXT_EVENT_STREAM.as_ref()) => {
            info!(%session_id, "Handling streaming SSE request. request_thinking={}", request_thinking);

            // User message was already saved above to get message_id for pre-processing

            // The assistant's message will be saved by stream_ai_response_and_save_message.

            let dek_for_stream_service = session_dek_arc.clone();
            match chat::generation::stream_ai_response_and_save_message_with_retry(
                chat::generation::StreamAiParams {
                    state: state_arc.clone(),
                    session_id,
                    user_id: user_id_value,
                    incoming_genai_messages: final_genai_message_list.clone(),
                    system_prompt: Some(final_system_prompt_str.clone()),
                    temperature: gen_temperature,
                    max_output_tokens: gen_max_output_tokens,
                    frequency_penalty: gen_frequency_penalty,
                    presence_penalty: gen_presence_penalty,
                    top_k: gen_top_k,
                    top_p: gen_top_p,
                    stop_sequences: None,
                    seed: gen_seed,
                    model_name: model_to_use.clone(),
                    model_provider: gen_model_provider_from_service,
                    gemini_thinking_budget: gen_gemini_thinking_budget,
                    gemini_enable_code_execution: gen_gemini_enable_code_execution,
                    request_thinking,
                    user_dek: Some(dek_for_stream_service),
                    character_name: Some(character_db_model.name.clone()),
                    player_chronicle_id,
                },
            )
            .await
            {
                Ok(service_stream) => {
                    debug!(%session_id, "Successfully obtained stream from chat_service::stream_ai_response_and_save_message");
                    
                    // Clone data needed for the stream
                    let pre_processing_analysis_id_clone = pre_processing_analysis_id.clone();
                    let state_for_update = state_arc.clone();
                    let session_id_for_update = session_id.clone();
                    
                    let final_stream = async_stream::stream! {
                        let mut content_produced = false;
                        let mut error_from_service_stream = false;
                        let mut assistant_message_id: Option<Uuid> = None;
                        futures::pin_mut!(service_stream);

                        while let Some(event_result) = service_stream.next().await {
                            match event_result {
                                Ok(scribe_event) => {
                                    let axum_sse_event = match scribe_event {
                                        ScribeSseEvent::Content(data) => {
                                            if !data.is_empty() { content_produced = true; }
                                            Event::default().event("content").data(data)
                                        }
                                        ScribeSseEvent::Thinking(data) => {
                                            Event::default().event("thinking").data(data)
                                        }
                                        ScribeSseEvent::Error(data) => {
                                            error_from_service_stream = true;
                                            Event::default().event("error").data(data)
                                        }
                                        ScribeSseEvent::TokenUsage { prompt_tokens, completion_tokens, model_name } => {
                                            let token_data = serde_json::json!({
                                                "prompt_tokens": prompt_tokens,
                                                "completion_tokens": completion_tokens,
                                                "model_name": model_name
                                            });
                                            Event::default().event("token_usage").data(token_data.to_string())
                                        }
                                        ScribeSseEvent::MessageSaved { message_id } => {
                                            // Capture the assistant message ID for post-processing
                                            if let Ok(msg_uuid) = Uuid::parse_str(&message_id) {
                                                assistant_message_id = Some(msg_uuid);
                                                
                                                // Update pre-processing analysis with assistant message ID if we have one
                                                if let Some(analysis_id) = pre_processing_analysis_id_clone {
                                                    debug!(session_id = %session_id_for_update, %analysis_id, 
                                                           assistant_message_id = %msg_uuid, 
                                                           "Updating pre-processing analysis with assistant message ID (streaming)");
                                                    
                                                    // Clone for the async task
                                                    let state_clone = state_for_update.clone();
                                                    let session_id_clone = session_id_for_update.clone();
                                                    
                                                    // Spawn a task to update the analysis
                                                    tokio::spawn(async move {
                                                        let conn = state_clone.pool.get().await;
                                                        if let Ok(conn) = conn {
                                                            let update_result = conn.interact(move |conn| {
                                                                AgentContextAnalysis::update_assistant_message_id(
                                                                    conn,
                                                                    analysis_id,
                                                                    msg_uuid,
                                                                )
                                                            })
                                                            .await;
                                                            
                                                            match update_result {
                                                                Ok(Ok(())) => {
                                                                    debug!(session_id = %session_id_clone, 
                                                                           "Successfully updated pre-processing analysis with assistant message ID");
                                                                }
                                                                Ok(Err(e)) => {
                                                                    warn!(session_id = %session_id_clone, error = ?e, 
                                                                          "Failed to update analysis with assistant message ID");
                                                                }
                                                                Err(e) => {
                                                                    warn!(session_id = %session_id_clone, error = ?e, 
                                                                          "Failed to interact with DB for analysis update");
                                                                }
                                                            }
                                                        }
                                                    });
                                                }
                                            }
                                            let message_data = serde_json::json!({
                                                "message_id": message_id
                                            });
                                            Event::default().event("message_saved").data(message_data.to_string())
                                        }
                                    };
                                    yield Ok(axum_sse_event);
                                }
                                Err(e) => {
                                    error_from_service_stream = true;
                                    yield Err(e);
                                }
                            }
                        }
                        if error_from_service_stream {
                            debug!(%session_id, "Service stream ended with an error or an error event was already sent. Not sending additional [DONE] event.");
                        } else if content_produced {
                            // Run post-processing agent if enabled
                            if let Some(mode) = &agent_mode {
                                if mode == "post_processing" {
                                    // Only run post-processing if we have a valid assistant message ID
                                    if let Some(assistant_msg_id) = assistant_message_id {
                                        info!(%session_id, ?assistant_msg_id, "Post-processing agent mode enabled - will run in background");
                                        
                                        // Note: We should check the assistant message status before running post-processing
                                        // but in streaming mode, the message is saved after streaming completes successfully,
                                        // so it should have status=completed. Failed streams won't reach this point.
                                        
                                        // Clone necessary data for the background task
                                        let session_id_clone = session_id;
                                        let user_id_clone = user_id_value;
                                        let player_chronicle_id_clone = player_chronicle_id;  // Clone chronicle_id for scoped search
                                        let state_clone = state_arc.clone();
                                        let session_dek_clone = session_dek_arc.clone();
                                        let recent_history_clone = gen_ai_recent_history_for_agent.clone();
                                        let current_user_text = current_user_content_text.clone();
                                    
                                    tokio::spawn(async move {
                                        info!(session_id = %session_id_clone, "Starting post-processing agent in background");
                                        
                                        // Create the agent with dependencies
                                        let search_tool = Arc::new(SearchKnowledgeBaseTool::new(
                                            state_clone.qdrant_service.clone(),
                                            state_clone.embedding_client.clone(),
                                            state_clone.clone(),
                                        ));
                                        
                                        let chronicle_service = Arc::new(ChronicleService::new(
                                            state_clone.pool.clone(),
                                        ));
                                        
                                        let agent = ContextEnrichmentAgent::new(
                                            state_clone.clone(),
                                            search_tool,
                                            chronicle_service,
                                        );
                                        
                                        // Prepare messages for the agent
                                        let recent_messages: Vec<(String, String)> = recent_history_clone
                                            .iter()
                                            .take(10)
                                            .map(|msg| {
                                                let role = match msg.role {
                                                    ChatRole::User => "User".to_string(),
                                                    ChatRole::Assistant => "Assistant".to_string(),
                                                    _ => "System".to_string(),
                                                };
                                                let content = match &msg.content {
                                                    MessageContent::Text(text) => text.clone(),
                                                    _ => String::new(),
                                                };
                                                (role, content)
                                            })
                                            .collect();
                                        
                                        // Add the current exchange
                                        let mut messages_for_agent = recent_messages;
                                        messages_for_agent.push(("User".to_string(), current_user_text));
                                        // Note: We don't have the assistant's response here in streaming mode
                                        // The agent will work with what it has
                                        
                                        // Run the agent with the required assistant message ID
                                        match agent.enrich_context(
                                            session_id_clone,
                                            user_id_clone,
                                            player_chronicle_id_clone,  // Pass chronicle_id for scoped search
                                            &messages_for_agent,
                                            EnrichmentMode::PostProcessing,
                                            session_dek_clone.expose_secret(),
                                            assistant_msg_id,  // Pass the required assistant message ID for association
                                        ).await {
                                            Ok(result) => {
                                                info!(
                                                    session_id = %session_id_clone, 
                                                    tokens_used = result.total_tokens_used,
                                                    execution_time_ms = result.execution_time_ms,
                                                    "Post-processing agent completed successfully"
                                                );
                                            }
                                            Err(e) => {
                                                warn!(
                                                    session_id = %session_id_clone, 
                                                    error = ?e, 
                                                    "Post-processing agent failed"
                                                );
                                            }
                                        }
                                    });
                                    } else {
                                        warn!(%session_id, "Skipping post-processing agent - no assistant message ID available in streaming mode");
                                    }
                                }
                            }
                            
                            debug!(%session_id, "Service stream ended, adding delay before [DONE] to ensure all chunks are transmitted.");
                            
                            // Critical: Add delay to ensure all chunks in the SSE pipeline are transmitted
                            // This prevents the connection from closing while chunks are still in flight
                            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                            
                            debug!(%session_id, "Delay complete, now sending [DONE] event.");
                            yield Ok(Event::default().event("done").data("[DONE]"));
                        } else {
                            debug!(%session_id, "Service stream ended without producing content (and no error), sending [DONE_EMPTY] event.");
                            yield Ok(Event::default().event("done").data("[DONE_EMPTY]"));
                        }
                    };
                    Ok(Sse::new(Box::pin(final_stream))
                        .keep_alive(
                            KeepAlive::new()
                                .interval(std::time::Duration::from_secs(1))
                                .text("keep-alive")
                        )
                        .into_response())
                }
                Err(e) => {
                    error!(error = ?e, %session_id, "Error calling chat_service::stream_ai_response_and_save_message");
                    let error_stream = async_stream::stream! {
                        let error_msg = format!("Service error: Failed to initiate AI processing - {e}");
                        trace!(%session_id, error_message = %error_msg, "Sending SSE 'error' event (service call failed)");
                        yield Ok::<_, AppError>(Event::default().event("error").data(error_msg));
                    };
                    Ok(Sse::new(Box::pin(error_stream))
                        .keep_alive(KeepAlive::default())
                        .into_response())
                }
            }
        }
        v if v.contains(mime::APPLICATION_JSON.as_ref()) => {
            info!(%session_id, "Handling non-streaming JSON request. request_thinking={}", request_thinking);

            // _user_message_to_save_for_db from get_session_data_for_generation contains the structured user message.
            // For JSON path, we save the user message explicitly before calling AI.
            // The content is current_user_content.

            let dek_for_user_save_json = session_dek_arc.clone();
            let _user_saved_message = match chat::message_handling::save_message(
                chat::message_handling::SaveMessageParams {
                    state: state_arc.clone(),
                    session_id,
                    user_id: user_id_value,
                    message_type_enum: MessageRole::User,
                    content: &current_user_content_text,
                    role_str: Some("user".to_string()),
                    parts: Some(json!([{"text": current_user_content_text}])),
                    attachments: None,
                    user_dek_secret_box: Some(dek_for_user_save_json),
                    model_name: model_to_use.clone(),
                    raw_prompt_debug: None, // User messages don't need raw prompt debug
                    status: crate::models::chats::MessageStatus::Completed,
                    error_message: None,
                },
            )
            .await
            {
                Ok(saved_msg) => {
                    debug!(message_id = %saved_msg.id, session_id = %session_id, "Successfully saved user message via chat_service (JSON path)");
                    saved_msg
                }
                Err(e) => {
                    error!(error = ?e, session_id = %session_id, "Error saving user message via chat_service (JSON path)");
                    return Err(e);
                }
            };

            // RAG context is handled by build_final_llm_prompt.
            // The old RAG logic here is removed.

            let chat_request = ChatRequest::new(final_genai_message_list.clone())
                .with_system(final_system_prompt_str.clone());

            let mut chat_options = ChatOptions::default();
            if let Some(temp_bd) = gen_temperature {
                if let Some(temp_f32) = temp_bd.to_f32() {
                    chat_options = chat_options.with_temperature(temp_f32.into());
                }
            }
            if let Some(tokens_i32) = gen_max_output_tokens {
                // tokens_i32 is Option<i32>
                if let Ok(tokens_u32) = u32::try_from(tokens_i32) {
                    chat_options = chat_options.with_max_tokens(tokens_u32);
                } else {
                    warn!("max_output_tokens is invalid ({}), ignoring", tokens_i32);
                }
            }
            if let Some(p_bd) = gen_top_p {
                // p_bd is Option<BigDecimal>
                if let Some(p_f32) = p_bd.to_f32() {
                    chat_options = chat_options.with_top_p(p_f32.into());
                }
            }
            // Add other gen_... parameters to chat_options as needed
            if let Some(budget_i32) = gen_gemini_thinking_budget {
                // budget_i32 is Option<i32>
                if budget_i32 > 0 {
                    if let Ok(budget_u32) = u32::try_from(budget_i32) {
                        chat_options =
                            chat_options.with_reasoning_effort(ReasoningEffort::Budget(budget_u32));
                    } else {
                        warn!("gemini_thinking_budget overflow ({}), ignoring", budget_i32);
                    }
                } else {
                    warn!(
                        "gemini_thinking_budget is not positive ({}), ignoring",
                        budget_i32
                    );
                }
            }
            // `with_gemini_enable_code_execution` removed as it's no longer a direct ChatOption.
            // The `gen_gemini_enable_code_execution` variable is still available if needed for other logic.

            // TODO: Add other gen_ parameters like top_k, frequency_penalty etc. if supported by ChatOptions

            trace!(%session_id, chat_request = ?chat_request, chat_options = ?chat_options, "Prepared ChatRequest and Options for AI (non-streaming, JSON path)");

            match chat::generation::exec_chat_with_retry(
                chat::generation::ExecChatWithRetryParams {
                    state: state_arc.clone(),
                    model_name: model_to_use.clone(),
                    model_provider: gen_model_provider_from_service,
                    chat_request,
                    chat_options: Some(chat_options),
                    session_id,
                    user_id: user_id_value,
                    character_name: Some(character_db_model.name.clone()),
                },
            )
            .await
            {
                Ok(chat_response) => {
                    debug!(%session_id, "Received successful non-streaming AI response (JSON path)");

                    let response_content = chat_response
                        .contents
                        .into_iter()
                        .next()
                        .and_then(|content| match content {
                            genai::chat::MessageContent::Text(text) => Some(text),
                            _ => None,
                        })
                        .unwrap_or_default();

                    trace!(%session_id, ?response_content, "Full non-streaming AI response (JSON path)");

                    // Save assistant message and capture ID for post-processing
                    let assistant_message_id = if response_content.is_empty() {
                        warn!(session_id = %session_id, "Skipping save for empty AI content (JSON path)");
                        None
                    } else {
                        match chat::message_handling::save_message(
                            chat::message_handling::SaveMessageParams {
                                state: state_arc.clone(),
                                session_id,
                                user_id: user_id_value,
                                message_type_enum: MessageRole::Assistant,
                                content: &response_content,
                                role_str: Some("assistant".to_string()),
                                parts: Some(json!([{"text": response_content.clone()}])),
                                attachments: None,
                                user_dek_secret_box: Some(session_dek_arc.clone()),
                                model_name: model_to_use.clone(),
                                raw_prompt_debug: None, // Non-stream AI responses don't include raw prompt debug
                                status: crate::models::chats::MessageStatus::Completed,
                                error_message: None,
                            },
                        )
                        .await
                        {
                            Ok(saved_message) => {
                                debug!(session_id = %session_id, message_id = %saved_message.id, "Successfully saved AI message via chat_service (JSON path)");
                                
                                // Update pre-processing analysis with assistant message ID if we have one
                                if let Some(analysis_id) = pre_processing_analysis_id {
                                    debug!(%session_id, %analysis_id, assistant_message_id = %saved_message.id, 
                                           "Updating pre-processing analysis with assistant message ID");
                                    
                                    let conn = state_arc.pool.get().await;
                                    if let Ok(conn) = conn {
                                        let assistant_msg_id = saved_message.id;
                                        let update_result = conn.interact(move |conn| {
                                            AgentContextAnalysis::update_assistant_message_id(
                                                conn,
                                                analysis_id,
                                                assistant_msg_id,
                                            )
                                        })
                                        .await;
                                        
                                        match update_result {
                                            Ok(Ok(())) => {
                                                debug!(%session_id, "Successfully updated pre-processing analysis with assistant message ID");
                                            }
                                            Ok(Err(e)) => {
                                                warn!(%session_id, error = ?e, "Failed to update analysis with assistant message ID");
                                            }
                                            Err(e) => {
                                                warn!(%session_id, error = ?e, "Failed to interact with DB for analysis update");
                                            }
                                        }
                                    }
                                }
                                
                                Some(saved_message.id)
                            }
                            Err(e) => {
                                error!(error = ?e, session_id = %session_id, "Error saving AI message via chat_service (JSON path)");
                                None
                            }
                        }
                    };

                    // Run post-processing agent if enabled AND we have a valid assistant message ID
                    if let Some(mode) = &agent_mode {
                        if mode == "post_processing" {
                            // Only run post-processing if we successfully saved the assistant message
                            if let Some(assistant_msg_id) = assistant_message_id {
                                info!(%session_id, "Post-processing agent mode enabled (non-streaming) - will run in background");
                                
                                // Clone necessary data for the background task
                                let session_id_clone = session_id;
                                let user_id_clone = user_id_value;
                                let player_chronicle_id_clone = player_chronicle_id;  // Clone chronicle_id for scoped search
                                let state_clone = state_arc.clone();
                                let session_dek_clone = session_dek_arc.clone();
                                let recent_history_clone = gen_ai_recent_history_for_agent.clone();
                                let current_user_text = current_user_content_text.clone();
                                let assistant_response = response_content.clone();
                            
                            tokio::spawn(async move {
                                info!(session_id = %session_id_clone, "Starting post-processing agent in background (non-streaming)");
                                
                                // Create the agent with dependencies
                                let search_tool = Arc::new(SearchKnowledgeBaseTool::new(
                                    state_clone.qdrant_service.clone(),
                                    state_clone.embedding_client.clone(),
                                    state_clone.clone(),
                                ));
                                
                                let chronicle_service = Arc::new(ChronicleService::new(
                                    state_clone.pool.clone(),
                                ));
                                
                                let agent = ContextEnrichmentAgent::new(
                                    state_clone.clone(),
                                    search_tool,
                                    chronicle_service,
                                );
                                
                                // Prepare messages for the agent
                                let recent_messages: Vec<(String, String)> = recent_history_clone
                                    .iter()
                                    .take(10)
                                    .map(|msg| {
                                        let role = match msg.role {
                                            ChatRole::User => "User".to_string(),
                                            ChatRole::Assistant => "Assistant".to_string(),
                                            _ => "System".to_string(),
                                        };
                                        let content = match &msg.content {
                                MessageContent::Text(text) => text.clone(),
                                _ => String::new(),
                            };
                                        (role, content)
                                    })
                                    .collect();
                                
                                // Add the current exchange (including assistant response)
                                let mut messages_for_agent = recent_messages;
                                messages_for_agent.push(("User".to_string(), current_user_text));
                                messages_for_agent.push(("Assistant".to_string(), assistant_response));
                                
                                // Run the agent with the assistant message ID
                                match agent.enrich_context(
                                    session_id_clone,
                                    user_id_clone,
                                    player_chronicle_id_clone,  // Pass chronicle_id for scoped search
                                    &messages_for_agent,
                                    EnrichmentMode::PostProcessing,
                                    session_dek_clone.expose_secret(),
                                    assistant_msg_id,  // Pass the assistant message ID for association
                                ).await {
                                    Ok(result) => {
                                        info!(
                                            session_id = %session_id_clone, 
                                            tokens_used = result.total_tokens_used,
                                            execution_time_ms = result.execution_time_ms,
                                            "Post-processing agent completed successfully (non-streaming)"
                                        );
                                    }
                                    Err(e) => {
                                        warn!(
                                            session_id = %session_id_clone, 
                                            error = ?e, 
                                            "Post-processing agent failed (non-streaming)"
                                        );
                                    }
                                }
                            });
                            } else {
                                warn!(%session_id, "Skipping post-processing agent - no assistant message ID available");
                            }
                        }
                    }

                    let response_payload = json!({
                        "message_id": Uuid::new_v4(), // This is a response ID, not related to DB message ID
                        "content": response_content
                    });
                    trace!(%session_id, response_payload = ?response_payload, "Sending non-streaming JSON response");

                    Ok(Json(response_payload).into_response())
                }
                Err(e) => {
                    let error_str = e.to_string();
                    error!(error = ?e, %session_id, "AI generation failed for non-streaming request (JSON path)");

                    // Provide more specific error messages for common issues
                    if error_str.contains("PropertyNotFound(\"/content/parts\")")
                        || error_str.contains("PropertyNotFound(\"/candidates\")")
                    {
                        Err(AppError::AiServiceError("AI safety filters blocked the request. Please try rephrasing your message.".to_string()))
                    } else if error_str.contains("Failed to parse stream data")
                        || error_str.contains("trailing characters")
                    {
                        Err(AppError::AiServiceError(
                            "AI service returned malformed data. Please try again.".to_string(),
                        ))
                    } else if error_str.contains("safety") || error_str.contains("blocked") {
                        Err(AppError::AiServiceError(
                            "Request was blocked by AI safety filters. Please try again."
                                .to_string(),
                        ))
                    } else if error_str.contains("quota") || error_str.contains("rate limit") {
                        Err(AppError::AiServiceError(
                            "AI service is temporarily busy. Please wait and try again."
                                .to_string(),
                        ))
                    } else {
                        Err(AppError::AiServiceError(format!(
                            "AI generation failed: {e}"
                        )))
                    }
                }
            }
        }
        _ => {
            // Fallback to SSE if Accept header is not recognized or empty
            info!(%session_id, "Accept header '{}' not recognized or empty, defaulting to SSE.", accept_header);

            // This is largely a copy of the SSE path above.
            let dek_for_fallback_stream_service = session_dek_arc.clone(); // MODIFIED: Use Arc clone
            match chat::generation::stream_ai_response_and_save_message_with_retry(
                chat::generation::StreamAiParams {
                    state: state_arc.clone(),
                    session_id,
                    user_id: user_id_value,
                    incoming_genai_messages: final_genai_message_list.clone(),
                    system_prompt: Some(final_system_prompt_str.clone()),
                    temperature: gen_temperature,
                    max_output_tokens: gen_max_output_tokens,
                    frequency_penalty: gen_frequency_penalty,
                    presence_penalty: gen_presence_penalty,
                    top_k: gen_top_k,
                    top_p: gen_top_p,
                    stop_sequences: None,
                    seed: gen_seed,
                    model_name: model_to_use.clone(),
                    model_provider: gen_model_provider_from_service,
                    gemini_thinking_budget: gen_gemini_thinking_budget,
                    gemini_enable_code_execution: gen_gemini_enable_code_execution,
                    request_thinking,
                    user_dek: Some(dek_for_fallback_stream_service),
                    character_name: Some(character_db_model.name.clone()),
                    player_chronicle_id,
                },
            )
            .await
            {
                Ok(service_stream) => {
                    debug!(%session_id, "Successfully obtained stream from chat_service (fallback SSE)");
                    let final_stream = async_stream::stream! {
                        let mut content_produced = false;
                        let mut error_from_service_stream = false;
                        let mut assistant_message_id: Option<Uuid> = None;
                        futures::pin_mut!(service_stream);

                        while let Some(event_result) = service_stream.next().await {
                            match event_result {
                                Ok(scribe_event) => {
                                    let axum_sse_event = match scribe_event {
                                        ScribeSseEvent::Content(data) => {
                                            if !data.is_empty() { content_produced = true; }
                                            Event::default().event("content").data(data)
                                        }
                                        ScribeSseEvent::Thinking(data) => {
                                            Event::default().event("thinking").data(data)
                                        }
                                        ScribeSseEvent::Error(data) => {
                                            error_from_service_stream = true;
                                            Event::default().event("error").data(data)
                                        }
                                        ScribeSseEvent::TokenUsage { prompt_tokens, completion_tokens, model_name } => {
                                            let token_data = serde_json::json!({
                                                "prompt_tokens": prompt_tokens,
                                                "completion_tokens": completion_tokens,
                                                "model_name": model_name
                                            });
                                            Event::default().event("token_usage").data(token_data.to_string())
                                        }
                                        ScribeSseEvent::MessageSaved { message_id } => {
                                            // Capture the assistant message ID for post-processing
                                            if let Ok(msg_uuid) = Uuid::parse_str(&message_id) {
                                                assistant_message_id = Some(msg_uuid);
                                            }
                                            let message_data = serde_json::json!({
                                                "message_id": message_id
                                            });
                                            Event::default().event("message_saved").data(message_data.to_string())
                                        }
                                    };
                                    yield Ok(axum_sse_event);
                                }
                                Err(e) => {
                                    error_from_service_stream = true;
                                    yield Err(e);
                                }
                            }
                        }
                        if error_from_service_stream {
                             debug!(%session_id, "Service stream ended with error (fallback). Not sending additional [DONE] event.");
                        } else if content_produced {
                             debug!(%session_id, "Service stream ended (fallback), sending [DONE] event.");
                             yield Ok(Event::default().event("done").data("[DONE]"));
                        } else {
                             debug!(%session_id, "Service stream ended without content (fallback), sending [DONE_EMPTY] event.");
                             yield Ok(Event::default().event("done").data("[DONE_EMPTY]"));
                        }
                    };
                    Ok(Sse::new(Box::pin(final_stream))
                        .keep_alive(
                            KeepAlive::new()
                                .interval(std::time::Duration::from_secs(1))
                                .text("keep-alive")
                        )
                        .into_response())
                }
                Err(e) => {
                    error!(error = ?e, %session_id, "Error calling chat_service (fallback SSE)");
                    let error_stream = async_stream::stream! {
                        let error_msg = format!("Service error (fallback): Failed to initiate AI processing - {e}");
                        yield Ok::<_, AppError>(Event::default().event("error").data(error_msg));
                    };
                    Ok(Sse::new(Box::pin(error_stream))
                        .keep_alive(KeepAlive::default())
                        .into_response())
                }
            }
        }
    }
}

pub fn chat_routes(state: AppState) -> Router<AppState> {
    info!("Entering chat_routes");
    Router::new()
        .route("/create_session", post(create_chat_session_handler))
        .route(
            "/:session_id/suggested-actions",
            post(generate_suggested_actions),
        )
        .route("/:session_id/expand", post(expand_text_handler))
        .route("/:session_id/impersonate", post(impersonate_handler))
        .route("/:session_id/agent-analysis", get(get_agent_analysis_handler))
        .route("/count-tokens", post(count_tokens_handler))
        .route("/ping", get(ping_handler))
        .route(
            "/:chat_id/settings",
            get(get_chat_settings_handler).put(update_chat_settings_handler),
        )
        .route("/:session_id_str/generate", post(generate_chat_response))
        .route(
            "/overrides/:session_id",
            post(create_or_update_chat_character_override_handler).with_state(state.clone()),
        )
        // Message variant routes
        .route(
            "/messages/:message_id/variants",
            get(get_message_variants_handler).post(create_message_variant_handler),
        )
        .route(
            "/messages/:message_id/variants/:variant_index",
            get(get_message_variant_by_index_handler).delete(delete_message_variant_handler),
        )
        .route(
            "/messages/:message_id/variants/count",
            get(get_variant_count_handler),
        )
        .with_state(state)
}

/// Count tokens for a given text using the hybrid token counter
#[instrument(skip_all)]
pub async fn count_tokens_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    Json(payload): Json<TokenCountRequest>,
) -> Result<Json<TokenCountResponse>, AppError> {
    // Ensure user is authenticated
    let _user = auth_session.user.as_ref().ok_or_else(|| {
        AppError::Unauthorized("User not found in session".to_string())
    })?;

    // Validate the payload
    payload.validate().map_err(|e| {
        AppError::BadRequest(format!("Invalid token count request: {}", e))
    })?;

    let model_to_use = payload.model.unwrap_or_else(|| state.config.token_counter_default_model.clone());

    // Determine counting mode based on request preference
    let counting_mode = if payload.use_api_counting {
        CountingMode::HybridPreferApi
    } else {
        CountingMode::HybridPreferLocal
    };

    // Use the hybrid token counter from app state
    let token_estimate = state
        .token_counter
        .count_tokens(&payload.text, counting_mode, Some(&model_to_use))
        .await
        .map_err(|e| {
            error!("Token counting failed: {}", e);
            AppError::AiServiceError(format!("Token counting failed: {}", e))
        })?;

    // Determine counting method used
    let counting_method = if payload.use_api_counting {
        "api_preferred".to_string()
    } else {
        "local_preferred".to_string()
    };

    let response = TokenCountResponse {
        total: token_estimate.total,
        text: token_estimate.text,
        images: token_estimate.images,
        video: token_estimate.video,
        audio: token_estimate.audio,
        is_estimate: token_estimate.is_estimate,
        model_used: model_to_use,
        counting_method,
    };

    info!(
        total_tokens = token_estimate.total,
        text_tokens = token_estimate.text,
        model = %response.model_used,
        method = %response.counting_method,
        "Token count completed"
    );

    Ok(Json(response))
}

/// Get agent context analysis for a chat session
#[instrument(skip_all)]
pub async fn get_agent_analysis_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    session_dek: SessionDek,
    Path(session_id): Path<Uuid>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Vec<AgentAnalysisResponse>>, AppError> {
    // Ensure user is authenticated
    let user = auth_session.user.as_ref().ok_or_else(|| {
        AppError::Unauthorized("User not found in session".to_string())
    })?;
    let user_id = user.id;

    // Verify the chat session belongs to the user
    let conn = state.pool.get().await?;
    let session_exists = conn.interact(move |conn| {
        use crate::schema::chat_sessions;
        use diesel::prelude::*;
        
        chat_sessions::table
            .filter(chat_sessions::id.eq(session_id))
            .filter(chat_sessions::user_id.eq(user_id))
            .select(Chat::as_select())
            .first::<Chat>(conn)
            .optional()
    }).await
    .map_err(|e| AppError::DbInteractError(format!("Database interaction failed: {}", e)))?
    .map_err(|e| AppError::DatabaseQueryError(format!("Failed to verify session: {}", e)))?;

    if session_exists.is_none() {
        return Err(AppError::NotFound("Chat session not found".to_string()));
    }

    // Parse analysis type from query params if provided
    let analysis_type_filter = params.get("analysis_type")
        .and_then(|s| s.parse::<AnalysisType>().ok())
        .map(|at| at.to_string());
    
    // Parse message_id from query params if provided
    let message_id_filter = params.get("message_id")
        .and_then(|s| s.parse::<Uuid>().ok());

    // Get all analysis records for the session
    let conn = state.pool.get().await?;
    let analysis_records = conn.interact(move |conn| {
        use crate::schema::agent_context_analysis::dsl::*;
        use diesel::prelude::*;
        
        let mut query = agent_context_analysis
            .filter(chat_session_id.eq(session_id))
            .filter(superseded_at.is_null()) // Only get active (non-superseded) analyses
            .into_boxed();

        if let Some(ref analysis_type_str) = analysis_type_filter {
            query = query.filter(analysis_type.eq(analysis_type_str));
        }
        
        // Filter by message_id if provided - check both message_id and assistant_message_id
        if let Some(msg_id) = message_id_filter {
            // Use OR condition to find analyses linked to either the user message or assistant message
            query = query.filter(
                message_id.eq(msg_id).or(assistant_message_id.eq(msg_id))
            );
        }

        query
            .order(created_at.desc())
            .load::<AgentContextAnalysis>(conn)
    }).await
    .map_err(|e| AppError::DbInteractError(format!("Database interaction failed: {}", e)))?
    .map_err(|e| AppError::DatabaseQueryError(format!("Failed to fetch agent analysis: {}", e)))?;

    // Convert to response DTOs with decrypted content
    let mut responses = Vec::new();
    for analysis in analysis_records {
        let decrypted_reasoning = analysis.get_decrypted_reasoning(&session_dek.0).ok();
        let decrypted_execution_log = analysis.get_decrypted_execution_log(&session_dek.0).ok();
        let decrypted_context = analysis.get_decrypted_context(&session_dek.0).ok();
        let decrypted_summary = analysis.get_decrypted_summary(&session_dek.0).ok();

        responses.push(AgentAnalysisResponse {
            id: analysis.id,
            chat_session_id: analysis.chat_session_id,
            analysis_type: analysis.analysis_type,
            agent_reasoning: decrypted_reasoning,
            planned_searches: analysis.planned_searches,
            execution_log: decrypted_execution_log,
            retrieved_context: decrypted_context,
            analysis_summary: decrypted_summary,
            total_tokens_used: analysis.total_tokens_used,
            execution_time_ms: analysis.execution_time_ms,
            model_used: analysis.model_used,
            created_at: analysis.created_at,
            updated_at: analysis.updated_at,
            message_id: Some(analysis.message_id), // Always present in DB, optional in API response
            status: analysis.status,
            error_message: analysis.error_message,
            retry_count: analysis.retry_count,
        });
    }

    info!(
        session_id = %session_id,
        user_id = %user_id,
        count = responses.len(),
        "Retrieved agent analysis records"
    );

    Ok(Json(responses))
}

async fn ping_handler() -> &'static str {
    "pong_from_chat_routes"
}

// Message variant handler functions

/// Get all variants for a message
async fn get_message_variants_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    session_dek: SessionDek,
    Path(message_id): Path<Uuid>,
) -> Result<Json<Vec<MessageVariantDto>>, AppError> {
    let user = auth_session
        .user
        .as_ref()
        .ok_or_else(|| AppError::Unauthorized("User not found in session".to_string()))?;

    let variants = crate::services::chat::message_variants::get_message_variants(
        Arc::new(state),
        message_id,
        user.id,
        &session_dek.0,
    )
    .await?;

    Ok(Json(variants))
}

/// Create a new variant for a message
async fn create_message_variant_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    session_dek: SessionDek,
    Path(message_id): Path<Uuid>,
    Json(payload): Json<CreateMessageVariantPayload>,
) -> Result<(StatusCode, Json<MessageVariantDto>), AppError> {
    let user = auth_session
        .user
        .as_ref()
        .ok_or_else(|| AppError::Unauthorized("User not found in session".to_string()))?;

    let variant = crate::services::chat::message_variants::create_message_variant(
        Arc::new(state),
        message_id,
        &payload.content,
        user.id,
        &session_dek.0,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(variant)))
}

/// Get a specific variant by index
async fn get_message_variant_by_index_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    session_dek: SessionDek,
    Path((message_id, variant_index)): Path<(Uuid, i32)>,
) -> Result<Json<Option<MessageVariantDto>>, AppError> {
    let user = auth_session
        .user
        .as_ref()
        .ok_or_else(|| AppError::Unauthorized("User not found in session".to_string()))?;

    let variant = crate::services::chat::message_variants::get_message_variant_by_index(
        Arc::new(state),
        message_id,
        variant_index,
        user.id,
        &session_dek.0,
    )
    .await?;

    Ok(Json(variant))
}

/// Delete a message variant
async fn delete_message_variant_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    Path((message_id, variant_index)): Path<(Uuid, i32)>,
) -> Result<Json<bool>, AppError> {
    let user = auth_session
        .user
        .as_ref()
        .ok_or_else(|| AppError::Unauthorized("User not found in session".to_string()))?;

    let deleted = crate::services::chat::message_variants::delete_message_variant(
        Arc::new(state),
        message_id,
        variant_index,
        user.id,
    )
    .await?;

    Ok(Json(deleted))
}

/// Get variant count for a message
async fn get_variant_count_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    Path(message_id): Path<Uuid>,
) -> Result<Json<i64>, AppError> {
    let user = auth_session
        .user
        .as_ref()
        .ok_or_else(|| AppError::Unauthorized("User not found in session".to_string()))?;

    let count = crate::services::chat::message_variants::get_variant_count(
        Arc::new(state),
        message_id,
        user.id,
    )
    .await?;

    Ok(Json(count))
}

#[instrument(skip(state, auth_session, _payload), fields(session_id = %session_id))] // _payload as it's not used
pub async fn generate_suggested_actions(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Path(session_id): Path<Uuid>,
    session_dek: SessionDek,
    Json(_payload): Json<SuggestedActionsRequest>, // _payload as it's an empty struct now
) -> Result<Json<SuggestedActionsResponse>, AppError> {
    info!(
        "Entering generate_suggested_actions for session_id: {}",
        session_id
    );

    let state_arc = Arc::new(state);
    let session_dek_arc = Arc::new(session_dek.0);

    let user = auth_session.user.ok_or_else(|| {
        error!(
            "User not found in session for suggested actions (session_id: {})",
            session_id
        );
        AppError::Unauthorized("User not found in session".to_string())
    })?;
    let user_id = user.id;
    debug!(user_id = %user_id, session_id = %session_id, "User and session_id extracted");

    // Fetch chat session owner ID for authorization check
    let chat_session_owner_id = state_arc
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .select(chat_sessions::user_id)
                .first::<Uuid>(conn)
        })
        .await
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!(
                "Interact dispatch error checking session owner: {e}"
            ))
        })?
        .map_err(|e_db| match e_db {
            diesel::result::Error::NotFound => {
                AppError::NotFound(format!("Chat session {session_id} not found."))
            }
            _ => AppError::DatabaseQueryError(format!(
                "Failed to query chat session owner for {session_id}: {e_db}"
            )),
        })?;

    if chat_session_owner_id != user_id {
        error!(%session_id, expected_owner = %user_id, actual_owner = %chat_session_owner_id, "User forbidden from accessing chat session for suggested actions.");
        return Err(AppError::Forbidden(
            "Access denied to chat session".to_string(),
        ));
    }
    debug!(%session_id, "User authorized for chat session");

    // Placeholder content for get_session_data_for_generation as we are not saving a new user message here.
    let current_user_content_for_service_call = String::new(); // Or a system message like "System: Requesting suggestions."

    let (
        managed_db_history,
        system_prompt_from_service,
        _active_lorebook_ids_for_search,
        session_character_id,
        raw_character_system_prompt,
        gen_temperature,        // We might use a fixed temp for suggestions
        _gen_max_output_tokens, // We use fixed max_tokens for suggestions
        _gen_frequency_penalty,
        _gen_presence_penalty,
        _gen_top_k,
        _gen_top_p,
        _gen_seed,
        _gen_model_name_from_service, // We use a fixed model for suggestions
        _gen_model_provider_from_service, // Model provider field
        _gen_gemini_thinking_budget,
        _gen_gemini_enable_code_execution,
        _user_message_struct_to_save, // Not saving a user message here
        _actual_recent_history_tokens_from_service,
        _rag_context_items_from_service, // RAG not typically used for suggestions
        _hist_management_strategy,
        _hist_management_limit,
        user_persona_name, // NEW - for template substitution
        _player_chronicle_id, // We don't use this for suggestions
        _agent_mode, // Agent mode - not used for suggestions
    ) = chat::generation::get_session_data_for_generation(
        state_arc.clone(),
        user_id,
        session_id,
        current_user_content_for_service_call,
        Some(session_dek_arc.clone()),
        None, // No frontend history for suggestions - use DB history
    )
    .await?;

    debug!(%session_id, "Fetched session data for suggestions. History items: {}", managed_db_history.len());

    // Fetch Character model from DB (only for character-based chats)
    let char_id = session_character_id.ok_or_else(|| {
        AppError::BadRequest("Suggested actions not supported for non-character chat modes".to_string())
    })?;
    let character_db_model = state_arc
        .pool
        .get()
        .await?
        .interact(move |conn| {
            app_schema::characters::table
                .filter(app_schema::characters::id.eq(char_id))
                .filter(app_schema::characters::user_id.eq(user_id)) // Ensure user owns character
                .select(Character::as_select())
                .first::<Character>(conn)
        })
        .await??; // Double question mark for interact and then DB result

    let character_metadata_for_prompt_builder = CharacterMetadata {
        id: character_db_model.id,
        user_id: character_db_model.user_id,
        name: character_db_model.name.clone(),
        description: character_db_model.description.clone(),
        description_nonce: character_db_model.description_nonce.clone(),
        personality: character_db_model.personality.clone(),
        personality_nonce: character_db_model.personality_nonce.clone(),
        scenario: character_db_model.scenario.clone(),
        scenario_nonce: character_db_model.scenario_nonce.clone(),
        mes_example: character_db_model.mes_example.clone(),
        mes_example_nonce: character_db_model.mes_example_nonce.clone(),
        creator_comment: character_db_model.creator_comment.clone(),
        creator_comment_nonce: character_db_model.creator_comment_nonce.clone(),
        first_mes: character_db_model.first_mes.clone(),
        created_at: character_db_model.created_at,
        updated_at: character_db_model.updated_at,
    };

    // Construct context for the suggestion prompt
    let mut suggestion_context_parts: Vec<String> = Vec::new();

    let decrypted_first_mes_str = match (
        &character_db_model.first_mes,
        &character_db_model.first_mes_nonce,
    ) {
        (Some(fm_bytes), Some(fm_nonce_bytes))
            if !fm_bytes.is_empty() && !fm_nonce_bytes.is_empty() =>
        {
            crate::crypto::decrypt_gcm(fm_bytes, fm_nonce_bytes, &session_dek_arc).map_or_else(
                |e| {
                    error!("Failed to decrypt first_mes: {}. Using empty string.", e);
                    String::new()
                },
                |decrypted_secret_vec| {
                    String::from_utf8(
                    decrypted_secret_vec.expose_secret().clone(),
                )
                .unwrap_or_else(|e| {
                    error!(
                        "Failed to convert decrypted first_mes to UTF-8: {}. Using empty string.",
                        e
                    );
                    String::new()
                })
                },
            )
        }
        (Some(fm_bytes), None) if !fm_bytes.is_empty() => {
            // No nonce, assume plaintext (less secure, but might be intended for some characters)
            String::from_utf8_lossy(fm_bytes).into_owned()
        }
        _ => String::new(), // No first_mes or empty
    };

    if !decrypted_first_mes_str.is_empty() {
        suggestion_context_parts.push(format!(
            "Character Introduction: \"{decrypted_first_mes_str}\""
        ));
    }

    // Use last 2-3 messages from history for context
    let history_for_prompt = managed_db_history.iter().rev().take(3).rev(); // Take last 3, then reverse to chronological
    for msg in history_for_prompt {
        // managed_db_history content is already decrypted by get_session_data_for_generation
        let content_str = String::from_utf8_lossy(&msg.content).into_owned();
        match msg.message_type {
            MessageRole::User => {
                suggestion_context_parts.push(format!("User: \"{content_str}\""));
            }
            MessageRole::Assistant => {
                suggestion_context_parts.push(format!("Assistant: \"{content_str}\""));
            }
            MessageRole::System => {} // Usually don't include system messages directly in this context
        }
    }

    let context_str_for_suggestions = suggestion_context_parts.join("\n");
    let prompt_text_for_llm_suggestions = format!(
        "Based on this conversation snippet:\n\n{context_str_for_suggestions}\n\nWhat are 2-4 concise follow-up actions or questions the user might say next? These should be suitable for buttons."
    );
    trace!(%session_id, "Constructed prompt for LLM suggested actions: {}", prompt_text_for_llm_suggestions);

    let suggestion_request_genai_message = GenAiChatMessage {
        role: ChatRole::User, // We are "asking" the LLM on behalf of the system/user for suggestions
        content: MessageContent::Text(prompt_text_for_llm_suggestions),
        options: None,
    };

    // Convert DbChatMessage history (already decrypted) to GenAiChatMessage history for prompt builder
    // This history is what *precedes* our special suggestion_request_genai_message
    let mut gen_ai_processed_history: Vec<GenAiChatMessage> = Vec::new();
    for db_msg in managed_db_history {
        // This is the full relevant history
        let content_str = String::from_utf8_lossy(&db_msg.content).into_owned();
        let chat_role = match db_msg.message_type {
            MessageRole::User => ChatRole::User,
            MessageRole::Assistant => ChatRole::Assistant,
            MessageRole::System => ChatRole::System,
        };
        gen_ai_processed_history.push(GenAiChatMessage {
            role: chat_role,
            content: MessageContent::from_text(content_str),
            options: None,
        });
    }

    // Use Flash for suggestions - it's fast and cheap for simple action generation
    let model_for_suggestions = "gemini-2.5-flash".to_string();

    let (final_system_prompt_for_suggestions, final_messages_for_suggestions_llm) =
        match prompt_builder::build_final_llm_prompt(prompt_builder::PromptBuildParams {
            config: state_arc.config.clone(),
            token_counter: state_arc.token_counter.clone(),
            recent_history: gen_ai_processed_history, // The actual chat history
            rag_items: Vec::new(),                    // No RAG for suggestions
            system_prompt_base: system_prompt_from_service,
            raw_character_system_prompt,
            character_metadata: Some(&character_metadata_for_prompt_builder),
            current_user_message: suggestion_request_genai_message, // Our special message asking for suggestions
            model_name: model_for_suggestions.clone(),
            user_dek: Some(&*session_dek_arc), // Add DEK for character description decryption
            user_persona_name,                 // Pass user persona name for template substitution
            agent_context: None,                // No agent context for suggestions
        })
        .await
        {
            Ok(prompt_data) => prompt_data,
            Err(e) => {
                error!(%session_id, error = ?e, "Failed to build final LLM prompt for suggestions");
                return Err(e);
            }
        };

    let chat_request = ChatRequest::new(final_messages_for_suggestions_llm)
        .with_system(final_system_prompt_for_suggestions);

    let suggested_actions_schema_value = json!({
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "A concise suggested action or question."
                }
            },
            "required": ["action"]
        }
    });

    let chat_options = ChatOptions::default()
        .with_temperature(
            gen_temperature
                .and_then(|t| t.to_f32())
                .unwrap_or(0.7)
                .into(),
        ) // Use session temp or default
        .with_max_tokens(1000) // Increased max tokens for suggestions
        .with_response_format(ChatResponseFormat::JsonSchemaSpec(JsonSchemaSpec {
            schema: suggested_actions_schema_value.clone(),
        }));

    trace!(%session_id, model = %model_for_suggestions, ?chat_request, ?chat_options, "Sending request to Gemini for suggested actions");

    let gemini_response = state_arc
        .ai_client
        .exec_chat(&model_for_suggestions, chat_request, Some(chat_options))
        .await
        .map_err(|e| {
            let error_str = e.to_string();
            error!(%session_id, "Gemini API error for suggested actions: {:?}", e);
            // Provide more specific error messages for common issues
            if error_str.contains("PropertyNotFound(\"/content/parts\")") {
                AppError::AiServiceError("AI safety filters blocked the suggestion request. Please try again with different conversation context.".to_string())
            } else if error_str.contains("Failed to parse stream data") || error_str.contains("trailing characters") {
                AppError::AiServiceError("AI service returned malformed data. Please try again.".to_string())
            } else if error_str.contains("safety") || error_str.contains("blocked") {
                AppError::AiServiceError("Request was blocked by AI safety filters. Please try again.".to_string())
            } else if error_str.contains("quota") || error_str.contains("rate limit") {
                AppError::AiServiceError("AI service is temporarily busy. Please wait and try again.".to_string())
            } else {
                AppError::AiServiceError(format!("Gemini API error: {e}"))
            }
        })?;

    debug!(%session_id, "Received response from Gemini for suggested actions");
    trace!(%session_id, ?gemini_response, "Full Gemini response object for suggested actions");

    let response_text = if let Some(text) = gemini_response.first_content_text_as_str() {
        text.to_string()
    } else {
        error!(%session_id, "Gemini response for suggested actions (JsonSchemaSpec) did not contain text content or was empty. Full response: {:?}", gemini_response);
        return Err(AppError::AiServiceError(
            "AI safety filters blocked the suggestion request. Please try again with different conversation context.".to_string()
        ));
    };
    debug!(%session_id, "Gemini response text (JsonSchemaSpec) for suggested actions: {}", response_text);

    // Parse the JSON response text as an array of suggested actions
    let suggestions: Vec<SuggestedActionItem> =
        serde_json::from_str(&response_text).map_err(|e| {
            error!(
                %session_id,
                "Failed to parse Gemini JSON response text (JsonSchemaSpec) into suggested actions: {:?}. Response text: {}",
                e,
                response_text
            );
            AppError::InternalServerErrorGeneric("Failed to parse structured response from AI (JsonSchemaSpec)".to_string())
        })?;

    info!(%session_id, "Successfully generated {} suggested actions via JsonSchemaSpec (parsed from text)", suggestions.len());

    // Extract token usage from Gemini response
    let token_usage = Some(crate::models::chats::SuggestedActionsTokenUsage {
        input_tokens: gemini_response.usage.prompt_tokens.unwrap_or(0) as usize,
        output_tokens: gemini_response.usage.completion_tokens.unwrap_or(0) as usize,
        total_tokens: gemini_response.usage.total_tokens.unwrap_or(0) as usize,
    });

    if let Some(ref token_info) = token_usage {
        info!(
            %session_id,
            input_tokens = token_info.input_tokens,
            output_tokens = token_info.output_tokens,
            total_tokens = token_info.total_tokens,
            "Token usage for suggested actions"
        );
    } else {
        warn!(%session_id, "No token usage information available in Gemini response for suggested actions");
    }

    Ok(Json(SuggestedActionsResponse { 
        suggestions,
        token_usage,
    }))
}

#[instrument(skip_all, err)]
pub async fn get_chat_session_with_dek(
    State(state): State<AppState>,
    Path(chat_id): Path<Uuid>,
    auth_session: CurrentAuthSession, // Use CurrentAuthSession
) -> Result<Json<ChatSessionWithDekResponse>, AppError> {
    let pool = state.pool.clone();
    let user = auth_session.user.ok_or_else(|| {
        error!("User not found in session for chat_id: {}", chat_id);
        AppError::Unauthorized("User not found in session".to_string())
    })?;

    let chat_session_db = pool
        .get()
        .await?
        .interact(move |conn| {
            crate::schema::chat_sessions::table
                .filter(crate::schema::chat_sessions::id.eq(chat_id))
                .filter(crate::schema::chat_sessions::user_id.eq(user.id))
                .select(Chat::as_select())
                .first::<Chat>(conn)
                .optional()
        })
        .await??;

    if let Some(session_db) = chat_session_db {
        let dek_present = user.dek.is_some();

        // Decrypt title if possible
        let decrypted_title = match (
            session_db.title_ciphertext.as_ref(),
            session_db.title_nonce.as_ref(),
            user.dek.as_ref(),
        ) {
            (Some(ciphertext), Some(nonce), Some(dek_wrapped))
                if !ciphertext.is_empty() && !nonce.is_empty() =>
            {
                crate::crypto::decrypt_gcm(ciphertext, nonce, &dek_wrapped.0).map_or_else(
                    |_| Some("[Decryption Failed]".to_string()),
                    |plaintext_secret| {
                        String::from_utf8(plaintext_secret.expose_secret().clone())
                            .map_or_else(|_| Some("[Invalid UTF-8]".to_string()), Some)
                    },
                )
            }
            _ => None,
        };

        Ok(Json(ChatSessionWithDekResponse {
            id: session_db.id,
            user_id: session_db.user_id,
            character_id: session_db.character_id,
            title: decrypted_title,
            dek_present,
        }))
    } else {
        Err(AppError::NotFound("Chat session not found".to_string()))
    }
}

#[instrument(skip_all, fields(user_id = field::Empty, chat_session_id = %session_id, field_name = %payload.field_name))]
pub async fn create_or_update_chat_character_override_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    session_dek: SessionDek,
    Path(session_id): Path<Uuid>,
    Json(payload): Json<CharacterOverrideDto>,
) -> Result<impl IntoResponse, AppError> {
    info!("Attempting to create or update chat character override via handler");
    payload.validate()?; // Validate DTO

    let user = auth_session.user.ok_or_else(|| {
        error!("User not found in session during override creation/update");
        AppError::Unauthorized("User not found in session".to_string())
    })?;
    let user_id = user.id;
    tracing::Span::current().record("user_id", tracing::field::display(user_id));

    // 1. Verify ownership of the chat_session and get original_character_id
    let chat_session_details = state
        .pool
        .get()
        .await?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .select((chat_sessions::user_id, chat_sessions::character_id))
                .first::<(Uuid, Option<Uuid>)>(conn)
                .optional()
        })
        .await??
        .ok_or_else(|| AppError::NotFound(format!("Chat session {session_id} not found")))?;

    if chat_session_details.0 != user_id {
        error!(
            "User {} attempted to modify overrides for chat session {} owned by {}",
            user_id, session_id, chat_session_details.0
        );
        return Err(AppError::Forbidden(
            "Access denied to chat session override".to_string(),
        ));
    }
    let original_character_id = chat_session_details.1.ok_or_else(|| {
        AppError::BadRequest("Cannot create character overrides for non-character chat sessions".to_string())
    })?;

    // 2. Call the ChatOverrideService to handle the logic
    let upserted_override: ChatCharacterOverride = state
        .chat_override_service // Use the service from AppState
        .create_or_update_chat_override(
            session_id,
            original_character_id,
            user_id,            // Pass user_id for logging/future checks in service
            payload.field_name, // field_name is already a String
            payload.value,      // value is already a String
            &session_dek,
        )
        .await?;

    info!(override_id = %upserted_override.id, "Chat character override created/updated successfully via handler calling service");

    Ok(Json(upserted_override))
}

// ============================================================================
// Text Expansion Handler
// ============================================================================

#[instrument(skip(state, auth_session, _session_dek), fields(user_id, session_id))]
pub async fn expand_text_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    Path(session_id): Path<Uuid>,
    _session_dek: SessionDek,
    Json(payload): Json<ExpandTextRequest>,
) -> Result<Json<ExpandTextResponse>, AppError> {
    info!(
        "Entering expand_text_handler for session_id: {}",
        session_id
    );

    // Validate the payload
    payload.validate().map_err(|e| {
        warn!("Validation failed for expand text request: {}", e);
        AppError::BadRequest(format!("Invalid request: {}", e))
    })?;

    let user = auth_session.user.ok_or_else(|| {
        error!(
            "User not found in session for text expansion (session_id: {})",
            session_id
        );
        AppError::Unauthorized("User not found in session".to_string())
    })?;
    let user_id = user.id;
    tracing::Span::current().record("user_id", tracing::field::display(user_id));
    tracing::Span::current().record("session_id", tracing::field::display(session_id));

    // Verify chat session ownership
    let chat_session_owner_id = state
        .pool
        .get()
        .await?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .select(chat_sessions::user_id)
                .first::<Uuid>(conn)
                .optional()
        })
        .await??
        .ok_or_else(|| AppError::NotFound(format!("Chat session {session_id} not found")))?;

    if chat_session_owner_id != user_id {
        error!(
            "User {} attempted to expand text for chat session {} owned by {}",
            user_id, session_id, chat_session_owner_id
        );
        return Err(AppError::Forbidden(
            "Access denied to chat session".to_string(),
        ));
    }

    // Get the active persona for this chat session
    let _chat_settings = state
        .pool
        .get()
        .await?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .select(chat_sessions::active_custom_persona_id)
                .first::<Option<Uuid>>(conn)
        })
        .await??;

    // Use the full generation pipeline for text expansion - same as impersonate but with different system prompt

    // Get the existing chat messages to build proper context
    let messages_result = state
        .pool
        .get()
        .await?
        .interact(move |conn| {
            use crate::schema::chat_messages;
            chat_messages::table
                .filter(chat_messages::session_id.eq(session_id))
                .order(chat_messages::created_at.asc())
                .select(crate::models::chats::ChatMessage::as_select())
                .load(conn)
        })
        .await??;

    // Build the chat history in the format expected by the generation service
    let mut chat_history = Vec::new();

    // Decrypt and convert existing messages to API format
    for db_message in messages_result.iter() {
        let decrypted_content = if let Some(nonce) = &db_message.content_nonce {
            match crate::crypto::decrypt_gcm(&db_message.content, nonce, &_session_dek.0) {
                Ok(content) => String::from_utf8_lossy(content.expose_secret()).to_string(),
                Err(_) => continue, // Skip messages we can't decrypt
            }
        } else {
            // Fallback for unencrypted content (shouldn't happen in production)
            String::from_utf8_lossy(&db_message.content).to_string()
        };

        let api_message = crate::models::chats::ApiChatMessage {
            role: match db_message.message_type {
                MessageRole::User => "user".to_string(),
                MessageRole::Assistant => "assistant".to_string(),
                MessageRole::System => "system".to_string(),
            },
            content: decrypted_content,
        };
        chat_history.push(api_message);
    }

    // Add a special instruction for text expansion
    let expansion_instruction = crate::models::chats::ApiChatMessage {
        role: "user".to_string(),
        content: format!(
            "[EXPAND: Take this brief text and expand it into a more detailed, natural response while maintaining perfect consistency with the conversation's established tone, style, setting, and voice. Original text: '{}']",
            payload.original_text
        ),
    };
    chat_history.push(expansion_instruction);

    // Use the existing generation infrastructure
    let state_arc = Arc::new(state);
    let user_dek_arc = Arc::new(_session_dek.0);

    // Clone the state_arc for later use in deletion
    let delete_state = state_arc.clone();

    // Get session data and model configuration like the normal chat flow does
    let session_data = state_arc
        .pool
        .get()
        .await?
        .interact(move |conn| {
            use crate::schema::chat_sessions;
            chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .select((
                    chat_sessions::history_management_strategy,
                    chat_sessions::history_management_limit,
                    chat_sessions::model_name,
                    chat_sessions::model_provider,
                    chat_sessions::temperature,
                    chat_sessions::max_output_tokens,
                    chat_sessions::frequency_penalty,
                    chat_sessions::presence_penalty,
                    chat_sessions::top_k,
                    chat_sessions::top_p,
                    chat_sessions::stop_sequences,
                    chat_sessions::seed,
                    chat_sessions::active_custom_persona_id,
                ))
                .first::<(
                    String,
                    i32,
                    String,
                    Option<String>,
                    Option<bigdecimal::BigDecimal>,
                    Option<i32>,
                    Option<bigdecimal::BigDecimal>,
                    Option<bigdecimal::BigDecimal>,
                    Option<i32>,
                    Option<bigdecimal::BigDecimal>,
                    Option<Vec<Option<String>>>,
                    Option<i32>,
                    Option<Uuid>,
                )>(conn)
        })
        .await??;

    // Build the special system prompt for text expansion with full context awareness
    let mut expansion_system_prompt = "You are a text expansion assistant helping the USER (not the character) expand their brief input text. ".to_string();

    // Add persona context if available
    if let Some(persona_id) = session_data.11 {
        expansion_system_prompt.push_str(&format!(
            "The user has an active persona (ID: {}) - expand the text AS THE USER/PERSONA would write it. ", persona_id
        ));
    }

    expansion_system_prompt.push_str(
        "CRITICAL INSTRUCTIONS:
        1. You are expanding text that the USER wants to send, NOT generating a response from the character/AI
        2. Write the expanded text in the USER's voice, maintaining their persona and writing style
        3. Use ALL conversation context to maintain consistency with established tone and setting
        4. Keep the user's original meaning and intent completely intact
        5. Make the text more detailed and natural within the conversation context
        6. Write as if you ARE the user/persona, not as the character responding to them
        7. Do NOT write from the character's perspective or as a response to the user
        
        When the user asks you to expand text, take their brief input and elaborate it while writing AS THE USER."
    );

    // Convert API messages to GenAI format for the generation service
    let mut genai_messages = chat_history
        .into_iter()
        .map(|msg| GenAiChatMessage {
            role: match msg.role.as_str() {
                "user" => ChatRole::User,
                "assistant" => ChatRole::Assistant,
                "system" => ChatRole::System,
                _ => ChatRole::User,
            },
            content: MessageContent::Text(msg.content),
            options: None,
        })
        .collect::<Vec<_>>();

    // Add the user's text to be expanded as the final message
    genai_messages.push(GenAiChatMessage {
        role: ChatRole::User,
        content: MessageContent::Text(format!(
            "Please expand this text: \"{}\"",
            payload.original_text
        )),
        options: None,
    });

    // Create StreamAiParams for the generation service with full pipeline
    let stream_params = chat::generation::StreamAiParams {
        state: state_arc,
        session_id,
        user_id,
        incoming_genai_messages: genai_messages,
        system_prompt: Some(expansion_system_prompt),
        temperature: session_data.4,
        max_output_tokens: session_data.5,
        frequency_penalty: session_data.6,
        presence_penalty: session_data.7,
        top_k: session_data.8,
        top_p: session_data.9,
        stop_sequences: session_data
            .10
            .and_then(|seq| seq.into_iter().collect::<Option<Vec<String>>>()),
        seed: session_data.11,
        model_name: session_data.2,
        model_provider: session_data.3,
        gemini_thinking_budget: None,
        gemini_enable_code_execution: Some(false),
        request_thinking: false,
        user_dek: Some(user_dek_arc),
        character_name: None, // Text expansion doesn't have a character
        player_chronicle_id: None, // Text expansion doesn't involve chronicle processing
    };

    // Generate the response using the full pipeline (with RAG, persona, lorebooks, etc.)
    let mut response_stream =
        chat::generation::stream_ai_response_and_save_message(stream_params).await?;

    // Collect the response
    let mut expanded_text = String::new();

    while let Some(event_result) = response_stream.next().await {
        match event_result {
            Ok(event) => {
                match event {
                    chat::types::ScribeSseEvent::Content(content) => {
                        expanded_text.push_str(&content);
                    }
                    chat::types::ScribeSseEvent::Error(error_msg) => {
                        error!("Error in expansion stream: {}", error_msg);
                        return Err(AppError::BadGateway("Failed to expand text".to_string()));
                    }
                    chat::types::ScribeSseEvent::TokenUsage { .. } => {
                        // For expansion, we don't need to handle token usage
                    }
                    _ => {
                        // Skip other event types (thinking, etc.)
                    }
                }
            }
            Err(e) => {
                error!("Error in expansion stream: {}", e);
                return Err(AppError::BadGateway("Failed to expand text".to_string()));
            }
        }
    }

    // Delete the most recent message since we don't want it saved for expansion
    // The generation service will have just created a message, so we find and delete the most recent one
    let delete_session_id = session_id;
    let _ = delete_state
        .pool
        .get()
        .await?
        .interact(move |conn| {
            use crate::schema::chat_messages;
            // Find the most recent message for this session and delete it (it will be the AI response we just generated)
            if let Ok(recent_message) = chat_messages::table
                .filter(chat_messages::session_id.eq(delete_session_id))
                .order(chat_messages::created_at.desc())
                .select(crate::models::chats::ChatMessage::as_select())
                .first(conn)
            {
                let _ = diesel::delete(
                    chat_messages::table.filter(chat_messages::id.eq(recent_message.id)),
                )
                .execute(conn);
                debug!("Deleted expansion message with ID: {}", recent_message.id);
            }
        })
        .await;

    if expanded_text.trim().is_empty() {
        warn!("AI returned empty text expansion");
        return Err(AppError::BadGateway(
            "AI failed to generate expanded text".to_string(),
        ));
    }

    info!(
        "Text expansion completed successfully for session_id: {}",
        session_id
    );
    Ok(Json(ExpandTextResponse {
        expanded_text: expanded_text.trim().to_string(),
    }))
}

// ============================================================================
// Impersonate Handler
// ============================================================================

#[instrument(skip(state, auth_session, session_dek), fields(user_id, session_id))]
pub async fn impersonate_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    Path(session_id): Path<Uuid>,
    session_dek: SessionDek,
    Json(payload): Json<ImpersonateRequest>,
) -> Result<Json<ImpersonateResponse>, AppError> {
    info!(
        "Entering impersonate_handler for session_id: {}",
        session_id
    );

    // Validate the payload
    payload.validate().map_err(|e| {
        warn!("Validation failed for impersonate request: {}", e);
        AppError::BadRequest(format!("Invalid request: {}", e))
    })?;

    let user = auth_session.user.ok_or_else(|| {
        error!(
            "User not found in session for impersonation (session_id: {})",
            session_id
        );
        AppError::Unauthorized("User not found in session".to_string())
    })?;
    let user_id = user.id;
    tracing::Span::current().record("user_id", tracing::field::display(user_id));
    tracing::Span::current().record("session_id", tracing::field::display(session_id));

    // Verify chat session ownership
    let chat_session_owner_id = state
        .pool
        .get()
        .await?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .select(chat_sessions::user_id)
                .first::<Uuid>(conn)
                .optional()
        })
        .await??
        .ok_or_else(|| AppError::NotFound(format!("Chat session {session_id} not found")))?;

    if chat_session_owner_id != user_id {
        error!(
            "User {} attempted to impersonate for chat session {} owned by {}",
            user_id, session_id, chat_session_owner_id
        );
        return Err(AppError::Forbidden(
            "Access denied to chat session".to_string(),
        ));
    }

    // Use the existing chat generation infrastructure but with an "impersonation" system prompt
    // This will include RAG, persona context, and all the same features as regular chat

    // Get the existing chat messages to build proper context
    let messages_result = state
        .pool
        .get()
        .await?
        .interact(move |conn| {
            use crate::schema::chat_messages;
            chat_messages::table
                .filter(chat_messages::session_id.eq(session_id))
                .order(chat_messages::created_at.asc())
                .select(crate::models::chats::ChatMessage::as_select())
                .load(conn)
        })
        .await??;

    // Build the chat history in the format expected by the generation service
    let mut chat_history = Vec::new();

    // Decrypt and convert existing messages to API format
    for db_message in messages_result.iter() {
        let decrypted_content = if let Some(nonce) = &db_message.content_nonce {
            match crate::crypto::decrypt_gcm(&db_message.content, nonce, &session_dek.0) {
                Ok(content) => String::from_utf8_lossy(content.expose_secret()).to_string(),
                Err(_) => continue, // Skip messages we can't decrypt
            }
        } else {
            // Fallback for unencrypted content (shouldn't happen in production)
            String::from_utf8_lossy(&db_message.content).to_string()
        };

        let api_message = crate::models::chats::ApiChatMessage {
            role: match db_message.message_type {
                MessageRole::User => "user".to_string(),
                MessageRole::Assistant => "assistant".to_string(),
                MessageRole::System => "system".to_string(),
            },
            content: decrypted_content,
        };
        chat_history.push(api_message);
    }

    // Add a special system message to instruct the AI to impersonate the user
    let impersonation_instruction = crate::models::chats::ApiChatMessage {
        role: "user".to_string(),
        content: "[IMPERSONATE: You are now speaking as the user persona. Generate a natural response that the user would make in this conversation context. Respond only as the user, not as an assistant.]".to_string(),
    };
    chat_history.push(impersonation_instruction);

    // Create the generation request using the existing chat pipeline
    let generation_request = GenerateChatRequest {
        history: chat_history,
        model: None, // Use chat's configured model
        query_text_for_rag: Some(
            "What should the user say in response to this conversation?".to_string(),
        ),
        analysis_mode: None, // Not applicable for suggested actions
    };

    // Call the existing generate_chat_response handler logic but collect the response
    // instead of streaming it directly to the client

    // Use the chat generation service infrastructure directly
    let state_arc = Arc::new(state);
    let user_dek_arc = Arc::new(session_dek.0);

    // Clone the state_arc for later use in deletion
    let delete_state = state_arc.clone();

    // Get session data and model configuration like the normal chat flow does
    let session_data = state_arc
        .pool
        .get()
        .await?
        .interact(move |conn| {
            use crate::schema::chat_sessions;
            chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .select((
                    chat_sessions::history_management_strategy,
                    chat_sessions::history_management_limit,
                    chat_sessions::model_name,
                    chat_sessions::model_provider,
                    chat_sessions::temperature,
                    chat_sessions::max_output_tokens,
                    chat_sessions::frequency_penalty,
                    chat_sessions::presence_penalty,
                    chat_sessions::top_k,
                    chat_sessions::top_p,
                    chat_sessions::stop_sequences,
                    chat_sessions::seed,
                    chat_sessions::active_custom_persona_id,
                ))
                .first::<(
                    String,
                    i32,
                    String,
                    Option<String>,
                    Option<bigdecimal::BigDecimal>,
                    Option<i32>,
                    Option<bigdecimal::BigDecimal>,
                    Option<bigdecimal::BigDecimal>,
                    Option<i32>,
                    Option<bigdecimal::BigDecimal>,
                    Option<Vec<Option<String>>>,
                    Option<i32>,
                    Option<Uuid>,
                )>(conn)
        })
        .await??;

    // Build the special system prompt for impersonation
    let mut impersonation_system_prompt =
        "You are impersonating the user in this conversation. ".to_string();

    // Add persona context if available
    if let Some(persona_id) = session_data.11 {
        impersonation_system_prompt.push_str(&format!(
            "You are speaking AS the user persona (ID: {}). ",
            persona_id
        ));
    }

    impersonation_system_prompt.push_str(
        "Generate a natural response that this user would make given the conversation context. \
        Respond only as the user character, not as an assistant. Use the user's personality, \
        speaking style, and context from the conversation history and any retrieved information. \
        Do not break character or mention that you are an AI.",
    );

    // Convert API messages to GenAI format for the generation service
    let genai_messages = generation_request
        .history
        .into_iter()
        .map(|msg| GenAiChatMessage {
            role: match msg.role.as_str() {
                "user" => ChatRole::User,
                "assistant" => ChatRole::Assistant,
                "system" => ChatRole::System,
                _ => ChatRole::User,
            },
            content: MessageContent::Text(msg.content),
            options: None,
        })
        .collect();

    // Create StreamAiParams for the generation service
    let stream_params = chat::generation::StreamAiParams {
        state: state_arc,
        session_id,
        user_id,
        incoming_genai_messages: genai_messages,
        system_prompt: Some(impersonation_system_prompt),
        temperature: session_data.4,
        max_output_tokens: session_data.5,
        frequency_penalty: session_data.6,
        presence_penalty: session_data.7,
        top_k: session_data.8,
        top_p: session_data.9,
        stop_sequences: session_data
            .10
            .and_then(|seq| seq.into_iter().collect::<Option<Vec<String>>>()),
        seed: session_data.11,
        model_name: session_data.2,
        model_provider: session_data.3,
        gemini_thinking_budget: None,
        gemini_enable_code_execution: Some(false),
        request_thinking: false,
        user_dek: Some(user_dek_arc),
        character_name: None, // Impersonation doesn't have a character
        player_chronicle_id: None, // Impersonation doesn't involve chronicle processing
    };

    // Generate the response using the full pipeline
    let mut response_stream =
        chat::generation::stream_ai_response_and_save_message(stream_params).await?;

    // Collect the response
    let mut generated_response = String::new();

    while let Some(event_result) = response_stream.next().await {
        match event_result {
            Ok(event) => {
                match event {
                    chat::types::ScribeSseEvent::Content(content) => {
                        generated_response.push_str(&content);
                    }
                    chat::types::ScribeSseEvent::Error(error_msg) => {
                        error!("Error in impersonation stream: {}", error_msg);
                        return Err(AppError::BadGateway(
                            "Failed to generate response".to_string(),
                        ));
                    }
                    chat::types::ScribeSseEvent::TokenUsage { .. } => {
                        // For impersonation, we don't need to handle token usage
                    }
                    _ => {
                        // Skip other event types (thinking, etc.)
                    }
                }
            }
            Err(e) => {
                error!("Error in impersonation stream: {}", e);
                return Err(AppError::BadGateway(
                    "Failed to generate response".to_string(),
                ));
            }
        }
    }

    // Delete the most recent message since we don't want it saved for impersonation
    // The generation service will have just created a message, so we find and delete the most recent one
    let delete_session_id = session_id;
    let _ = delete_state
        .pool
        .get()
        .await?
        .interact(move |conn| {
            use crate::schema::chat_messages;
            // Find the most recent message for this session and delete it (it will be the AI response we just generated)
            if let Ok(recent_message) = chat_messages::table
                .filter(chat_messages::session_id.eq(delete_session_id))
                .order(chat_messages::created_at.desc())
                .select(crate::models::chats::ChatMessage::as_select())
                .first(conn)
            {
                let _ = diesel::delete(
                    chat_messages::table.filter(chat_messages::id.eq(recent_message.id)),
                )
                .execute(conn);
                debug!(
                    "Deleted impersonation message with ID: {}",
                    recent_message.id
                );
            }
        })
        .await;

    if generated_response.trim().is_empty() {
        warn!("AI returned empty impersonation response");
        return Err(AppError::BadGateway(
            "AI failed to generate response".to_string(),
        ));
    }

    info!(
        "Impersonation completed successfully for session_id: {}",
        session_id
    );
    Ok(Json(ImpersonateResponse {
        generated_response: generated_response.trim().to_string(),
    }))
}

// ============================================================================
// Message Variant Handlers
// ============================================================================
