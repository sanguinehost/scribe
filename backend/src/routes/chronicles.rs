// backend/src/routes/chronicles.rs

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use axum_login::AuthSession;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, instrument, warn};
use uuid::Uuid;
use validator::Validate;

use crate::{
    auth::{
        user_store::Backend as AuthBackend,
        session_dek::SessionDek,
    },
    errors::AppError,
    models::{
        chats::ChatMessage,
        chronicle::{
            CreateChronicleRequest, PlayerChronicle, PlayerChronicleWithCounts, UpdateChronicleRequest,
        },
        chronicle_event::{ChronicleEvent, CreateEventRequest, EventFilter, EventOrderBy, EventSource},
    },
    services::{
        ChronicleService,
    },
    state::AppState,
};

/// Query parameters for listing events
#[derive(Debug, Deserialize)]
pub struct EventQuery {
    pub event_type: Option<String>,
    pub source: Option<EventSource>,
    pub order_by: Option<EventOrderBy>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Request payload for re-chronicling from chat
#[derive(Debug, Deserialize, Validate)]
pub struct ReChronicleRequest {
    /// The chat session ID to re-chronicle
    pub chat_session_id: Uuid,
    /// Whether to purge existing chronicle events before re-chronicling
    #[serde(default)]
    pub purge_existing: bool,
    /// Start message index (optional, defaults to beginning)
    pub start_message_index: Option<usize>,
    /// End message index (optional, defaults to end)
    pub end_message_index: Option<usize>,
    /// AI model to use for extraction (optional)
    pub extraction_model: Option<String>,
    /// Maximum number of messages to process in a single batch
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
}

fn default_batch_size() -> usize {
    10
}

/// Response from re-chronicling operation
#[derive(Debug, Serialize, Deserialize)]
pub struct ReChronicleResponse {
    /// Number of events created during re-chronicling
    pub events_created: usize,
    /// Number of messages processed
    pub messages_processed: usize,
    /// Number of existing events that were purged (if purge_existing was true)
    pub events_purged: usize,
    /// Processing summary
    pub summary: String,
}

/// Request payload for generating a chronicle name from chat session
#[derive(Debug, Deserialize, Validate)]
pub struct GenerateChronicleNameRequest {
    /// The chat session ID to analyze for name generation
    pub chat_session_id: Uuid,
}

/// Response with the generated chronicle name
#[derive(Debug, Serialize)]
pub struct GenerateChronicleNameResponse {
    /// The generated chronicle name
    pub name: String,
    /// Optional reasoning for the name choice (for debugging)
    pub reasoning: Option<String>,
}


impl From<EventQuery> for EventFilter {
    fn from(query: EventQuery) -> Self {
        Self {
            event_type: query.event_type,
            source: query.source,
            keywords: None, // Will be used for search in the future
            after_timestamp: None,
            before_timestamp: None,
            chat_session_id: None,
            order_by: query.order_by,
            limit: query.limit,
            offset: query.offset,
        }
    }
}

/// Create the chronicles router with all endpoints
pub fn create_chronicles_router(state: AppState) -> Router<AppState> {
    info!("=== CREATING CHRONICLES ROUTER ===");
    Router::new()
        .route("/", post(create_chronicle).get(list_chronicles))
        .route("/generate-name", post(generate_chronicle_name))
        .route("/:chronicle_id", get(get_chronicle).put(update_chronicle).delete(delete_chronicle))
        .route("/:chronicle_id/events", post(create_event).get(list_events))
        .route("/:chronicle_id/events/:event_id", delete(delete_event))
        .route("/:chronicle_id/re-chronicle", post(re_chronicle_from_chat))
        .with_state(state)
}

// --- Chronicle CRUD Handlers ---

/// Create a new chronicle
#[instrument(skip(auth_session, state))]
async fn create_chronicle(
    auth_session: AuthSession<AuthBackend>,
    State(state): State<AppState>,
    Json(request): Json<CreateChronicleRequest>,
) -> Result<(StatusCode, Json<PlayerChronicle>), AppError> {
    info!("=== CREATE CHRONICLE HANDLER CALLED ===");
    
    // Validate the request
    request.validate()?;
    
    let user = auth_session.user.ok_or_else(|| {
        error!("No authenticated user found in session");
        AppError::Unauthorized("Authentication required".to_string())
    })?;

    info!("Creating chronicle for user {}: {}", user.id, request.name);

    let chronicle_service = ChronicleService::new(state.pool.clone());
    let chronicle = chronicle_service.create_chronicle(user.id, request).await?;

    info!("Successfully created chronicle {}", chronicle.id);
    Ok((StatusCode::CREATED, Json(chronicle)))
}

/// List all chronicles for the authenticated user
#[instrument(skip(auth_session, state))]
async fn list_chronicles(
    auth_session: AuthSession<AuthBackend>,
    State(state): State<AppState>,
) -> Result<Json<Vec<PlayerChronicleWithCounts>>, AppError> {
    let user = auth_session.user.ok_or_else(|| {
        error!("No authenticated user found in session");
        AppError::Unauthorized("Authentication required".to_string())
    })?;

    info!("Listing chronicles for user {}", user.id);

    let chronicle_service = ChronicleService::new(state.pool.clone());
    let chronicles = chronicle_service.get_user_chronicles_with_counts(user.id).await?;

    info!("Retrieved {} chronicles for user {}", chronicles.len(), user.id);
    Ok(Json(chronicles))
}

/// Get a specific chronicle by ID
#[instrument(skip(auth_session, state))]
async fn get_chronicle(
    auth_session: AuthSession<AuthBackend>,
    State(state): State<AppState>,
    Path(chronicle_id): Path<Uuid>,
) -> Result<Json<PlayerChronicle>, AppError> {
    let user = auth_session.user.ok_or_else(|| {
        error!("No authenticated user found in session");
        AppError::Unauthorized("Authentication required".to_string())
    })?;

    info!("Getting chronicle {} for user {}", chronicle_id, user.id);

    let chronicle_service = ChronicleService::new(state.pool.clone());
    let chronicle = chronicle_service.get_chronicle(user.id, chronicle_id).await?;

    info!("Successfully retrieved chronicle {}", chronicle_id);
    Ok(Json(chronicle))
}

/// Update a chronicle
#[instrument(skip(auth_session, state))]
async fn update_chronicle(
    auth_session: AuthSession<AuthBackend>,
    State(state): State<AppState>,
    Path(chronicle_id): Path<Uuid>,
    Json(request): Json<UpdateChronicleRequest>,
) -> Result<Json<PlayerChronicle>, AppError> {
    // Validate the request
    request.validate()?;
    
    let user = auth_session.user.ok_or_else(|| {
        error!("No authenticated user found in session");
        AppError::Unauthorized("Authentication required".to_string())
    })?;

    info!("Updating chronicle {} for user {}", chronicle_id, user.id);

    let chronicle_service = ChronicleService::new(state.pool.clone());
    let chronicle = chronicle_service.update_chronicle(user.id, chronicle_id, request).await?;

    info!("Successfully updated chronicle {}", chronicle_id);
    Ok(Json(chronicle))
}

/// Delete a chronicle
#[instrument(skip(auth_session, state))]
async fn delete_chronicle(
    auth_session: AuthSession<AuthBackend>,
    State(state): State<AppState>,
    Path(chronicle_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let user = auth_session.user.ok_or_else(|| {
        error!("No authenticated user found in session");
        AppError::Unauthorized("Authentication required".to_string())
    })?;

    info!("Deleting chronicle {} for user {}", chronicle_id, user.id);

    // First, clean up all chronicle event embeddings from Qdrant
    // This must be done before deleting the chronicle from the database
    // because the database CASCADE will delete the events
    if let Err(e) = state
        .embedding_pipeline_service
        .delete_chronicle_events_by_chronicle_id(Arc::new(state.clone()), chronicle_id, user.id)
        .await
    {
        warn!(
            chronicle_id = %chronicle_id,
            error = %e,
            "Failed to delete chronicle event embeddings from Qdrant, but will proceed with chronicle deletion"
        );
        // We log the error but don't fail the request, as the database deletion is more important
        // and we don't want to leave the user unable to delete their chronicle
    } else {
        info!(chronicle_id = %chronicle_id, "Successfully cleaned up chronicle event embeddings from Qdrant");
    }

    // Now delete the chronicle from the database (this will CASCADE delete all chronicle_events)
    let chronicle_service = ChronicleService::new(state.pool.clone());
    chronicle_service.delete_chronicle(user.id, chronicle_id).await?;

    info!("Successfully deleted chronicle {} and all associated data", chronicle_id);
    Ok(StatusCode::NO_CONTENT)
}

// --- Event Handlers ---

/// Create a new event in a chronicle
#[instrument(skip(auth_session, state))]
async fn create_event(
    auth_session: AuthSession<AuthBackend>,
    session_dek: crate::auth::session_dek::SessionDek,
    State(state): State<AppState>,
    Path(chronicle_id): Path<Uuid>,
    Json(request): Json<CreateEventRequest>,
) -> Result<(StatusCode, Json<ChronicleEvent>), AppError> {
    // Validate the request
    request.validate()?;
    
    let user = auth_session.user.ok_or_else(|| {
        error!("No authenticated user found in session");
        AppError::Unauthorized("Authentication required".to_string())
    })?;

    info!("Creating event in chronicle {} for user {}: {}", chronicle_id, user.id, request.event_type);

    let chronicle_service = ChronicleService::new(state.pool.clone());
    let mut event = chronicle_service.create_event(user.id, chronicle_id, request, Some(&session_dek)).await?;

    // Embed the chronicle event for semantic search
    if let Err(e) = state
        .embedding_pipeline_service
        .process_and_embed_chronicle_event(Arc::new(state.clone()), event.clone(), Some(&session_dek))
        .await
    {
        warn!(event_id = %event.id, error = %e, "Failed to embed chronicle event, but event was created successfully");
        // Don't fail the request if embedding fails
    } else {
        info!(event_id = %event.id, "Successfully embedded chronicle event for semantic search");
    }

    // Decrypt event summary before returning to client
    if event.has_encrypted_summary() {
        event.summary = event.get_decrypted_summary(&session_dek.0)?;
    }
    // Also decrypt keywords if encrypted
    if event.has_encrypted_keywords() {
        let decrypted_keywords = event.get_decrypted_keywords(&session_dek.0)?;
        event.keywords = Some(decrypted_keywords.into_iter().map(Some).collect());
    }

    info!("Successfully created event {}", event.id);
    Ok((StatusCode::CREATED, Json(event)))
}

/// List events for a chronicle with optional filtering
#[instrument(skip(auth_session, session_dek, state))]
async fn list_events(
    auth_session: AuthSession<AuthBackend>,
    session_dek: SessionDek,
    State(state): State<AppState>,
    Path(chronicle_id): Path<Uuid>,
    Query(query): Query<EventQuery>,
) -> Result<Json<Vec<ChronicleEvent>>, AppError> {
    let user = auth_session.user.ok_or_else(|| {
        error!("No authenticated user found in session");
        AppError::Unauthorized("Authentication required".to_string())
    })?;

    info!("Listing events for chronicle {} for user {}", chronicle_id, user.id);

    let filter = EventFilter::from(query);
    let chronicle_service = ChronicleService::new(state.pool.clone());
    let mut events = chronicle_service.get_chronicle_events(user.id, chronicle_id, filter).await?;

    // Decrypt event summaries before returning
    for event in &mut events {
        if event.has_encrypted_summary() {
            event.summary = event.get_decrypted_summary(&session_dek.0)?;
        }
        // Also decrypt keywords if encrypted
        if event.has_encrypted_keywords() {
            let decrypted_keywords = event.get_decrypted_keywords(&session_dek.0)?;
            event.keywords = Some(decrypted_keywords.into_iter().map(Some).collect());
        }
    }

    info!("Retrieved {} events for chronicle {}", events.len(), chronicle_id);
    Ok(Json(events))
}

/// Delete an event
#[instrument(skip(auth_session, state))]
async fn delete_event(
    auth_session: AuthSession<AuthBackend>,
    State(state): State<AppState>,
    Path((chronicle_id, event_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let user = auth_session.user.ok_or_else(|| {
        error!("No authenticated user found in session");
        AppError::Unauthorized("Authentication required".to_string())
    })?;

    info!("Deleting event {} from chronicle {} for user {}", event_id, chronicle_id, user.id);

    let chronicle_service = ChronicleService::new(state.pool.clone());
    chronicle_service.delete_event(user.id, event_id).await?;

    // Clean up embeddings for the deleted event
    if let Err(e) = state
        .embedding_pipeline_service
        .delete_chronicle_event_chunks(Arc::new(state.clone()), event_id, user.id)
        .await
    {
        warn!(event_id = %event_id, error = %e, "Failed to delete chronicle event embeddings, but event was deleted successfully");
        // Don't fail the request if embedding cleanup fails
    } else {
        info!(event_id = %event_id, "Successfully cleaned up chronicle event embeddings");
    }

    info!("Successfully deleted event {}", event_id);
    Ok(StatusCode::NO_CONTENT)
}

/// Re-chronicle events from chat messages
/// 
/// This endpoint processes chat messages and extracts chronicle events using the 
/// narrative intelligence system. It can optionally purge existing events first.
#[instrument(skip(auth_session, session_dek, state))]
async fn re_chronicle_from_chat(
    auth_session: AuthSession<AuthBackend>,
    session_dek: SessionDek,
    State(state): State<AppState>,
    Path(chronicle_id): Path<Uuid>,
    Json(request): Json<ReChronicleRequest>,
) -> Result<Json<ReChronicleResponse>, AppError> {
    // Validate the request
    request.validate()?;
    
    let user = auth_session.user.ok_or_else(|| {
        error!("No authenticated user found in session");
        AppError::Unauthorized("Authentication required".to_string())
    })?;

    info!(
        "Re-chronicling chat {} for chronicle {} by user {}",
        request.chat_session_id, chronicle_id, user.id
    );

    let chronicle_service = ChronicleService::new(state.pool.clone());
    
    // Verify the chronicle exists and belongs to the user
    let _chronicle = chronicle_service.get_chronicle(user.id, chronicle_id).await?;
    
    let mut events_purged = 0;
    
    // Purge existing events if requested
    if request.purge_existing {
        info!("Purging existing chronicle events for chronicle {}", chronicle_id);
        let existing_events = chronicle_service.get_chronicle_events(
            user.id,
            chronicle_id,
            EventFilter::default()
        ).await?;
        
        events_purged = existing_events.len();
        
        for event in existing_events {
            // Delete the event
            chronicle_service.delete_event(user.id, event.id).await?;
            
            // Clean up embeddings
            if let Err(e) = state
                .embedding_pipeline_service
                .delete_chronicle_event_chunks(Arc::new(state.clone()), event.id, user.id)
                .await
            {
                warn!(event_id = %event.id, error = %e, "Failed to delete chronicle event embeddings during purge");
            }
        }
        
        info!("Purged {} existing chronicle events", events_purged);
    }
    
    // Get chat messages
    let messages = get_chat_messages(&state, request.chat_session_id, user.id).await?;
    
    if messages.is_empty() {
        return Ok(Json(ReChronicleResponse {
            events_created: 0,
            messages_processed: 0,
            events_purged,
            summary: "No messages found in chat session".to_string(),
        }));
    }
    
    // Filter messages by index range if specified
    let start_idx = request.start_message_index.unwrap_or(0);
    let end_idx = request.end_message_index.unwrap_or(messages.len());
    
    let messages_to_process: Vec<_> = messages
        .into_iter()
        .enumerate()
        .filter(|(idx, _)| *idx >= start_idx && *idx < end_idx)
        .map(|(_, msg)| msg)
        .collect();
    
    info!(
        "Processing {} messages from indices {} to {}",
        messages_to_process.len(),
        start_idx,
        end_idx
    );
    
    let mut total_events_created = 0;
    let mut messages_processed = 0;
    
    // Process messages in batches to provide context
    let batch_size = request.batch_size.min(50); // Cap at 50 for safety
    
    for (batch_idx, batch) in messages_to_process.chunks(batch_size).enumerate() {
        info!(
            "Processing batch {} with {} messages",
            batch_idx,
            batch.len()
        );
        
        // Get the narrative intelligence service
        let narrative_service = state.narrative_intelligence_service.as_ref()
            .ok_or_else(|| AppError::InternalServerErrorGeneric("Narrative intelligence service not available".to_string()))?;
        
        // Process this batch of messages through the narrative intelligence system
        let processing_result = narrative_service.process_chat_history_batch(
            user.id,
            request.chat_session_id,
            Some(chronicle_id),
            batch.to_vec(),
            &session_dek,
        ).await?;
        
        total_events_created += processing_result.events_created;
        messages_processed += batch.len();
        
        info!(
            "Batch {} complete: {} events created from {} messages",
            batch_idx,
            processing_result.events_created,
            batch.len()
        );
    }
    
    let summary = format!(
        "Re-chronicling complete: {} events created from {} messages{}",
        total_events_created,
        messages_processed,
        if events_purged > 0 { format!(", {} existing events purged", events_purged) } else { String::new() }
    );
    
    info!("{}", summary);
    
    Ok(Json(ReChronicleResponse {
        events_created: total_events_created,
        messages_processed,
        events_purged,
        summary,
    }))
}

/// Helper function to get the character name for a chat session
async fn get_character_name_for_session(
    state: &AppState,
    chat_session_id: Uuid,
    user_id: Uuid,
) -> Result<Option<String>, AppError> {
    use crate::schema::{chat_sessions, characters};
    use diesel::{QueryDsl, RunQueryDsl, ExpressionMethods, JoinOnDsl, SelectableHelper, BoolExpressionMethods, NullableExpressionMethods};
    
    let conn = state.pool.get().await?;
    
    let character_name = conn.interact(move |conn| {
        chat_sessions::table
            .left_join(characters::table.on(
                chat_sessions::character_id.eq(characters::id.nullable())
            ))
            .filter(chat_sessions::id.eq(chat_session_id))
            .filter(chat_sessions::user_id.eq(user_id))
            .select(characters::name.nullable())
            .first::<Option<String>>(conn)
    })
    .await
    .map_err(|e| AppError::DatabaseQueryError(format!("Database interaction failed: {}", e)))?
    .map_err(|e| AppError::DatabaseQueryError(format!("Failed to fetch character name: {}", e)))?;
    
    Ok(character_name)
}

/// Helper function to get chat messages for a session
async fn get_chat_messages(
    state: &AppState,
    chat_session_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<ChatMessage>, AppError> {
    use crate::schema::{chat_messages, chat_sessions};
    use diesel::{QueryDsl, RunQueryDsl, ExpressionMethods, JoinOnDsl, SelectableHelper, BoolExpressionMethods};
    
    let conn = state.pool.get().await?;
    
    let messages = conn.interact(move |conn| {
        chat_messages::table
            .inner_join(
                chat_sessions::table.on(
                    chat_messages::session_id.eq(chat_sessions::id)
                        .and(chat_sessions::user_id.eq(user_id))
                )
            )
            .filter(chat_messages::session_id.eq(chat_session_id))
            .select(ChatMessage::as_select())
            .order(chat_messages::created_at.asc())
            .load::<ChatMessage>(conn)
    })
    .await
    .map_err(|e| AppError::DatabaseQueryError(format!("Database interaction failed: {}", e)))?
    .map_err(|e| AppError::DatabaseQueryError(format!("Failed to fetch chat messages: {}", e)))?;
    
    Ok(messages)
}

/// Generate a chronicle name from a chat session using AI
#[instrument(skip(auth_session, session_dek, state))]
async fn generate_chronicle_name(
    auth_session: AuthSession<AuthBackend>,
    session_dek: SessionDek,
    State(state): State<AppState>,
    Json(request): Json<GenerateChronicleNameRequest>,
) -> Result<Json<GenerateChronicleNameResponse>, AppError> {
    use diesel::prelude::*;
    use crate::schema::{chat_messages, chat_sessions};
    use crate::services::agentic::AgenticNarrativeFactory;
    
    // Validate the request
    request.validate()?;
    
    let user = auth_session.user.ok_or_else(|| {
        error!("No authenticated user found in session");
        AppError::Unauthorized("Authentication required".to_string())
    })?;

    info!(
        "Generating chronicle name for chat session {} by user {}",
        request.chat_session_id, user.id
    );

    // Fetch chat messages for the session
    let messages: Vec<ChatMessage> = state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to get database connection: {}", e)))?
        .interact(move |conn| {
            chat_messages::table
                .inner_join(
                    chat_sessions::table.on(
                        chat_messages::session_id.eq(chat_sessions::id)
                            .and(chat_sessions::user_id.eq(user.id))
                    )
                )
                .filter(chat_messages::session_id.eq(request.chat_session_id))
                .select(ChatMessage::as_select())
                .order(chat_messages::created_at.asc())
                .load::<ChatMessage>(conn)
        })
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Database interaction failed: {}", e)))?
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to fetch chat messages: {}", e)))?;
    
    if messages.is_empty() {
        return Err(AppError::NotFound(
            "No messages found in the specified chat session".to_string()
        ));
    }
    
    // Fetch the character name if available
    let character_name = get_character_name_for_session(&state, request.chat_session_id, user.id).await?;
    
    // Create a NarrativeAgentRunner using the factory
    let chronicle_service = Arc::new(ChronicleService::new(state.pool.clone()));
    let app_state = Arc::new(state.clone());
    
    let agent_runner = AgenticNarrativeFactory::create_system_with_deps(
        state.ai_client.clone(),
        chronicle_service.clone(),
        state.lorebook_service.clone(),
        state.qdrant_service.clone(),
        state.embedding_client.clone(),
        app_state,
        Some(AgenticNarrativeFactory::create_dev_config()),
    );
    
    let generated_name = agent_runner
        .generate_chronicle_name_from_messages(&messages, &session_dek, character_name)
        .await?;
    
    info!(
        "Successfully generated chronicle name '{}' for chat session {}",
        generated_name, request.chat_session_id
    );
    
    Ok(Json(GenerateChronicleNameResponse {
        name: generated_name,
        reasoning: None, // We could extract this from the structured output if needed
    }))
}