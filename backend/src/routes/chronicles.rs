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
use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;
use validator::Validate;

/// Default value for purge_existing field - defaults to true for clean re-chronicling
fn default_purge_existing() -> bool {
    true
}

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
        EventDataToInsert,
        hybrid_query_service::{
            HybridQueryService, HybridQuery, HybridQueryType, HybridQueryOptions
        },
        ecs_enhanced_rag_service::{
            EntityStateSnapshot, RelationshipContext
        },
        chronicle_event_listener::{ChronicleEventNotification, ChronicleNotificationType},
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
    #[serde(default = "default_purge_existing")]
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
    4
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
    /// Number of ECS entities created during re-chronicling (if ECS is enabled)
    pub ecs_entities_created: Option<usize>,
    /// Processing summary
    pub summary: String,
}

/// Response for chronicle entities endpoint
#[derive(Debug, Serialize, Deserialize)]
pub struct ChronicleEntitiesResponse {
    /// Chronicle ID
    pub chronicle_id: Uuid,
    /// Current entity states in this chronicle
    pub entities: Vec<EntityStateSnapshot>,
    /// Metadata about the entity query
    pub metadata: ChronicleEntitiesMetadata,
}

/// Metadata for chronicle entities response
#[derive(Debug, Serialize, Deserialize)]
pub struct ChronicleEntitiesMetadata {
    /// Total number of entities found
    pub total_entities: usize,
    /// Whether ECS was available for enhanced data
    pub ecs_enhanced: bool,
    /// Any warnings encountered
    pub warnings: Vec<String>,
}

/// Response for entity timeline endpoint  
#[derive(Debug, Serialize, Deserialize)]
pub struct EntityTimelineResponse {
    /// Entity ID
    pub entity_id: Uuid,
    /// Chronicle events involving this entity
    pub chronicle_events: Vec<ChronicleEvent>,
    /// Current entity state (if available)
    pub current_state: Option<EntityStateSnapshot>,
    /// Metadata about the timeline query
    pub metadata: EntityTimelineMetadata,
}

/// Metadata for entity timeline response
#[derive(Debug, Serialize, Deserialize)]
pub struct EntityTimelineMetadata {
    /// Total number of events found
    pub total_events: usize,
    /// Whether ECS was available for enhanced data
    pub ecs_enhanced: bool,
    /// Any warnings encountered
    pub warnings: Vec<String>,
}

/// Response for chronicle relationships endpoint
#[derive(Debug, Serialize, Deserialize)]
pub struct ChronicleRelationshipsResponse {
    /// Chronicle ID
    pub chronicle_id: Uuid,
    /// Current relationships in this chronicle
    pub relationships: Vec<RelationshipContext>,
    /// Metadata about the relationships query
    pub metadata: ChronicleRelationshipsMetadata,
}

/// Metadata for chronicle relationships response
#[derive(Debug, Serialize, Deserialize)]
pub struct ChronicleRelationshipsMetadata {
    /// Total number of relationships found
    pub total_relationships: usize,
    /// Whether ECS was available for enhanced data
    pub ecs_enhanced: bool,
    /// Any warnings encountered
    pub warnings: Vec<String>,
}

/// Query parameters for hybrid queries
#[derive(Debug, Deserialize)]
pub struct HybridQueryParams {
    /// Query type (optional, defaults to narrative query)
    pub query_type: Option<String>,
    /// Query text for narrative queries
    pub query: Option<String>,
    /// Maximum results to return
    pub limit: Option<usize>,
    /// Include current entity states
    #[serde(default = "default_true")]
    pub include_current_state: bool,
    /// Include relationship context
    #[serde(default = "default_true")]
    pub include_relationships: bool,
    /// Confidence threshold for results
    pub confidence_threshold: Option<f32>,
}

fn default_true() -> bool {
    true
}


impl From<EventQuery> for EventFilter {
    fn from(query: EventQuery) -> Self {
        Self {
            event_type: query.event_type,
            source: query.source,
            action: None,
            modality: None,
            involves_entity: None,
            after_timestamp: None,
            before_timestamp: None,
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
        .route("/:chronicle_id", get(get_chronicle).put(update_chronicle).delete(delete_chronicle))
        .route("/:chronicle_id/events", post(create_event).get(list_events))
        .route("/:chronicle_id/events/:event_id", delete(delete_event))
        .route("/:chronicle_id/re-chronicle", post(re_chronicle_from_chat))
        // New ECS-enhanced endpoints for Phase 4.2.3
        .route("/:chronicle_id/entities", get(get_chronicle_entities))
        .route("/:chronicle_id/relationships", get(get_chronicle_relationships))
        .with_state(state)
}

/// Create the entities router with ECS-enhanced endpoints
pub fn create_entities_router(state: AppState) -> Router<AppState> {
    info!("=== CREATING ENTITIES ROUTER ===");
    let router = Router::new()
        .route("/:entity_id/timeline", get(get_entity_timeline))
        .with_state(state);
    info!("=== ENTITIES ROUTER CREATED WITH TIMELINE ROUTE ===");
    router
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

    let chronicle_service = ChronicleService::new(state.pool.clone());
    chronicle_service.delete_chronicle(user.id, chronicle_id).await?;

    info!("Successfully deleted chronicle {}", chronicle_id);
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
    let event = chronicle_service.create_event(user.id, chronicle_id, request, Some(&session_dek)).await?;

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

    // Emit ChronicleEventNotification to trigger ECS updates
    let notification = ChronicleEventNotification {
        event_id: event.id,
        user_id: user.id,
        chronicle_id,
        event_type: event.event_type.clone(),
        notification_type: ChronicleNotificationType::Created,
    };
    
    if let Err(e) = state.chronicle_event_listener.notify_chronicle_event(notification).await {
        warn!(event_id = %event.id, error = %e, "Failed to notify ECS system about new chronicle event");
        // Don't fail the request if ECS notification fails - continue gracefully
    } else {
        info!(event_id = %event.id, "Successfully notified ECS system about new chronicle event");
    }

    info!("Successfully created event {}", event.id);
    Ok((StatusCode::CREATED, Json(event)))
}

/// List events for a chronicle with optional filtering
#[instrument(skip(auth_session, state))]
async fn list_events(
    auth_session: AuthSession<AuthBackend>,
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
    let events = chronicle_service.get_chronicle_events(user.id, chronicle_id, filter).await?;

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

    // Acquire a permit from the global re-chronicle semaphore to limit concurrent jobs
    let _permit = state.rechronicle_semaphore.clone().acquire_owned().await
        .map_err(|_| AppError::ServiceUnavailable("Too many re-chronicle jobs running concurrently".to_string()))?;

    // Validate chronicle ownership
    let chronicle_service = ChronicleService::new(state.pool.clone());
    let _chronicle = chronicle_service.get_chronicle(user.id, chronicle_id).await?;
    
    // Handle purging existing events if requested
    let events_purged = if request.purge_existing {
        // First purge ECS entities for this chronicle
        let ecs_entities_purged = state.ecs_entity_manager
            .purge_entities_by_chronicle(user.id, chronicle_id)
            .await?;
        
        info!("Purged {} ECS entities for chronicle {}", ecs_entities_purged, chronicle_id);
        
        // Then purge chronicle events
        purge_existing_events(&state, &chronicle_service, user.id, chronicle_id).await?
    } else {
        0
    };
    
    // Get and filter chat messages
    let messages = get_chat_messages(&state, request.chat_session_id, user.id).await?;
    if messages.is_empty() {
        return Ok(Json(ReChronicleResponse {
            events_created: 0,
            messages_processed: 0,
            events_purged,
            ecs_entities_created: Some(0),
            summary: "No messages found in chat session".to_string(),
        }));
    }
    
    let messages_to_process = filter_messages_by_range(
        messages,
        request.start_message_index.unwrap_or(0),
        request.end_message_index
    );
    
    info!(
        "Processing {} messages from indices {} to {}",
        messages_to_process.len(),
        request.start_message_index.unwrap_or(0),
        request.end_message_index.unwrap_or(messages_to_process.len())
    );
    
    // Process messages using the streaming pipeline
    let (events_created, messages_processed, ecs_entities_created) = process_messages_with_streaming_pipeline(
        &state,
        &user,
        chronicle_id,
        &session_dek,
        &request,
        messages_to_process,
    ).await?;
    
    let summary = build_summary(events_created, messages_processed, events_purged, Some(ecs_entities_created));
    info!("{}", summary);
    
    Ok(Json(ReChronicleResponse {
        events_created,
        messages_processed,
        events_purged,
        ecs_entities_created: Some(ecs_entities_created),
        summary,
    }))
}

/// Purge existing chronicle events for a chronicle
async fn purge_existing_events(
    state: &AppState,
    chronicle_service: &ChronicleService,
    user_id: Uuid,
    chronicle_id: Uuid,
) -> Result<usize, AppError> {
    info!("Purging existing chronicle events for chronicle {}", chronicle_id);
    
    let existing_events = chronicle_service.get_chronicle_events(
        user_id,
        chronicle_id,
        EventFilter {
            limit: None, // Remove limit to purge ALL events
            ..EventFilter::default()
        }
    ).await?;
    
    let events_count = existing_events.len();
    
    for event in existing_events {
        // Delete the event
        chronicle_service.delete_event(user_id, event.id).await?;
        
        // Clean up embeddings
        if let Err(e) = state
            .embedding_pipeline_service
            .delete_chronicle_event_chunks(Arc::new(state.clone()), event.id, user_id)
            .await
        {
            warn!(event_id = %event.id, error = %e, "Failed to delete chronicle event embeddings during purge");
        }
    }
    
    info!("Purged {} existing chronicle events", events_count);
    Ok(events_count)
}

/// Filter messages by the specified index range
fn filter_messages_by_range(
    messages: Vec<ChatMessage>,
    start_idx: usize,
    end_idx: Option<usize>,
) -> Vec<ChatMessage> {
    let end_idx = end_idx.unwrap_or(messages.len());
    
    messages
        .into_iter()
        .enumerate()
        .filter(|(idx, _)| *idx >= start_idx && *idx < end_idx)
        .map(|(_, msg)| msg)
        .collect()
}

/// Process messages using the streaming pipeline approach
async fn process_messages_with_streaming_pipeline(
    state: &AppState,
    user: &crate::models::users::User,
    chronicle_id: Uuid,
    session_dek: &SessionDek,
    request: &ReChronicleRequest,
    messages_to_process: Vec<ChatMessage>,
) -> Result<(usize, usize, usize), AppError> {
    // Configuration for batching and concurrency
    // Note: Currently using sequential processing for chronological order
    
    // Create bounded channel for streaming pipeline (1024 capacity provides back-pressure)
    let (tx, rx) = mpsc::channel::<EventDataToInsert>(1024);
    
    // Spawn the database writer task (consumer)
    let db_writer_chronicle_service = ChronicleService::new(state.pool.clone());
    let db_writer_embedding_service = state.embedding_pipeline_service.clone();
    let db_writer_state = state.clone();
    let db_writer_session_dek = session_dek.clone();
    let user_id = user.id;
    
    let db_writer_handle = tokio::spawn(async move {
        db_writer_task(
            rx,
            db_writer_chronicle_service,
            user_id,
            chronicle_id,
            db_writer_session_dek,
            db_writer_embedding_service,
            Arc::new(db_writer_state),
        ).await
    });
    
    // Process batches and send events to the channel (producers)
    let batches: Vec<_> = messages_to_process.chunks(request.batch_size).enumerate().collect();
    
    // Process all batches sequentially to maintain chronological order
    let mut all_events_from_all_batches = Vec::new();
    
    for (batch_idx, batch) in batches {
        info!(
            "Processing batch {} with {} messages (sequential processing for chronological order)",
            batch_idx,
            batch.len()
        );

        let narrative_service = state.narrative_intelligence_service.as_ref()
            .ok_or_else(|| AppError::InternalServerErrorGeneric("Narrative intelligence service not available".to_string()))?;

        let batch_result = narrative_service.process_chat_history_batch_with_execution(
            user.id,
            request.chat_session_id,
            Some(chronicle_id),
            batch.to_vec(),
            &session_dek,
            batch_idx,
            false, // exclude_persona_context for re-chronicle
            request.extraction_model.clone()
                .or_else(|| Some(state.config.agentic_extraction_model.clone())),
        ).await?;
        
        // Stage 2: Dynamic AI Triage - Lowered threshold to increase sensitivity
        let confidence_threshold = 0.1; // Drastically lowered from state.config.rechronicle_confidence_threshold
        if !batch_result.is_significant && (batch_result.confidence as f32) < confidence_threshold {
            info!(
                "Batch {} discarded by AI triage. Significance: {}, Confidence: {:.2}",
                batch_idx, batch_result.is_significant, batch_result.confidence
            );
            continue;
        }

        info!(
            "Batch {} execution complete: {} events ready for chronological sorting from {} messages",
            batch_idx,
            batch_result.events.len(),
            batch.len()
        );
        
        // Collect events from this batch
        all_events_from_all_batches.extend(batch_result.events);
    }
    
    // Sort ALL events by timestamp to ensure perfect chronological order
    all_events_from_all_batches.sort_by_key(|event| event.timestamp);
    
    info!(
        "Collected and sorted {} total events from all batches by timestamp",
        all_events_from_all_batches.len()
    );
    
    // Send sorted events to the streaming pipeline in chronological order
    for event_data in all_events_from_all_batches {
        if tx.send(event_data).await.is_err() {
            error!("DB writer task has shut down, cannot send event");
            break;
        }
    }
    
    // Drop the original sender to signal the end of producers
    drop(tx);
    
    // Wait for the DB writer to finish processing all events
    let (events_created, messages_processed, ecs_entities_created) = match db_writer_handle.await {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(AppError::InternalServerErrorGeneric("DB writer task panicked".into())),
    };
    
    Ok((events_created, messages_processed, ecs_entities_created))
}

/// Build a summary string for the re-chronicle operation
fn build_summary(events_created: usize, messages_processed: usize, events_purged: usize, ecs_entities_created: Option<usize>) -> String {
    let mut summary = format!(
        "Re-chronicling complete: {} events created from {} messages{}",
        events_created,
        messages_processed,
        if events_purged > 0 { format!(", {} existing events purged", events_purged) } else { String::new() }
    );
    
    // Add ECS entity count if available
    if let Some(ecs_count) = ecs_entities_created {
        if ecs_count > 0 {
            summary.push_str(&format!(", {} ECS entities generated", ecs_count));
        }
    }
    
    summary
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

/// Stage 1: Heuristic Pre-Filter for message batches.
fn is_batch_heuristically_significant(batch: &[ChatMessage], session_dek: &SessionDek) -> bool {
    const MIN_WORD_COUNT: usize = 10;
    let total_words: usize = batch.iter().map(|m| {
        m.decrypt_content_field(&session_dek.0)
            .map(|content| content.split_whitespace().count())
            .unwrap_or(0)
    }).sum();

    if total_words < MIN_WORD_COUNT {
        return false;
    }

    // Additional checks can be added here (e.g., dialogue presence, actor count)

    true
}

/// Database writer task that consumes events from the channel and batches them for insertion
async fn db_writer_task(
    mut receiver: mpsc::Receiver<EventDataToInsert>,
    chronicle_service: ChronicleService,
    user_id: Uuid,
    chronicle_id: Uuid,
    session_dek: crate::auth::session_dek::SessionDek,
    embedding_pipeline_service: Arc<dyn crate::services::embeddings::EmbeddingPipelineServiceTrait + Send + Sync>,
    app_state: Arc<AppState>,
) -> Result<(usize, usize, usize), AppError> {
    let mut events_created = 0;
    let mut messages_processed = 0;
    let mut ecs_entities_created = 0;
    
    // Collect all events first, then sort by timestamp for proper chronological order
    let mut all_events = Vec::new();
    
    // Collect all events from the channel
    while let Some(event_data) = receiver.recv().await {
        all_events.push(event_data);
    }
    
    // Sort events by timestamp to ensure chronological order
    all_events.sort_by_key(|event| event.timestamp);
    
    info!(
        "DB writer processing {} events in chronological order for chronicle {}",
        all_events.len(),
        chronicle_id
    );
    
    // Process events in chronological order
    for event_data in all_events {
        messages_processed += 1;
        
        info!(
            "DB writer inserting chronicle event: {} ({}) at {}",
            event_data.summary,
            event_data.event_type,
            event_data.timestamp.format("%Y-%m-%d %H:%M:%S")
        );
        
        let create_request = CreateEventRequest {
            event_type: event_data.event_type,
            summary: event_data.summary,
            source: EventSource::AiExtracted,
            event_data: event_data.event_data,
            timestamp_iso8601: Some(event_data.timestamp), // Use the event timestamp from the data
        };
        
        match chronicle_service.create_event(user_id, chronicle_id, create_request, Some(&session_dek)).await {
            Ok(event) => {
                events_created += 1;
                
                // Embed the chronicle event for semantic search
                if let Err(e) = embedding_pipeline_service
                    .process_and_embed_chronicle_event(app_state.clone(), event.clone(), Some(&session_dek))
                    .await
                {
                    warn!(event_id = %event.id, error = %e, "Failed to embed chronicle event, but event was created successfully");
                } else {
                    info!(event_id = %event.id, "Successfully embedded chronicle event for semantic search");
                }
                
                // NEW: Generate ECS entities if feature flag is enabled
                if app_state.feature_flags.enable_ecs_enhanced_rag {
                    info!(event_id = %event.id, "Starting ECS entity generation for chronicle event");
                    
                    match app_state.chronicle_ecs_translator.translate_event(&event, user_id).await {
                        Ok(translation_result) => {
                            let entities_count = translation_result.entities_created.len();
                            let components_count = translation_result.component_updates.len();
                            let relationships_count = translation_result.relationship_updates.len();
                            
                            ecs_entities_created += entities_count;
                            
                            info!(
                                event_id = %event.id,
                                entities_created = entities_count,
                                components_updated = components_count,
                                relationships_updated = relationships_count,
                                "Successfully generated ECS entities from chronicle event"
                            );
                            
                            // Log any translation messages (warnings, etc.)
                            for message in &translation_result.messages {
                                info!(event_id = %event.id, translation_message = %message, "ECS translation message");
                            }
                        },
                        Err(e) => {
                            warn!(
                                event_id = %event.id, 
                                error = %e, 
                                "Failed to generate ECS entities from chronicle event, but event was created successfully"
                            );
                            // Continue processing - ECS generation failure doesn't break the chronicle creation
                        }
                    }
                } else {
                    debug!(event_id = %event.id, "ECS enhanced RAG is disabled, skipping entity generation");
                }
            },
            Err(e) => {
                error!("Failed to create chronicle event during streaming insertion: {}", e);
                // Continue with other events even if one fails
            }
        }
    }
    
    info!(
        "DB writer task completed: {} events created from {} messages, {} ECS entities generated", 
        events_created, 
        messages_processed,
        ecs_entities_created
    );
    Ok((events_created, messages_processed, ecs_entities_created))
}

// --- ECS-Enhanced Hybrid Query Handlers (Phase 4.2.3) ---

/// Get current entity states for a chronicle
/// 
/// This endpoint provides current ECS entity states that are relevant to the chronicle,
/// supporting two modes:
/// 1. Simple listing mode (no query param): Direct entity listing for UI navigation
/// 2. AI-driven search mode (with query param): Hybrid query for agentic pipeline
#[instrument(skip(auth_session, state))]
async fn get_chronicle_entities(
    auth_session: AuthSession<AuthBackend>,
    State(state): State<AppState>,
    Path(chronicle_id): Path<Uuid>,
    Query(params): Query<HybridQueryParams>,
) -> Result<Json<ChronicleEntitiesResponse>, AppError> {
    let user = auth_session.user.ok_or_else(|| {
        error!("No authenticated user found in session");
        AppError::Unauthorized("Authentication required".to_string())
    })?;

    info!("Getting entities for chronicle {} by user {}", chronicle_id, user.id);

    // Verify chronicle ownership
    let chronicle_service = ChronicleService::new(state.pool.clone());
    let _chronicle = chronicle_service.get_chronicle(user.id, chronicle_id).await?;

    // Check if this is a simple listing (no query) or AI-driven search (with query)
    let is_ai_search = params.query.is_some();
    let entities = if is_ai_search {
        // AI-driven search mode for agentic pipeline
        info!("Using AI-driven search mode for chronicle entities");
        
        // Create hybrid query service
        let hybrid_service = create_hybrid_query_service(&state).await?;

        // Build hybrid query to find entities in this chronicle
        let query = HybridQuery {
            query_type: HybridQueryType::NarrativeQuery {
                query_text: params.query.unwrap_or_else(|| "Find all entities and characters in this chronicle".to_string()),
                focus_entities: None,
                time_range: None,
            },
            user_id: user.id,
            chronicle_id: Some(chronicle_id),
            max_results: params.limit.unwrap_or(50),
            include_current_state: params.include_current_state,
            include_relationships: params.include_relationships,
            options: HybridQueryOptions {
                use_cache: true,
                include_timelines: false, // We don't need timelines for this endpoint
                analyze_relationships: params.include_relationships,
                confidence_threshold: params.confidence_threshold.unwrap_or(0.6),
            },
        };

        // Execute the hybrid query
        let result = hybrid_service.execute_hybrid_query(query).await?;

        // Extract entity states from the result
        result.entities
            .into_iter()
            .filter_map(|entity_context| entity_context.current_state)
            .collect()
    } else {
        // Simple listing mode for UI navigation
        info!("Using simple listing mode for chronicle entities");
        
        // Use direct entity manager query
        let entity_manager = state.ecs_entity_manager.clone();
        let entity_results = entity_manager
            .get_entities_by_chronicle(user.id, chronicle_id, params.limit)
            .await?;

        // Convert ECS entity results to EntityStateSnapshot format
        let mut entities = Vec::new();
        for entity_result in entity_results {
            let snapshot = EntityStateSnapshot {
                entity_id: entity_result.entity.id,
                archetype_signature: entity_result.entity.archetype_signature,
                components: entity_result.components.into_iter().map(|comp| {
                    (comp.component_type, comp.component_data)
                }).collect(),
                snapshot_time: entity_result.entity.updated_at,
                status_indicators: vec![], // Empty for now, could be populated based on component data
            };
            entities.push(snapshot);
        }

        entities
    };

    let metadata = ChronicleEntitiesMetadata {
        total_entities: entities.len(),
        ecs_enhanced: true, // We know ECS is available since we're using the entity manager
        warnings: vec![],
    };

    let response = ChronicleEntitiesResponse {
        chronicle_id,
        entities,
        metadata,
    };

    info!("Retrieved {} entities for chronicle {} (mode: {})", 
          response.entities.len(), chronicle_id, 
          if is_ai_search { "AI-search" } else { "simple-listing" });
    Ok(Json(response))
}

/// Get chronicle events timeline for a specific entity
/// 
/// This endpoint provides the chronicle events involving a specific entity,
/// along with current entity state if available from ECS.
#[instrument(skip(auth_session, state))]
async fn get_entity_timeline(
    auth_session: AuthSession<AuthBackend>,
    State(state): State<AppState>,
    Path(entity_id): Path<Uuid>,
    Query(params): Query<HybridQueryParams>,
) -> Result<Json<EntityTimelineResponse>, AppError> {
    info!("=== GET_ENTITY_TIMELINE HANDLER CALLED ===");
    info!("Entity ID: {}", entity_id);
    
    let user = auth_session.user.ok_or_else(|| {
        error!("No authenticated user found in session");
        AppError::Unauthorized("Authentication required".to_string())
    })?;

    info!("Getting timeline for entity {} by user {}", entity_id, user.id);

    // Create hybrid query service
    let hybrid_service = create_hybrid_query_service(&state).await?;

    // Build hybrid query to get entity timeline
    let query = HybridQuery {
        query_type: HybridQueryType::EntityTimeline {
            entity_name: "entity".to_string(), // Placeholder, will be resolved by entity_id
            entity_id: Some(entity_id),
            include_current_state: params.include_current_state,
        },
        user_id: user.id,
        chronicle_id: None, // Will search across all user's chronicles
        max_results: params.limit.unwrap_or(100),
        include_current_state: params.include_current_state,
        include_relationships: params.include_relationships,
        options: HybridQueryOptions {
            use_cache: true,
            include_timelines: true,
            analyze_relationships: params.include_relationships,
            confidence_threshold: params.confidence_threshold.unwrap_or(0.6),
        },
    };

    // Execute the hybrid query
    let result = hybrid_service.execute_hybrid_query(query).await?;

    // Extract timeline events and current state
    let chronicle_events = result.chronicle_events;
    let current_state = result.entities
        .first()
        .and_then(|entity| entity.current_state.clone());

    let metadata = EntityTimelineMetadata {
        total_events: chronicle_events.len(),
        ecs_enhanced: !result.warnings.iter().any(|w| w.contains("ECS unavailable")),
        warnings: result.warnings,
    };

    let response = EntityTimelineResponse {
        entity_id,
        chronicle_events,
        current_state,
        metadata,
    };

    info!("Retrieved {} events for entity {}", response.chronicle_events.len(), entity_id);
    Ok(Json(response))
}

/// Get current relationship graph for a chronicle
/// 
/// This endpoint provides the current relationships between entities in the chronicle,
/// using ECS relationship data when available.
#[instrument(skip(auth_session, state))]
async fn get_chronicle_relationships(
    auth_session: AuthSession<AuthBackend>,
    State(state): State<AppState>,
    Path(chronicle_id): Path<Uuid>,
    Query(params): Query<HybridQueryParams>,
) -> Result<Json<ChronicleRelationshipsResponse>, AppError> {
    let user = auth_session.user.ok_or_else(|| {
        error!("No authenticated user found in session");
        AppError::Unauthorized("Authentication required".to_string())
    })?;

    info!("Getting relationships for chronicle {} by user {}", chronicle_id, user.id);

    // Verify chronicle ownership
    let chronicle_service = ChronicleService::new(state.pool.clone());
    let _chronicle = chronicle_service.get_chronicle(user.id, chronicle_id).await?;

    // Create hybrid query service
    let hybrid_service = create_hybrid_query_service(&state).await?;

    // Build hybrid query to find relationships in this chronicle
    let query = HybridQuery {
        query_type: HybridQueryType::NarrativeQuery {
            query_text: "Find all relationships and interactions between characters".to_string(),
            focus_entities: None,
            time_range: None,
        },
        user_id: user.id,
        chronicle_id: Some(chronicle_id),
        max_results: params.limit.unwrap_or(100),
        include_current_state: false, // We focus on relationships, not entity states
        include_relationships: true,
        options: HybridQueryOptions {
            use_cache: true,
            include_timelines: false,
            analyze_relationships: true,
            confidence_threshold: params.confidence_threshold.unwrap_or(0.6),
        },
    };

    // Execute the hybrid query
    let result = hybrid_service.execute_hybrid_query(query).await?;

    // Extract relationships from the result
    let relationships: Vec<RelationshipContext> = result.entities
        .into_iter()
        .flat_map(|entity_context| entity_context.relationships)
        .collect();

    let metadata = ChronicleRelationshipsMetadata {
        total_relationships: relationships.len(),
        ecs_enhanced: !result.warnings.iter().any(|w| w.contains("ECS unavailable")),
        warnings: result.warnings,
    };

    let response = ChronicleRelationshipsResponse {
        chronicle_id,
        relationships,
        metadata,
    };

    info!("Retrieved {} relationships for chronicle {}", response.relationships.len(), chronicle_id);
    Ok(Json(response))
}

/// Helper function to get hybrid query service from shared AppState
async fn create_hybrid_query_service(state: &AppState) -> Result<HybridQueryService, AppError> {
    // Simply return a clone of the shared hybrid query service from AppState
    // This eliminates the anti-pattern of creating new service instances
    Ok((*state.hybrid_query_service).clone())
}