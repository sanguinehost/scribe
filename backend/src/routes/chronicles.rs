// backend/src/routes/chronicles.rs

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use axum_login::AuthSession;
use serde::Deserialize;
use tracing::{error, info, instrument};
use uuid::Uuid;
use validator::Validate;

use crate::{
    auth::{
        session_dek::SessionDek,
        user_store::Backend as AuthBackend,
    },
    errors::AppError,
    models::{
        chronicle::{
            CreateChronicleRequest, PlayerChronicle, PlayerChronicleWithCounts, UpdateChronicleRequest,
        },
        chronicle_event::{ChronicleEvent, CreateEventRequest, EventFilter, EventOrderBy, EventSource},
    },
    services::{
        ChronicleService, 
        EventExtractionService,
        event_extraction_service::ExtractionConfig,
        tokenizer_service::TokenizerService,
        chat::message_handling::get_messages_for_session,
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

/// Request for extracting events from a chat session
#[derive(Debug, Deserialize, Validate)]
pub struct ExtractEventsRequest {
    /// The chat session ID to extract events from
    pub chat_session_id: Uuid,
    /// Starting message index (optional, defaults to 0)
    pub start_message_index: Option<usize>,
    /// Ending message index (optional, extracts from start to end if not provided)
    pub end_message_index: Option<usize>,
    /// Model to use for extraction (defaults to gemini-2.5-flash-lite-preview-06-17)
    pub extraction_model: Option<String>,
}

/// Response for event extraction
#[derive(Debug, serde::Serialize)]
pub struct ExtractEventsResponse {
    /// Number of events extracted
    pub events_extracted: usize,
    /// List of extracted events
    pub events: Vec<ChronicleEvent>,
}

impl From<EventQuery> for EventFilter {
    fn from(query: EventQuery) -> Self {
        Self {
            event_type: query.event_type,
            source: query.source,
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
        .route("/:chronicle_id/extract-events", post(extract_events_from_chat))
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
    let event = chronicle_service.create_event(user.id, chronicle_id, request).await?;

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

    info!("Successfully deleted event {}", event_id);
    Ok(StatusCode::NO_CONTENT)
}

/// Extract events from a chat session
#[instrument(skip(auth_session, state, session_dek))]
async fn extract_events_from_chat(
    auth_session: AuthSession<AuthBackend>,
    State(state): State<AppState>,
    Path(chronicle_id): Path<Uuid>,
    session_dek: SessionDek,
    Json(request): Json<ExtractEventsRequest>,
) -> Result<Json<ExtractEventsResponse>, AppError> {
    // Validate the request
    request.validate()?;
    
    let user = auth_session.user.ok_or_else(|| {
        error!("No authenticated user found in session");
        AppError::Unauthorized("Authentication required".to_string())
    })?;

    info!(
        "Extracting events from chat {} for chronicle {} for user {}",
        request.chat_session_id, chronicle_id, user.id
    );

    // Create services
    let chronicle_service = ChronicleService::new(state.pool.clone());
    let tokenizer_service = TokenizerService::new(&state.config.tokenizer_model_path)?;
    let extraction_service = EventExtractionService::new(
        state.ai_client.clone(),
        tokenizer_service,
        chronicle_service,
    );

    // Configure extraction
    let config = ExtractionConfig {
        model_name: request.extraction_model.unwrap_or_else(|| {
            "gemini-2.5-flash-lite-preview-06-17".to_string()
        }),
        ..Default::default()
    };

    // Fetch messages from the chat session
    info!("Fetching messages for chat session {}...", request.chat_session_id);
    let messages = get_messages_for_session(
        &state.pool,
        user.id,
        request.chat_session_id
    ).await?;

    let total_message_count = messages.len();
    info!("Retrieved {} total messages from chat session", total_message_count);

    // Apply message range filtering if specified
    let filtered_messages = if let (Some(start), Some(end)) = (request.start_message_index, request.end_message_index) {
        if start >= total_message_count || end >= total_message_count || start > end {
            return Err(AppError::BadRequest(format!(
                "Invalid message range: {}-{} for {} total messages",
                start, end, total_message_count
            )));
        }
        info!("Applying message range filter: {}..{}", start, end);
        messages[start..=end].to_vec()
    } else if let Some(start) = request.start_message_index {
        if start >= total_message_count {
            return Err(AppError::BadRequest(format!(
                "Invalid start index: {} for {} total messages",
                start, total_message_count
            )));
        }
        info!("Applying start index filter: {}..", start);
        messages[start..].to_vec()
    } else {
        info!("Using all messages (no filtering applied)");
        messages
    };

    info!(
        "Prepared {} messages for extraction (filtered from {} total)", 
        filtered_messages.len(),
        total_message_count
    );
    
    // Extract events
    info!("Starting event extraction process...");
    let extracted_events = extraction_service
        .extract_events_from_messages(user.id, chronicle_id, filtered_messages, &session_dek, config)
        .await?;

    info!("Event extraction completed successfully");
    let response = ExtractEventsResponse {
        events_extracted: extracted_events.len(),
        events: extracted_events,
    };

    info!("Successfully extracted {} events, returning response", response.events_extracted);
    Ok(Json(response))
}