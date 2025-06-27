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
use std::sync::Arc;
use tracing::{error, info, instrument, warn};
use uuid::Uuid;
use validator::Validate;

use crate::{
    auth::{
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