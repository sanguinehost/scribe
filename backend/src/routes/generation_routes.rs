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
    EnhancementRequest, EnhancementResult, FieldGenerationRequest, FieldGenerationResult,
    FieldGenerator, FullCharacterGenerator, FullCharacterRequest, FullCharacterResult,
};
use crate::state::AppState;
use axum::{Router, extract::State, http::StatusCode, response::Json, routing::post};
use axum_login::AuthSession;
use std::sync::Arc;
use tracing::{info, instrument};

// Define the type alias for the auth session
type CurrentAuthSession = AuthSession<AuthBackend>;

/// Create the generation router with all endpoints
pub fn router() -> Router<AppState> {
    Router::new()
        // Character generation endpoints
        .route("/character/field", post(generate_character_field_handler))
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
#[instrument(skip_all, fields(field = ?payload.field))]
pub async fn generate_character_field_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    dek: SessionDek, // SECURITY: SessionDek required for decrypting lorebook content
    Json(payload): Json<FieldGenerationRequest>,
) -> Result<Json<FieldGenerationResult>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    info!(
        "Generating field {:?} for user {} (mode: create)",
        payload.field, user.id
    );

    let field_generator = FieldGenerator::new(Arc::new(state));
    let result = field_generator
        .generate_field(payload, user.id, Some(&dek))
        .await?;

    Ok(Json(result))
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
#[instrument(skip_all)]
pub async fn enhance_character_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    Json(payload): Json<EnhancementRequest>,
) -> Result<Json<EnhancementResult>, AppError> {
    Err(AppError::NotImplemented(
        "Character enhancement not yet implemented".to_string(),
    ))
}

// ============================================================================
// Lorebook Generation Handlers
// ============================================================================

/// POST /api/generation/lorebook/entries
///
/// Generate multiple lorebook entries from context/description
#[instrument(skip_all)]
pub async fn generate_lorebook_entries_handler(
    State(_state): State<AppState>,
    auth_session: CurrentAuthSession,
    Json(_payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    let _user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    info!("Generating multiple lorebook entries");

    // TODO: Implement batch lorebook entry generation
    // This will use the LorebookService and AI client to generate multiple entries
    Err(AppError::NotImplemented(
        "Batch lorebook entry generation not yet implemented".to_string(),
    ))
}

/// POST /api/generation/lorebook/entry
///
/// Generate a single lorebook entry from a prompt
#[instrument(skip_all)]
pub async fn generate_lorebook_entry_handler(
    State(_state): State<AppState>,
    auth_session: CurrentAuthSession,
    Json(_payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    let _user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    info!("Generating single lorebook entry");

    // TODO: Implement single lorebook entry generation
    // This will use the LorebookService and AI client to generate an entry
    Err(AppError::NotImplemented(
        "Single lorebook entry generation not yet implemented".to_string(),
    ))
}

// ============================================================================
// Scribe Assistant Handler
// ============================================================================

/// POST /api/generation/scribe-assistant
///
/// Interactive AI assistant for content creation and ideation
#[instrument(skip_all)]
pub async fn scribe_assistant_handler(
    State(_state): State<AppState>,
    auth_session: CurrentAuthSession,
    Json(_payload): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let _user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;

    info!("Scribe assistant chat request");

    // TODO: Implement Scribe assistant chat interface
    // This will provide an interactive AI chat for content creation help
    Err(AppError::NotImplemented(
        "Scribe assistant not yet implemented".to_string(),
    ))
}
