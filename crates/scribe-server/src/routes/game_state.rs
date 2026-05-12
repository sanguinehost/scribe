use crate::auth::token_auth::UnifiedAuth;
use crate::db::DbId;
use crate::errors::AppError;
use crate::models::game_state::GameState;
use crate::schema::chat_sessions;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    routing::put,
    Json, Router,
};
use diesel::prelude::*;
use regex::Regex;
use serde::Deserialize;
use tracing::{error, info, instrument, warn};
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateGameStatePayload {
    pub game_state: GameState,
}

pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route(
            "/sessions/{session_id}/game-state",
            put(update_game_state_handler),
        )
        .with_state(state)
}

#[instrument(skip_all, fields(session_id = %session_id_str))]
pub async fn update_game_state_handler(
    State(state): State<AppState>,
    auth: UnifiedAuth,
    Path(session_id_str): Path<String>,
    Json(payload): Json<UpdateGameStatePayload>,
) -> Result<Json<GameState>, AppError> {
    let user = auth
        .user()
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user_id = user.id;

    let session_id = DbId::parse_str(&session_id_str)
        .map_err(|_| AppError::BadRequest("Invalid session ID".to_string()))?;

    // 1. Authorization: Check session ownership
    let is_owner = crate::db::with_conn(&state.pool, move |db_conn| {
        chat_sessions::table
            .filter(chat_sessions::id.eq(session_id))
            .filter(chat_sessions::user_id.eq(user_id))
            .select(chat_sessions::id)
            .first::<DbId>(db_conn)
            .optional()
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await?
    .is_some();

    if !is_owner {
        warn!(%session_id, %user_id, "Unauthorized attempt to update game state");
        return Err(AppError::Forbidden("Access denied".to_string()));
    }

    // 2. Validation & Sanitization
    let mut sanitized_state = payload.game_state;
    validate_and_sanitize_game_state(&mut sanitized_state)?;

    // 3. Persist new state
    let game_state_service =
        crate::services::game_state_service::GameStateService::new(state.pool.clone());
    game_state_service
        .manual_update(session_id, sanitized_state.clone())
        .await?;

    info!(%session_id, "Game state manually updated by user");
    Ok(Json(sanitized_state))
}

fn validate_and_sanitize_game_state(state: &mut GameState) -> Result<(), AppError> {
    // OWASP LLM10 - Unbounded Consumption: Check overall size
    let state_json = serde_json::to_string(state).unwrap_or_default();
    if state_json.len() > 1024 * 1024 {
        // 1MB limit
        return Err(AppError::PayloadTooLarge(
            "Game state too large".to_string(),
        ));
    }

    // Sanitize Location
    if let Some(loc) = &mut state.location {
        loc.id = sanitize_string(&loc.id, 512)?;
        loc.name = sanitize_string(&loc.name, 512)?;
        if let Some(region) = &mut loc.region {
            *region = sanitize_string(region, 512)?;
        }
    }

    // Sanitize Inventory
    for item in &mut state.inventory {
        item.id = sanitize_string(&item.id, 512)?;
        item.name = sanitize_string(&item.name, 512)?;
        if let Some(cat) = &mut item.category {
            *cat = sanitize_string(cat, 256)?;
        }
    }

    // Sanitize Quests
    for quest in &mut state.quests {
        quest.id = sanitize_string(&quest.id, 512)?;
        quest.title = sanitize_string(&quest.title, 1024)?;
        if let Some(giver) = &mut quest.giver {
            *giver = sanitize_string(giver, 512)?;
        }
    }

    // Sanitize NPCs
    for npc in state.npcs.values_mut() {
        npc.id = sanitize_string(&npc.id, 512)?;
        npc.name = sanitize_string(&npc.name, 512)?;
        npc.disposition = sanitize_string(&npc.disposition, 256)?;
        npc.status = sanitize_string(&npc.status, 256)?;
        npc.role = sanitize_string(&npc.role, 512)?;
        if let Some(desc) = &mut npc.description {
            *desc = sanitize_string(desc, 4096)?;
        }
        if let Some(pers) = &mut npc.personality {
            *pers = sanitize_string(pers, 4096)?;
        }
        if let Some(map) = npc.data.as_object_mut() {
            for val in map.values_mut() {
                if let Some(s) = val.as_str() {
                    *val = serde_json::Value::String(sanitize_string(s, 4096)?);
                }
            }
        }
    }

    // Validate Time
    if let Some(time) = &mut state.game_time {
        if time.hour > 23 {
            return Err(AppError::BadRequest("Invalid hour".into()));
        }
        if time.minute > 59 {
            return Err(AppError::BadRequest("Invalid minute".into()));
        }
        if time.second > 59 {
            return Err(AppError::BadRequest("Invalid second".into()));
        }

        // Sanitize time strings
        time.period = sanitize_string(&time.period, 256)?;
        if let Some(season) = &mut time.season {
            *season = sanitize_string(season, 256)?;
        }
        time.calendar_system = sanitize_string(&time.calendar_system, 256)?;
        time.date = sanitize_string(&time.date, 512)?;
        if let Some(weekday) = &mut time.weekday {
            *weekday = sanitize_string(weekday, 256)?;
        }
    }

    // Validate Vitals
    for (name, vital) in &state.vitals {
        if vital.current > vital.max {
            return Err(AppError::BadRequest(format!(
                "Vital {} current exceeds max",
                name
            )));
        }
    }

    // Sanitize Quests Objectives
    for quest in &mut state.quests {
        for objective in &mut quest.objectives {
            if let Some(desc) = objective.description.as_str() {
                objective.description = serde_json::Value::String(sanitize_string(desc, 1024)?);
            }
        }
    }

    Ok(())
}

fn sanitize_string(s: &str, max_len: usize) -> Result<String, AppError> {
    if s.len() > max_len {
        return Err(AppError::BadRequest(format!(
            "String too long (max {max_len})"
        )));
    }

    // LLM01 - Prompt Injection detection
    let injection_patterns = [
        r"(?i)ignore\s+(?:previous|all|the|all\s+previous)\s+(?:instructions?|prompts?|rules?)",
        r"(?i)forget\s+(?:everything|all|previous)",
        r"(?i)new\s+(?:instructions?|rules?|system)",
        r"(?i)act\s+as\s+(?:admin|root|system)",
        r"(?i)you\s+are\s+no\s+longer\s+(?:bound|limited|restricted)",
    ];

    for pattern in injection_patterns {
        let re = Regex::new(pattern).map_err(|e| {
            error!("Regex compilation error: {}", e);
            AppError::InternalServerErrorGeneric("Internal security error".to_string())
        })?;
        if re.is_match(s) {
            warn!("Potential prompt injection detected in manual input: {}", s);
            return Err(AppError::BadRequest(
                "Potential prompt injection detected".to_string(),
            ));
        }
    }

    // Basic XSS prevention: remove control characters but allow Unicode
    // We allow anything that is NOT a control character (0-31, 127, etc.)
    // This preserves emojis and non-Latin scripts
    let sanitized: String = s
        .chars()
        .filter(|&c| !c.is_control() || c.is_whitespace())
        .collect();

    Ok(sanitized)
}
