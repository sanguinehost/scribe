use crate::auth::AuthBackend;
use crate::errors::AppError;
use crate::privacy::logging::loggable_user_id;
use crate::state::AppState;
use axum::{extract::State, Json};
use axum_login::AuthSession;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TelemetryPayload {
    pub component: String,
    pub error_message: String,
    pub route: String,
    pub severity: String, // "error", "fatal", "warning"
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TelemetryResponse {
    pub success: bool,
}

/// Ingests telemetry metrics and errors from the Frontend (SvelteKit client)
/// Applies the current user's active session context automatically via privacy wrappers
#[tracing::instrument(skip(_state, payload))]
pub async fn ingest_telemetry(
    State(_state): State<AppState>,
    auth: AuthSession<AuthBackend>,
    Json(payload): Json<TelemetryPayload>,
) -> Result<Json<TelemetryResponse>, AppError> {
    // Obfuscate the user ID if present, else tag as unauthenticated
    let log_id = if let Some(user) = auth.user {
        loggable_user_id(user.id).to_string()
    } else {
        "unauthenticated".to_string()
    };

    // Emit a highly structured generic event that OpenObserve can group
    tracing::error!(
        event_type = "frontend_client_error",
        frontend_component = %payload.component,
        frontend_route = %payload.route,
        severity = %payload.severity,
        client_user_id = %log_id,
        "Frontend UI Error: {}", payload.error_message
    );

    Ok(Json(TelemetryResponse { success: true }))
}
