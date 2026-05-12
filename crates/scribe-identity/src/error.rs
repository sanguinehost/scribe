use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database query failed: {0}")]
    DatabaseQueryError(String),
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Forbidden: {0}")]
    Forbidden(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Internal server error: {0}")]
    InternalServerError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            AppError::DatabaseQueryError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Database query error: {}", msg)),
            AppError::UserNotFound => (StatusCode::NOT_FOUND, "User not found".to_string()),
            AppError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::InternalServerError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

impl From<scribe_core::CoreError> for AppError {
    fn from(error: scribe_core::CoreError) -> Self {
        match error {
            scribe_core::CoreError::Internal(msg) => AppError::InternalServerError(msg),
            scribe_core::CoreError::NotFound(_) | scribe_core::CoreError::ResourceNotFound(_) | scribe_core::CoreError::UserNotFound => AppError::UserNotFound,
            scribe_core::CoreError::Unauthorized(msg) => AppError::Unauthorized(msg),
            scribe_core::CoreError::InvalidCredentials => AppError::InvalidCredentials,
            scribe_core::CoreError::Forbidden(msg) => AppError::Forbidden(msg),
            scribe_core::CoreError::BadRequest(msg) | scribe_core::CoreError::ValidationError(msg) => AppError::InternalServerError(format!("Bad request: {}", msg)),
            scribe_core::CoreError::Conflict(msg) => AppError::InternalServerError(format!("Conflict: {}", msg)),
            scribe_core::CoreError::UsernameTaken => AppError::InternalServerError("Conflict: Username taken".to_string()),
            scribe_core::CoreError::EmailTaken => AppError::InternalServerError("Conflict: Email taken".to_string()),
            scribe_core::CoreError::RateLimited(_) => AppError::InternalServerError("Rate limited".to_string()),
            scribe_core::CoreError::NotImplemented(msg) => AppError::InternalServerError(format!("Not implemented: {}", msg)),
            scribe_core::CoreError::Timeout(msg) => AppError::InternalServerError(format!("Timeout: {}", msg)),
        }
    }
}
