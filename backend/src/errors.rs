// backend/src/errors.rs
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Custom Error type for the application.
/// Wraps various error types and maps them to appropriate HTTP status codes.
#[derive(Error, Debug)]
pub enum AppError {
    #[error("Internal Server Error")]
    InternalServerError(#[from] anyhow::Error),

    #[error("Database error: {0}")]
    DatabaseError(#[from] diesel::result::Error),

    #[error("Database pool error: {0}")]
    DbPoolError(#[from] diesel::r2d2::PoolError),

    #[error("Not Found: {0}")]
    NotFound(String),

    #[error("Bad Request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Character parsing error: {0}")]
    CharacterParseError(#[from] crate::services::character_parser::ParserError),

    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Multipart error: {0}")]
    MultipartError(#[from] axum::extract::multipart::MultipartError),

    #[error("Invalid UUID: {0}")]
    UuidError(#[from] uuid::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::InternalServerError(ref err) => {
                tracing::error!("Internal Server Error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error".to_string(),
                )
            }
            AppError::DatabaseError(ref err) => {
                tracing::error!("Database Error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "A database error occurred".to_string(),
                )
            }
            AppError::DbPoolError(ref err) => {
                tracing::error!("DB Pool Error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Could not acquire database connection".to_string(),
                )
            }
            AppError::NotFound(ref message) => (StatusCode::NOT_FOUND, message.clone()),
            AppError::BadRequest(ref message) => (StatusCode::BAD_REQUEST, message.clone()),
            AppError::Unauthorized(ref message) => (StatusCode::UNAUTHORIZED, message.clone()),
            AppError::Forbidden(ref message) => (StatusCode::FORBIDDEN, message.clone()),
            AppError::CharacterParseError(ref err) => {
                tracing::warn!("Character parsing failed: {}", err);
                (StatusCode::BAD_REQUEST, format!("Character parsing failed: {}", err))
            }
            AppError::IoError(ref err) => {
                tracing::error!("IO Error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An input/output error occurred".to_string(),
                )
            }
            AppError::MultipartError(ref err) => {
                tracing::error!("Multipart Error: {:?}", err);
                 (
                    StatusCode::BAD_REQUEST,
                    format!("Failed to process multipart form data: {}", err),
                )
            }
             AppError::UuidError(ref err) => {
                tracing::error!("UUID Error: {:?}", err);
                 (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid identifier format: {}", err),
                )
            }
        };

        // Fix: Use correct json! macro syntax
        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

pub type Result<T, E = AppError> = std::result::Result<T, E>;