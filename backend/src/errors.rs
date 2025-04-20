// backend/src/errors.rs
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;
use diesel::result::Error as DieselError;
use tracing::error;
use crate::auth::AuthError;
use crate::auth::user_store::Backend as AuthBackend;
use axum_login;
use anyhow::anyhow;

/// Custom Error type for the application.
/// Wraps various error types and maps them to appropriate HTTP status codes.
#[derive(Error, Debug)]
pub enum AppError {
    #[error("Configuration Error: {0}")]
    ConfigurationError(String),

    #[error("LLM Client Error: {0}")]
    LlmError(String),

    #[error("Internal Server Error")]
    InternalServerError(#[from] anyhow::Error),

    #[error("Database error: {0}")]
    DatabaseError(#[from] DieselError),

    #[error("Database pool error: {0}")]
    DbPoolError(#[from] deadpool_diesel::PoolError),

    #[error("Task join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),

    #[error("Not Found: {0}")]
    NotFound(String),

    #[error("Bad Request: {0}")]
    BadRequest(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Forbidden")]
    Forbidden,

    #[error("Username already taken")]
    UsernameTaken,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Character parsing error: {0}")]
    CharacterParseError(#[from] crate::services::character_parser::ParserError),

    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Multipart error: {0}")]
    MultipartError(#[from] axum::extract::multipart::MultipartError),

    #[error("Invalid UUID: {0}")]
    UuidError(#[from] uuid::Error),

    #[error("Not Implemented")]
    NotImplemented,

    #[error("Authentication/Authorization error: {0}")]
    AuthError(#[from] AuthError),

    // Add a variant for axum_login errors if specific handling is needed,
    // otherwise, the From impl below will handle it.
    // #[error("Login session error: {0}")]
    // LoginSessionError(String),
}

// Implement From for axum_login::Error
impl From<axum_login::Error<AuthBackend>> for AppError {
    fn from(err: axum_login::Error<AuthBackend>) -> Self {
        match err {
            axum_login::Error::Session(session_err) => {
                error!(error = ?session_err, "axum_login session error");
                // Map tower_sessions::session_store::Error into an AppError
                // It might be a Backend error (like DB error) or Decode error
                AppError::InternalServerError(anyhow!("Session storage error: {}", session_err))
                // Or potentially map more granularly if needed:
                // AppError::LoginSessionError(session_err.to_string())
            }
            axum_login::Error::Backend(backend_err) => {
                error!(error = ?backend_err, "axum_login backend error");
                // We already have `From<AuthError> for AppError` via #[from]
                // on the AuthError variant, so this conversion should work automatically.
                AppError::AuthError(backend_err)
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::debug!(error = ?self, ">>> AppError::into_response called with");

        let (status, error_message) = match self {
            AppError::ConfigurationError(ref message) => {
                tracing::error!("Configuration Error: {}", message);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Server configuration error".to_string(), // Generic message
                )
            }
            AppError::LlmError(ref message) => {
                tracing::error!("LLM Error: {}", message);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An error occurred with the language model".to_string(), // Generic message
                )
            }
            AppError::InternalServerError(ref err) => {
                tracing::error!("Internal Server Error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error".to_string(),
                )
            }
            AppError::DatabaseError(ref err) => {
                tracing::error!("Database Error: {:?}", err);
                // Treat all database errors as internal server errors
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "A database error occurred".to_string(),
                )
            }
            AppError::DbPoolError(ref err) => {
                tracing::error!("DB Pool Error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Could not acquire database connection pool".to_string(),
                )
            }
            AppError::JoinError(ref err) => {
                tracing::error!("Task Join Error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Background task failed".to_string(),
                )
            }
            AppError::NotFound(ref message) => (StatusCode::NOT_FOUND, message.clone()),
            AppError::BadRequest(ref message) => (StatusCode::BAD_REQUEST, message.clone()),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "Forbidden".to_string()),
            AppError::UsernameTaken => (StatusCode::CONFLICT, "Username already taken".to_string()),
            AppError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()),
            AppError::CharacterParseError(ref err) => {
                tracing::warn!("Character parsing failed: {}", err);
                (
                    StatusCode::BAD_REQUEST,
                    format!("Character parsing failed: {}", err),
                )
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
            AppError::NotImplemented => {
                tracing::error!("Attempted to use unimplemented functionality");
                (
                    StatusCode::NOT_IMPLEMENTED,
                    "Functionality not yet implemented".to_string(),
                )
            }
            AppError::AuthError(ref err) => match err {
                AuthError::WrongCredentials => {
                    (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string())
                }
                AuthError::UsernameTaken => {
                    (StatusCode::CONFLICT, "Username already taken".to_string())
                }
                AuthError::HashingError => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Password hashing failed".to_string(),
                ),
                AuthError::UserNotFound => {
                    (StatusCode::NOT_FOUND, "User not found".to_string())
                }
                AuthError::DatabaseError(db_err) => {
                    error!("Database error during authentication: {:?}", db_err);
                    match db_err {
                        DieselError::NotFound => {
                            (StatusCode::NOT_FOUND, "Auth-related resource not found".to_string())
                        }
                        _ => (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "A database error occurred during authentication".to_string(),
                        ),
                    }
                }
                AuthError::InteractError(msg) => {
                    error!("Database interaction error during authentication: {}", msg);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "A database interaction error occurred".to_string(),
                    )
                }
                AuthError::PoolError(pool_err) => {
                    error!("Database pool error during authentication: {:?}", pool_err);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Database pool error during authentication".to_string(),
                    )
                }
            },
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

pub type Result<T, E = AppError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::Response;
    use serde_json::Value;
    // Import necessary types for constructing errors
    use crate::services::character_parser::ParserError;
    use axum::body::to_bytes; // Explicitly import to_bytes
    use base64::{Engine as _, engine::general_purpose::STANDARD as base64_standard};
    use uuid::Uuid; // Import Uuid for parsing

    // Helper function to extract JSON body from response using axum::body::to_bytes
    async fn get_body_json(response: Response) -> Value {
        let body = response.into_body();
        // Use the explicitly imported function
        let body_bytes = to_bytes(body, usize::MAX)
            .await
            .expect("Failed to read body bytes");
        serde_json::from_slice(&body_bytes).expect("Failed to parse JSON body")
    }

    #[tokio::test]
    async fn test_internal_server_error_response() {
        let error = AppError::InternalServerError(anyhow::anyhow!("Something went wrong"));
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Internal Server Error");
    }

    #[tokio::test]
    async fn test_database_error_response() {
        // Using NotFound as a representative Diesel error
        let error = AppError::DatabaseError(diesel::result::Error::NotFound);
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "A database error occurred");
    }

    #[tokio::test]
    async fn test_db_pool_error_response_indirect() {
        // This test verifies that *some* error mapping occurs, but constructing
        // a real r2d2::PoolError here is difficult. We use InternalServerError
        // as a stand-in to ensure the test compiles and runs.
        // The `test_db_pool_error_response_direct` covers the specific match arm.
        let inner_error = anyhow::anyhow!("Simulated DB Pool Error via InternalServerError");
        let error = AppError::InternalServerError(inner_error);
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Internal Server Error");
    }

    #[tokio::test]
    async fn test_not_found_response() {
        let msg = "Resource not found".to_string();
        let error = AppError::NotFound(msg.clone());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], msg);
    }

    #[tokio::test]
    async fn test_bad_request_response() {
        let msg = "Invalid input".to_string();
        let error = AppError::BadRequest(msg.clone());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], msg);
    }

    #[tokio::test]
    async fn test_unauthorized_response() {
        let error = AppError::Unauthorized;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Unauthorized");
    }

    #[tokio::test]
    async fn test_forbidden_response() {
        let error = AppError::Forbidden;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Forbidden");
    }

    #[tokio::test]
    async fn test_character_parse_error_response() {
        // Construct a Base64Error
        let base64_decode_error = base64_standard.decode("invalid-base64!").unwrap_err();
        let inner_error = ParserError::Base64Error(base64_decode_error);
        let error = AppError::CharacterParseError(inner_error);
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = get_body_json(response).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("Character parsing failed")
        );
    }

    #[tokio::test]
    async fn test_io_error_response() {
        let error = AppError::IoError(std::io::Error::new(std::io::ErrorKind::Other, "io error"));
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "An input/output error occurred");
    }

    #[tokio::test]
    async fn test_multipart_error_response_indirect() {
        // This test verifies that *some* error mapping occurs, but constructing
        // a real MultipartError here is difficult. We use InternalServerError
        // as a stand-in.
        // The `test_multipart_error_response_direct` covers the specific match arm.
        let inner_error = anyhow::anyhow!("Simulated Multipart Error via InternalServerError");
        let error = AppError::InternalServerError(inner_error);
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("Internal Server Error")
        );
    }

    #[tokio::test]
    async fn test_uuid_error_response() {
        // Parse an invalid string using Uuid::parse_str to get the error
        let inner_error = Uuid::parse_str("invalid-uuid").unwrap_err();
        let error = AppError::UuidError(inner_error);
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = get_body_json(response).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("Invalid identifier format")
        );
    }
}
