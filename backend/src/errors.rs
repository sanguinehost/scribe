// backend/src/errors.rs
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;
use tracing::error;
use validator::ValidationErrors;

// Corrected and Consolidated Imports
use crate::auth::user_store::Backend as AuthBackend;
use crate::services::character_parser::ParserError as CharacterParserError; // Alias for clarity
use anyhow::Error as AnyhowError;
use bcrypt; // Use bcrypt directly
use deadpool_diesel::PoolError as DeadpoolDieselPoolError; // Removed unused InteractError
use diesel::result::Error as DieselError;

// AppError should automatically be Send + Sync if all its fields are.
// Remove Send and Sync from derive list.
#[derive(Error, Debug, Clone)]
pub enum AppError {
    // --- Authentication/Authorization Errors ---
    #[error("User not found")]
    UserNotFound, // Often used in auth flows

    // --- Gateway Errors ---
    #[error("Bad Gateway: {0}")]
    BadGateway(String), // For external service errors

    #[error("Invalid credentials")]
    InvalidCredentials, // Specific auth error

    #[error("Password hashing failed: {0}")]
    PasswordHashingFailed(String), // Change to String instead of BcryptError

    #[error("Username is already taken")]
    UsernameTaken, // Specific registration error

    #[error("Email is already taken")]
    EmailTaken, // Add Email Taken variant

    #[error("Unauthorized: {0}")]
    Unauthorized(String), // General unauthorized access

    #[error("Forbidden")]
    Forbidden, // Access denied despite authentication

    #[error("Authentication framework error: {0}")]
    AuthError(String), // Use String instead of the full error type

    #[error("Session store error: {0}")]
    SessionStoreError(String), // Use String instead of tower_sessions::session_store::Error

    #[error("Session not found")] // Added SessionNotFound variant
    SessionNotFound,

    #[error("Cryptography error: {0}")]
    CryptoError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Session operation error: {0}")]
    SessionError(String),

    // --- Database Errors ---
    #[error("Database query error: {0}")]
    DatabaseQueryError(String), // Use String instead of DieselError

    #[error("Database pool error: {0}")]
    DbPoolError(String), // Use String instead of DeadpoolDieselPoolError

    #[error("Database managed pool error: {0}")]
    DbManagedPoolError(String), // Use String instead of DeadpoolManagedPoolError

    #[error("Database pool build error: {0}")]
    DbPoolBuildError(String), // Use String instead of DeadpoolBuildError

    #[error("Database interaction error (deadpool): {0}")]
    DbInteractError(String), // Use String instead of DeadpoolInteractError

    #[error("Database migration error: {0}")]
    DbMigrationError(String), // Use String instead of DieselMigrationError

    // --- Request/Input Errors ---
    #[error("Bad Request: {0}")]
    BadRequest(String),

    #[error("Not Found: {0}")]
    NotFound(String), // Resource not found

    #[error("Conflict: {0}")]
    Conflict(String), // Resource conflict (e.g., duplicate entries)

    #[error("File upload error: {0}")]
    FileUploadError(String), // Use String instead of MultipartError

    #[error("Character parsing error: {0}")]
    CharacterParseError(#[from] CharacterParserError),

    #[error("Invalid Input: {0}")]
    InvalidInput(String),

    #[error("Integer Parsing Error: {0}")]
    ParseIntError(String), // Use String instead of ParseIntError

    #[error("UUID Error: {0}")]
    UuidError(String), // Use String instead of UuidError

    // --- External Service Errors ---
    #[error("LLM API error: {0}")]
    GeminiError(String), // Use String instead of GenAIError

    #[error("Image Processing Error: {0}")]
    ImageProcessingError(String), // Use String instead of ImageError

    #[error("HTTP Request Error: {0}")]
    HttpRequestError(String), // Use String instead of ReqwestError

    #[error("HTTP Middleware Error: {0}")]
    HttpMiddlewareError(String), // Use String instead of ReqwestMiddlewareError

    #[error("LLM Client Error: {0}")]
    LlmClientError(String),

    #[error("Vector DB Error: {0}")]
    VectorDbError(String),

    #[error("AI Service Error: {0}")] // New variant for AI service specific errors
    AiServiceError(String),

    // --- General/Internal Errors ---
    #[error("Configuration Error: {0}")]
    ConfigError(String),

    #[error("IO Error: {0}")]
    IoError(String), // Use String instead of std::io::Error

    #[error("Serialization Error: {0}")]
    SerializationError(String), // Use String instead of serde_json::Error

    #[error("Internal Server Error: {0}")]
    InternalServerErrorGeneric(String), // Renamed from InternalServerError

    #[error("Internal Server Error: Password processing error.")]
    PasswordProcessingError, // New specific variant

    #[error("LLM Generation Error: {0}")] // Maybe wrap specific GenAIError later
    GenerationError(String), // Using String for now if GenAIError covers multiple cases

    #[error("LLM Embedding Error: {0}")] // Maybe wrap specific GenAIError later
    EmbeddingError(String), // Using String for now

    #[error("Session Error: {0}")]
    Session(String), // Use String instead of tower_sessions::session::Error

    // Added RateLimited variant
    #[error("API Rate Limit Exceeded")]
    RateLimited,

    // Added NotImplemented variant
    #[error("Not Implemented: {0}")]
    NotImplemented(String),

    // WebSocket Errors
    #[error("WebSocket send error: {0}")]
    WebSocketSendError(String),
    #[error("WebSocket receive error: {0}")]
    WebSocketReceiveError(String),

    // Chunking Errors (NEW)
    #[error("Text chunking error: {0}")]
    ChunkingError(String),

    // Character Parsing Error (NEW)
    #[error("Character parsing error: {0}")]
    CharacterParsingError(String),

    // Tokenization Error (NEW)
    #[error("Text processing error: {0}")]
    TextProcessingError(String),

    #[error("Validation error: {0}")]
    ValidationError(#[from] ValidationErrors),
}

// This helper enum is necessary because axum_login::Error requires the UserStore::Error
// to implement Clone, but many underlying errors (like DieselError, BcryptError) don't.
// We convert the underlying errors into cloneable string representations here.
#[derive(Error, Debug, Clone)]
pub enum AuthBackendError {
    #[error("Invalid Credentials")]
    InvalidCredentials,
    #[error("User Not Found")]
    UserNotFound,
    #[error("Password Hashing Failed: {0}")]
    PasswordHashingFailed(String), // Store as String
    #[error("Database Query Error: {0}")]
    DbQueryError(String), // Store as String
    #[error("Username Taken")]
    UsernameTaken,
    #[error("Database Pool Error: {0}")]
    // Added for completeness if UserStore interacts with pool directly
    DbPoolError(String),
    #[error("Internal Server Error: {0}")] // Catch-all for other errors
    InternalError(String),
}

// Implement From for errors that UserStore might return, converting them to AuthBackendError
// KEEPING these From impls for AuthBackendError as they are needed for its purpose.
impl From<bcrypt::BcryptError> for AuthBackendError {
    fn from(err: bcrypt::BcryptError) -> Self {
        Self::PasswordHashingFailed(err.to_string())
    }
}

impl From<DieselError> for AuthBackendError {
    fn from(err: DieselError) -> Self {
        match err {
            DieselError::NotFound => Self::UserNotFound, // Map specific Diesel errors
            _ => Self::DbQueryError(err.to_string()),
        }
    }
}

// If UserStore directly interacts with the pool and can return PoolError
impl From<DeadpoolDieselPoolError> for AuthBackendError {
    fn from(err: DeadpoolDieselPoolError) -> Self {
        Self::DbPoolError(err.to_string())
    }
}

// Catch-all for any other error type UserStore might encounter
impl From<AnyhowError> for AuthBackendError {
    fn from(err: AnyhowError) -> Self {
        Self::InternalError(format!("{err:?}")) // Use debug format for full chain
    }
}

// --- From implementations for common errors not handled by #[from] ---

// No need for manual From<...> for AppError anymore,
// as #[from] handles them.

// --- IntoResponse Implementation ---
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            Self::ValidationError(validation_errors) => {
                Self::validation_error_response(&validation_errors)
            }
            app_error => Self::error_to_response(app_error)
        }
    }
}

impl AppError {
    fn validation_error_response(validation_errors: &validator::ValidationErrors) -> Response {
        let status = StatusCode::UNPROCESSABLE_ENTITY;
        let error_message = "Validation error".to_string();

        // Convert validation errors to JSON
        let mut error_details = serde_json::Map::new();
        for (field, errors) in validation_errors.field_errors() {
            let field_errors: Vec<serde_json::Value> = errors
                .iter()
                .map(|error| {
                    let mut err_map = serde_json::Map::new();
                    err_map.insert("code".to_string(), json!(error.code));
                    if let Some(message) = &error.message {
                        err_map.insert("message".to_string(), json!(message));
                    }
                    // Add params if they exist and are useful
                    let params: serde_json::Map<String, serde_json::Value> = error
                        .params
                        .iter()
                        .map(|(k, v)| (k.to_string(), json!(v)))
                        .collect();
                    if !params.is_empty() {
                        err_map.insert("params".to_string(), json!(params));
                    }
                    json!(err_map)
                })
                .collect();
            error_details.insert(field.to_string(), json!(field_errors));
        }

        let body = Json(json!({
            "error": error_message,
            "error_details": error_details
        }));
        (status, body).into_response()
    }

    fn error_to_response(app_error: Self) -> Response {
        let (status, error_message) = Self::get_status_and_message(app_error);
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }

    fn get_status_and_message(app_error: Self) -> (StatusCode, String) {
        match app_error {
            // Handle client errors (4xx)
            err if Self::is_client_error(&err) => Self::handle_client_error(err),
            
            // Handle gateway errors (5xx external services)
            err if Self::is_gateway_error(&err) => Self::handle_gateway_error(err),
            
            // Handle not implemented
            Self::NotImplemented(msg) => {
                error!("Not Implemented: {msg}");
                (StatusCode::NOT_IMPLEMENTED, msg)
            }

            // Handle all server errors (5xx internal)
            _ => Self::handle_internal_server_error(app_error)
        }
    }

    const fn is_client_error(error: &Self) -> bool {
        matches!(error,
            Self::BadRequest(_) |
            Self::InvalidInput(_) |
            Self::InvalidCredentials |
            Self::Unauthorized(_) |
            Self::Forbidden |
            Self::NotFound(_) |
            Self::UserNotFound |
            Self::SessionNotFound |
            Self::Conflict(_) |
            Self::UsernameTaken |
            Self::EmailTaken |
            Self::RateLimited |
            Self::FileUploadError(_) |
            Self::CharacterParseError(_) |
            Self::CharacterParsingError(_) |
            Self::ParseIntError(_) |
            Self::UuidError(_) |
            Self::AuthError(_) |
            Self::WebSocketReceiveError(_)
        )
    }

    const fn is_gateway_error(error: &Self) -> bool {
        matches!(error,
            Self::BadGateway(_) |
            Self::GenerationError(_) |
            Self::EmbeddingError(_) |
            Self::VectorDbError(_)
        )
    }

    fn handle_client_error(app_error: Self) -> (StatusCode, String) {
        match app_error {
            // Simple client errors without logging
            err if Self::is_simple_client_error(&err) => Self::handle_simple_client_error(err),
            
            // Client errors that require logging
            err if Self::is_logged_client_error(&err) => Self::handle_logged_client_error(err),
            
            _ => unreachable!("Non-client error passed to handle_client_error")
        }
    }

    const fn is_simple_client_error(error: &Self) -> bool {
        matches!(error,
            Self::BadRequest(_) |
            Self::InvalidInput(_) |
            Self::InvalidCredentials |
            Self::Unauthorized(_) |
            Self::Forbidden |
            Self::NotFound(_) |
            Self::UserNotFound |
            Self::SessionNotFound |
            Self::Conflict(_) |
            Self::UsernameTaken |
            Self::EmailTaken |
            Self::RateLimited
        )
    }

    const fn is_logged_client_error(error: &Self) -> bool {
        matches!(error,
            Self::AuthError(_) |
            Self::WebSocketReceiveError(_)
        ) || Self::is_file_parsing_error(error)
    }

    fn handle_simple_client_error(app_error: Self) -> (StatusCode, String) {
        match app_error {
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            Self::InvalidInput(msg) => (StatusCode::BAD_REQUEST, format!("Invalid input: {msg}")),
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()),
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            Self::Forbidden => (StatusCode::FORBIDDEN, "Forbidden".to_string()),
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            Self::UserNotFound => (StatusCode::NOT_FOUND, "User not found".to_string()),
            Self::SessionNotFound => (StatusCode::UNAUTHORIZED, "Session not found or expired".to_string()),
            Self::Conflict(msg) => (StatusCode::CONFLICT, msg),
            Self::UsernameTaken => (StatusCode::CONFLICT, "Username is already taken".to_string()),
            Self::EmailTaken => (StatusCode::CONFLICT, "Email is already taken".to_string()),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "API rate limit exceeded. Please try again later.".to_string()),
            _ => unreachable!("Non-simple client error passed to handle_simple_client_error")
        }
    }

    fn handle_logged_client_error(app_error: Self) -> (StatusCode, String) {
        match app_error {
            // File and parsing errors
            err if Self::is_file_parsing_error(&err) => Self::handle_file_parsing_error(err),
            
            // Authentication errors  
            Self::AuthError(e) => {
                error!("Authentication framework error: {e}");
                (StatusCode::UNAUTHORIZED, "Authentication error".to_string())
            }
            
            // WebSocket errors
            Self::WebSocketReceiveError(e) => {
                error!("WebSocket receive error: {e}");
                (StatusCode::BAD_REQUEST, "WebSocket receive error".to_string())
            }
            
            _ => unreachable!("Non-logged client error passed to handle_logged_client_error")
        }
    }

    const fn is_file_parsing_error(error: &Self) -> bool {
        matches!(error,
            Self::FileUploadError(_) |
            Self::CharacterParseError(_) |
            Self::CharacterParsingError(_) |
            Self::ParseIntError(_) |
            Self::UuidError(_)
        )
    }

    fn handle_file_parsing_error(app_error: Self) -> (StatusCode, String) {
        let (log_msg, user_msg) = match app_error {
            Self::FileUploadError(e) => (format!("File upload error: {e}"), "File upload failed"),
            Self::CharacterParseError(e) => (format!("Character parsing error: {e}"), "Failed to parse character data"),
            Self::CharacterParsingError(e) => (format!("Character parsing error: {e}"), "Failed to parse character data"),
            Self::ParseIntError(e) => (format!("Integer parsing error: {e}"), "Invalid numeric value provided"),
            Self::UuidError(e) => (format!("UUID error: {e}"), "Invalid identifier format"),
            _ => unreachable!("Non-file parsing error passed to handle_file_parsing_error")
        };
        
        error!("{}", log_msg);
        (StatusCode::BAD_REQUEST, user_msg.to_string())
    }

    fn handle_gateway_error(app_error: Self) -> (StatusCode, String) {
        let (log_msg, user_msg) = match app_error {
            Self::BadGateway(msg) => (format!("Bad Gateway error: {msg}"), msg),
            Self::GenerationError(e) => (format!("LLM generation error: {e}"), "AI service request failed".to_string()),
            Self::EmbeddingError(e) => (format!("LLM embedding error: {e}"), "AI embedding service request failed".to_string()),
            Self::VectorDbError(e) => (format!("Vector DB error: {e}"), "Failed to process embeddings".to_string()),
            _ => unreachable!("Non-gateway error passed to handle_gateway_error")
        };
        
        error!("{}", log_msg);
        (StatusCode::BAD_GATEWAY, user_msg)
    }

    fn handle_internal_server_error(app_error: Self) -> (StatusCode, String) {
        // Use category-based dispatch to reduce cognitive complexity
        if let Some(result) = Self::try_handle_categorized_error(&app_error) {
            return result;
        }
        
        // Handle remaining generic server errors
        Self::handle_generic_server_error(app_error)
    }

    fn try_handle_categorized_error(app_error: &Self) -> Option<(StatusCode, String)> {
        // Session and authentication errors
        if Self::is_session_error(app_error) {
            return Some(Self::handle_session_error(app_error.clone()));
        }
        
        // Database errors
        if Self::is_database_error(app_error) {
            return Some(Self::handle_database_error(app_error.clone()));
        }
        
        // Cryptographic errors
        if Self::is_crypto_error(app_error) {
            return Some(Self::handle_crypto_error(app_error.clone()));
        }
        
        // AI service errors
        if Self::is_ai_service_error(app_error) {
            return Some(Self::handle_ai_service_error(app_error.clone()));
        }
        
        // HTTP and communication errors
        if Self::is_communication_error(app_error) {
            return Some(Self::handle_communication_error(app_error.clone()));
        }
        
        // Text processing errors
        if Self::is_text_processing_error(app_error) {
            return Some(Self::handle_text_processing_error(app_error.clone()));
        }
        
        None
    }

    fn handle_generic_server_error(app_error: Self) -> (StatusCode, String) {
        match app_error {
            // System/Configuration errors
            err if Self::is_system_config_error(&err) => Self::handle_system_config_error(err),
            
            // Password/Security errors
            Self::PasswordProcessingError => Self::handle_password_processing_error(),
            
            // Generic/Fallback errors
            err => Self::handle_fallback_error(err),
        }
    }

    const fn is_session_error(error: &Self) -> bool {
        matches!(error,
            Self::SessionStoreError(_) |
            Self::SessionError(_) |
            Self::Session(_)
        )
    }

    const fn is_database_error(error: &Self) -> bool {
        matches!(error,
            Self::DatabaseQueryError(_) |
            Self::DbPoolError(_) |
            Self::DbManagedPoolError(_) |
            Self::DbPoolBuildError(_) |
            Self::DbInteractError(_) |
            Self::DbMigrationError(_)
        )
    }

    const fn is_crypto_error(error: &Self) -> bool {
        matches!(error,
            Self::CryptoError(_) |
            Self::EncryptionError(_) |
            Self::DecryptionError(_) |
            Self::PasswordHashingFailed(_)
        )
    }

    const fn is_ai_service_error(error: &Self) -> bool {
        matches!(error,
            Self::GeminiError(_) |
            Self::LlmClientError(_) |
            Self::AiServiceError(_)
        )
    }

    const fn is_communication_error(error: &Self) -> bool {
        matches!(error,
            Self::HttpRequestError(_) |
            Self::HttpMiddlewareError(_) |
            Self::WebSocketSendError(_) |
            Self::ImageProcessingError(_)
        )
    }

    const fn is_text_processing_error(error: &Self) -> bool {
        matches!(error,
            Self::ChunkingError(_) |
            Self::TextProcessingError(_)
        )
    }

    const fn is_system_config_error(error: &Self) -> bool {
        matches!(error,
            Self::ConfigError(_) |
            Self::IoError(_) |
            Self::SerializationError(_)
        )
    }

    fn handle_session_error(app_error: Self) -> (StatusCode, String) {
        match app_error {
            Self::SessionStoreError(e) => {
                error!("Session store error: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Session management error".to_string())
            }
            Self::SessionError(e) => {
                error!("Session operation error: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, "A session operation failed.".to_string())
            }
            Self::Session(e) => {
                error!("Session error: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Session management error".to_string())
            }
            _ => unreachable!("Non-session error passed to handle_session_error")
        }
    }

    fn handle_database_error(app_error: Self) -> (StatusCode, String) {
        let (log_msg, user_msg) = match app_error {
            Self::DatabaseQueryError(e) => (format!("Database query error: {e}"), "Database error"),
            Self::DbPoolError(e) => (format!("Database pool error: {e}"), "Database connection error"),
            Self::DbManagedPoolError(e) => (format!("Database managed pool error: {e}"), "Database connection error"),
            Self::DbPoolBuildError(e) => (format!("Database pool build error: {e}"), "Database configuration error"),
            Self::DbInteractError(e) => (format!("Database interaction error: {e}"), "Database task execution error"),
            Self::DbMigrationError(e) => (format!("Database migration error: {e}"), "Database schema error"),
            _ => unreachable!("Non-database error passed to handle_database_error")
        };
        
        error!("{}", log_msg);
        (StatusCode::INTERNAL_SERVER_ERROR, user_msg.to_string())
    }

    fn handle_crypto_error(app_error: Self) -> (StatusCode, String) {
        let (log_msg, user_msg) = match app_error {
            Self::CryptoError(e) => (format!("Cryptography error: {e}"), "A cryptographic operation failed."),
            Self::EncryptionError(e) => (format!("Encryption error: {e}"), "Encryption operation failed."),
            Self::DecryptionError(e) => (format!("Decryption error: {e}"), "Data decryption failed."),
            Self::PasswordHashingFailed(e) => (format!("Password hashing failed: {e}"), "Internal security error"),
            _ => unreachable!("Non-crypto error passed to handle_crypto_error")
        };
        
        error!("{}", log_msg);
        (StatusCode::INTERNAL_SERVER_ERROR, user_msg.to_string())
    }

    fn handle_ai_service_error(app_error: Self) -> (StatusCode, String) {
        let (log_msg, user_msg) = match app_error {
            Self::GeminiError(e) => (format!("LLM API error: {e}"), "AI service error".to_string()),
            Self::LlmClientError(e) => (format!("LLM client error: {e}"), "AI service client error".to_string()),
            Self::AiServiceError(e) => (format!("AI Service Error: {e}"), e),
            _ => unreachable!("Non-AI service error passed to handle_ai_service_error")
        };
        
        error!("{}", log_msg);
        (StatusCode::INTERNAL_SERVER_ERROR, user_msg)
    }

    fn handle_communication_error(app_error: Self) -> (StatusCode, String) {
        let (log_msg, user_msg) = match app_error {
            Self::HttpRequestError(e) => (format!("HTTP request error: {e}"), "Failed to communicate with external service"),
            Self::HttpMiddlewareError(e) => (format!("HTTP middleware error: {e}"), "Failed during external service communication"),
            Self::WebSocketSendError(e) => (format!("WebSocket send error: {e}"), "WebSocket send error"),
            Self::ImageProcessingError(e) => (format!("Image processing error: {e}"), "Failed to process image"),
            _ => unreachable!("Non-communication error passed to handle_communication_error")
        };
        
        error!("{}", log_msg);
        (StatusCode::INTERNAL_SERVER_ERROR, user_msg.to_string())
    }

    fn handle_text_processing_error(app_error: Self) -> (StatusCode, String) {
        let (log_msg, user_msg) = match app_error {
            Self::ChunkingError(e) => (format!("Text chunking error: {e}"), "Text chunking error"),
            Self::TextProcessingError(e) => (format!("Text processing error: {e}"), "Failed to process text"),
            _ => unreachable!("Non-text processing error passed to handle_text_processing_error")
        };
        
        error!("{}", log_msg);
        (StatusCode::INTERNAL_SERVER_ERROR, user_msg.to_string())
    }

    fn handle_system_config_error(app_error: Self) -> (StatusCode, String) {
        let (log_msg, user_msg) = match app_error {
            Self::ConfigError(e) => (format!("Configuration error: {e}"), "Server configuration error"),
            Self::IoError(e) => (format!("IO error: {e}"), "File system or network error"),
            Self::SerializationError(e) => (format!("Serialization error: {e}"), "Data formatting error"),
            _ => unreachable!("Non-system config error passed to handle_system_config_error")
        };
        
        error!("{}", log_msg);
        (StatusCode::INTERNAL_SERVER_ERROR, user_msg.to_string())
    }

    fn handle_password_processing_error() -> (StatusCode, String) {
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error: Password processing error.".to_string())
    }

    fn handle_fallback_error(app_error: Self) -> (StatusCode, String) {
        match app_error {
            Self::InternalServerErrorGeneric(e) => {
                error!("Internal server error: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, "An unexpected error occurred".to_string())
            }
            Self::ValidationError(_) => {
                unreachable!("ValidationError should be handled by the outer match arm")
            }
            _ => {
                error!("Unhandled error type: {:?}", app_error);
                (StatusCode::INTERNAL_SERVER_ERROR, "An unexpected error occurred".to_string())
            }
        }
    }
}

// --- Convenience Result Type ---
pub type Result<T, E = AppError> = std::result::Result<T, E>;

// --- From implementations ---
impl From<bcrypt::BcryptError> for AppError {
    fn from(err: bcrypt::BcryptError) -> Self {
        Self::PasswordHashingFailed(err.to_string())
    }
}

impl From<axum_login::Error<AuthBackend>> for AppError {
    fn from(err: axum_login::Error<AuthBackend>) -> Self {
        // Restore original (potentially incorrect) match logic
        match err {
            axum_login::Error::Session(session_err) => {
                tracing::error!("Session component of axum_login::Error: {session_err:?}");
                if session_err.to_string().contains("decode error") {
                    // Heuristic check
                    Self::Unauthorized(format!("Invalid session data: {session_err}"))
                } else {
                    Self::SessionStoreError(format!(
                        "Session processing error: {session_err}"
                    ))
                }
            }
            // This variant caused E0599 before, indicating it might be incorrect for the current axum_login version.
            // We'll leave it commented out for now and rely on the fact that this path isn't being hit for the current 404s.
            // If we later encounter panics *here*, we'll need to revisit the axum_login::Error structure.
            /*
            axum_login::Error::Identity(user_store_err) => {
                tracing::error!("Identity (UserStore) component of axum_login::Error: {:?}", user_store_err);
                match user_store_err {
                    AuthBackendError::UserNotFound => Self::UserNotFound,
                    AuthBackendError::InvalidCredentials => Self::InvalidCredentials,
                    AuthBackendError::PasswordHashingFailed(s) => Self::PasswordHashingFailed(s),
                    AuthBackendError::DbQueryError(s) => Self::DatabaseQueryError(s),
                    AuthBackendError::UsernameTaken => Self::UsernameTaken,
                    AuthBackendError::DbPoolError(s) => Self::DbPoolError(s),
                    AuthBackendError::InternalError(s) => Self::InternalServerErrorGeneric(s),
                }
            }
            */
            // Add a temporary catch-all that maps to Unauthorized until we know the correct variants
            axum_login::Error::Backend(_) => { // Changed _ to axum_login::Error::Backend(_)
                tracing::error!("Unhandled axum_login::Error variant: {err:?}");
                Self::Unauthorized(format!("Unhandled authentication error: {err}"))
            }
        }
    }
}

impl From<tower_sessions::session_store::Error> for AppError {
    fn from(err: tower_sessions::session_store::Error) -> Self {
        Self::SessionStoreError(err.to_string())
    }
}

impl From<diesel::result::Error> for AppError {
    fn from(err: diesel::result::Error) -> Self {
        match err {
            DieselError::NotFound => Self::NotFound("Resource not found".to_string()),
            // Explicitly check the error message for "Record not found" as a fallback
            ref e if e.to_string().contains("Record not found") => {
                Self::NotFound("Resource not found".to_string())
            }
            _ => Self::DatabaseQueryError(err.to_string()),
        }
    }
}

impl From<deadpool_diesel::PoolError> for AppError {
    fn from(err: deadpool_diesel::PoolError) -> Self {
        Self::DbPoolError(err.to_string())
    }
}

impl From<deadpool::managed::PoolError<deadpool_diesel::PoolError>> for AppError {
    fn from(err: deadpool::managed::PoolError<deadpool_diesel::PoolError>) -> Self {
        Self::DbManagedPoolError(err.to_string())
    }
}

impl From<deadpool::managed::BuildError> for AppError {
    fn from(err: deadpool::managed::BuildError) -> Self {
        Self::DbPoolBuildError(err.to_string())
    }
}

impl From<deadpool_diesel::InteractError> for AppError {
    fn from(err: deadpool_diesel::InteractError) -> Self {
        Self::DbInteractError(err.to_string())
    }
}

impl From<diesel_migrations::MigrationError> for AppError {
    fn from(err: diesel_migrations::MigrationError) -> Self {
        Self::DbMigrationError(err.to_string())
    }
}

impl From<axum::extract::multipart::MultipartError> for AppError {
    fn from(err: axum::extract::multipart::MultipartError) -> Self {
        Self::FileUploadError(err.to_string())
    }
}

impl From<std::num::ParseIntError> for AppError {
    fn from(err: std::num::ParseIntError) -> Self {
        Self::ParseIntError(err.to_string())
    }
}

impl From<uuid::Error> for AppError {
    fn from(err: uuid::Error) -> Self {
        Self::UuidError(err.to_string())
    }
}

impl From<genai::Error> for AppError {
    fn from(err: genai::Error) -> Self {
        Self::GeminiError(err.to_string())
    }
}

impl From<image::ImageError> for AppError {
    fn from(err: image::ImageError) -> Self {
        Self::ImageProcessingError(err.to_string())
    }
}

impl From<reqwest::Error> for AppError {
    fn from(err: reqwest::Error) -> Self {
        Self::HttpRequestError(err.to_string())
    }
}

impl From<reqwest_middleware::Error> for AppError {
    fn from(err: reqwest_middleware::Error) -> Self {
        Self::HttpMiddlewareError(err.to_string())
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError(err.to_string())
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        Self::InternalServerErrorGeneric(err.to_string()) // Use renamed variant
    }
}

impl From<tower_sessions::session::Error> for AppError {
    fn from(err: tower_sessions::session::Error) -> Self {
        Self::Session(err.to_string())
    }
}

// From impl for AuthError
impl From<crate::auth::AuthError> for AppError {
    fn from(err: crate::auth::AuthError) -> Self {
        match err {
            crate::auth::AuthError::WrongCredentials => Self::InvalidCredentials,
            crate::auth::AuthError::UsernameTaken => Self::UsernameTaken,
            crate::auth::AuthError::EmailTaken => Self::EmailTaken,
            crate::auth::AuthError::HashingError => {
                Self::PasswordHashingFailed("Bcrypt hashing failed".to_string())
            } // This remains, not PasswordProcessingError, as From<AuthError> is generic
            crate::auth::AuthError::UserNotFound => Self::UserNotFound,
            crate::auth::AuthError::DatabaseError(msg) => Self::DatabaseQueryError(msg),
            crate::auth::AuthError::PoolError(e) => Self::DbPoolError(e.to_string()),
            crate::auth::AuthError::InteractError(s) => Self::DbInteractError(s),
            crate::auth::AuthError::CryptoOperationFailed(crypto_err) => {
                Self::InternalServerErrorGeneric(format!(
                    "Cryptography operation failed: {crypto_err}"
                ))
            } // Use renamed variant
            crate::auth::AuthError::RecoveryNotSetup => Self::BadRequest(
                "Account recovery has not been set up for this user.".to_string(),
            ),
            crate::auth::AuthError::InvalidRecoveryPhrase => {
                Self::BadRequest("The provided recovery phrase was invalid.".to_string())
            }
            crate::auth::AuthError::SessionDeletionError(msg) => {
                Self::InternalServerErrorGeneric(format!("Failed to delete session: {msg}"))
            }
            crate::auth::AuthError::AccountLocked => Self::Unauthorized(
                "Your account is locked. Please contact an administrator.".to_string(),
            ),
        }
    }
}

// --- Test Module ---
#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::StatusCode, response::IntoResponse};
    use serde_json::Value;

    // Helper function to create an io::Error for testing
    fn create_io_error() -> std::io::Error {
        std::io::Error::other("Test IO error")
    }

    // Helper function to create a serde_json::Error for testing
    fn create_serde_json_error() -> serde_json::Error {
        serde_json::from_str::<i32>("not a number").unwrap_err()
    }

    // Helper function to extract JSON from response body
    async fn get_body_json(response: axum::response::Response) -> Value {
        let (_, body) = response.into_parts();
        let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        serde_json::from_slice(&body_bytes).unwrap()
    }

    #[test]
    fn test_auth_error_conversions() {
        let auth_error_wc = crate::auth::AuthError::WrongCredentials;
        let app_error_wc: AppError = auth_error_wc.into();
        assert!(matches!(app_error_wc, AppError::InvalidCredentials));

        let auth_error_ut = crate::auth::AuthError::UsernameTaken;
        let app_error_ut: AppError = auth_error_ut.into();
        assert!(matches!(app_error_ut, AppError::UsernameTaken));

        let auth_error_he = crate::auth::AuthError::HashingError;
        let app_error_he: AppError = auth_error_he.into();
        assert!(matches!(app_error_he, AppError::PasswordHashingFailed(_)));

        let auth_error_unf = crate::auth::AuthError::UserNotFound;
        let app_error_unf: AppError = auth_error_unf.into();
        assert!(matches!(app_error_unf, AppError::UserNotFound));

        let db_err_str = "db error".to_string();
        let auth_error_dbe = crate::auth::AuthError::DatabaseError(db_err_str.clone());
        let app_error_dbe: AppError = auth_error_dbe.into();
        assert!(matches!(app_error_dbe, AppError::DatabaseQueryError(s) if s == db_err_str));

        let pool_err = deadpool_diesel::PoolError::Timeout(deadpool::managed::TimeoutType::Create);
        let pool_err_str = pool_err.to_string();
        let auth_error_pool = crate::auth::AuthError::PoolError(pool_err);
        let app_error_pool: AppError = auth_error_pool.into();
        assert!(matches!(app_error_pool, AppError::DbPoolError(s) if s == pool_err_str));

        let interact_err_str = "interact error".to_string();
        let auth_error_interact = crate::auth::AuthError::InteractError(interact_err_str.clone());
        let app_error_interact: AppError = auth_error_interact.into();
        assert!(matches!(app_error_interact, AppError::DbInteractError(s) if s == interact_err_str));
    }

    // --- Tests for AppError IntoResponse arms ---

    #[tokio::test]
    async fn test_invalid_credentials_response() {
        let error = AppError::InvalidCredentials; // Line 235
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED); // Line 236
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Invalid credentials");
    }

    #[tokio::test]
    async fn test_conflict_response() {
        let error = AppError::Conflict("Item already exists".to_string()); // Line 76
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Item already exists");
    }

    #[tokio::test]
    async fn test_user_not_found_response() {
        let error = AppError::UserNotFound; // Line 27
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "User not found");
    }

    #[tokio::test]
    async fn test_invalid_input_response() {
        let error = AppError::InvalidInput("Age must be positive".to_string()); // Line 86
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Invalid input: Age must be positive");
    }

    #[tokio::test]
    async fn test_parse_int_error_response() {
        let parse_error = "abc".parse::<i32>().unwrap_err();
        let error: AppError = parse_error.into(); // Line 758-759 trigger this variant
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Invalid numeric value provided");
    }

    #[tokio::test]
    async fn test_auth_error_response() {
        // Use the From<axum_login::Error> conceptual test path
        let error = AppError::AuthError("Simulated axum_login error".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Authentication error");
    }

    #[tokio::test]
    async fn test_session_store_error_response() {
        // Use the From<tower_sessions::session_store::Error> conceptual test path
        let error = AppError::SessionStoreError("Simulated session store error".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Session management error");
    }

    #[tokio::test]
    async fn test_rate_limited_response() {
        let error = AppError::RateLimited;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = get_body_json(response).await;
        assert_eq!(
            body["error"],
            "API rate limit exceeded. Please try again later."
        );
    }

    #[tokio::test]
    async fn test_db_pool_error_response() {
        let pool_error =
            deadpool_diesel::PoolError::Timeout(deadpool::managed::TimeoutType::Create);
        let error: AppError = pool_error.into();
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Database connection error");
    }

    #[tokio::test]
    async fn test_db_managed_pool_error_response() {
        let inner_pool_error =
            deadpool_diesel::PoolError::Timeout(deadpool::managed::TimeoutType::Create);
        let managed_pool_error: deadpool::managed::PoolError<deadpool_diesel::PoolError> =
            deadpool::managed::PoolError::Backend(inner_pool_error);
        let error: AppError = managed_pool_error.into();
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Database connection error");
    }

    #[tokio::test]
    async fn test_db_pool_build_error_response() {
        // Use the corrected way to create BuildError
        let build_error = deadpool::managed::BuildError::NoRuntimeSpecified;
        let error: AppError = build_error.into();
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Database configuration error");
    }

    #[tokio::test]
    async fn test_db_interact_error_response() {
        let interact_error = deadpool_diesel::InteractError::Aborted;
        let error: AppError = interact_error.into();
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Database task execution error");
    }

    #[tokio::test]
    async fn test_db_migration_error_response() {
        // Use the corrected way to create MigrationError
        let migration_error = diesel_migrations::MigrationError::NoMigrationRun;
        let error: AppError = migration_error.into();
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Database schema error");
    }

    #[tokio::test]
    async fn test_password_hashing_failed_response() {
        // Use the From<bcrypt::Error> conceptual test path
        let error = AppError::PasswordHashingFailed("Simulated bcrypt error".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Internal security error");
    }

    #[tokio::test]
    async fn test_config_error_response() {
        let error = AppError::ConfigError("Missing config value".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Server configuration error");
    }

    #[tokio::test]
    async fn test_io_error_response() {
        let io_error = create_io_error();
        let error: AppError = io_error.into();
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "File system or network error");
    }

    #[tokio::test]
    async fn test_serialization_error_response() {
        let json_error = create_serde_json_error();
        let error: AppError = json_error.into();
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Data formatting error");
    }

    #[tokio::test]
    async fn test_gemini_error_response() {
        // Use the From<genai::Error> conceptual test path
        let error = AppError::GeminiError("Simulated genai error".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "AI service error");
    }

    #[tokio::test]
    async fn test_image_processing_error_response() {
        let io_error = create_io_error();
        let image_error = image::ImageError::IoError(io_error);
        let error: AppError = image_error.into();
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Failed to process image");
    }

    #[tokio::test]
    async fn test_http_request_error_response() {
        // Directly create the AppError variant as From<reqwest::Error> is hard to test
        let error = AppError::HttpRequestError("Simulated reqwest error".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Failed to communicate with external service");
    }

    #[tokio::test]
    async fn test_http_middleware_error_response() {
        // Simulate middleware error directly as reqwest::Error is hard to construct
        let middleware_error =
            reqwest_middleware::Error::Middleware(anyhow::anyhow!("Simulated middleware error"));
        let error: AppError = middleware_error.into();
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(
            body["error"],
            "Failed during external service communication"
        );
    }

    #[tokio::test]
    async fn test_llm_client_error_response() {
        let error = AppError::LlmClientError("Client config invalid".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "AI service client error");
    }

    #[tokio::test]
    async fn test_generation_error_response() {
        let error = AppError::GenerationError("Content blocked".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "AI service request failed");
    }

    #[tokio::test]
    async fn test_embedding_error_response() {
        let error = AppError::EmbeddingError("Model dimension mismatch".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "AI embedding service request failed");
    }

    #[tokio::test]
    async fn test_vector_db_error_response() {
        let error = AppError::VectorDbError("Qdrant connection failed".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Failed to process embeddings");
    }

    #[tokio::test]
    async fn test_session_error_response() {
        // Use the corrected way to create session::Error
        let json_error = create_serde_json_error();
        // Construct via Store(Decode(...)) as determined above
        // Assuming session_store::Error::Decode is constructible.
        // Assuming session_store::Error::Decode is constructible.
        // Assuming session_store::Error::Decode is constructible.
        // Assuming session_store::Error::Decode is constructible.
        // Assuming session_store::Error::Decode is constructible.
        let store_error = tower_sessions::session_store::Error::Decode(json_error.to_string()); // Convert to String
        let session_error = tower_sessions::session::Error::Store(store_error);
        let error: AppError = session_error.into();
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Session management error");
    }

    #[tokio::test]
    async fn test_not_implemented_response() {
        let error = AppError::NotImplemented("Feature X not ready".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Feature X not ready");
    }

    #[tokio::test]
    async fn test_websocket_send_error_response() {
        let error = AppError::WebSocketSendError("Connection closed".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "WebSocket send error");
    }

    #[tokio::test]
    async fn test_websocket_receive_error_response() {
        let error = AppError::WebSocketReceiveError("Invalid message format".to_string()); // Line 160
        let response = error.into_response(); // Line 459
        assert_eq!(response.status(), StatusCode::BAD_REQUEST); // Line 463
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "WebSocket receive error"); // Line 463
    }

    #[tokio::test]
    async fn test_chunking_error_response() {
        let error = AppError::ChunkingError("Chunk size too small".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Text chunking error");
    }

    #[tokio::test]
    async fn test_character_parsing_error_response() {
        // This tests the *other* variant AppError::CharacterParsingError(String)
        let error = AppError::CharacterParsingError("Missing required field 'name'".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Failed to parse character data");
    }

    #[tokio::test]
    async fn test_session_not_found_response() {
        let app_error = AppError::SessionNotFound;
        let response = app_error.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Session not found or expired");
    }

    #[tokio::test]
    async fn test_crypto_error_response() {
        let app_error = AppError::CryptoError("Test crypto error".to_string());
        let response = app_error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "A cryptographic operation failed.");
    }

    #[tokio::test]
    async fn test_decryption_error_response() {
        let app_error = AppError::DecryptionError("Test decryption error".to_string());
        let response = app_error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "Data decryption failed.");
    }

    #[tokio::test]
    async fn test_session_error_response_new() {
        let app_error = AppError::SessionError("Test session op error".to_string());
        let response = app_error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = get_body_json(response).await;
        assert_eq!(body["error"], "A session operation failed.");
    }
}
