// use scribe_backend; // Keep backend types if needed by error variants - Removed
use reqwest;
use serde_json;
use url;
// Remove unused import, derive macro handles it
// use thiserror::Error;

/// Custom Error type for the CLI client
#[derive(thiserror::Error, Debug)]
#[allow(dead_code)] // Allow unused variants for now
pub enum CliError {
    // Made pub
    #[error("Request failed: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("URL parsing error: {0}")]
    UrlParse(#[from] url::ParseError),
    #[error("JSON serialization/deserialization error: {0}")]
    // Renamed JsonDeser -> Json, updated message
    Json(#[from] serde_json::Error),
    #[error("API returned an error: status={status}, message={message}")]
    ApiError {
        status: reqwest::StatusCode,
        message: String,
    },
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    #[error("Registration failed: {0}")]
    RegistrationFailed(String),
    #[error("Resource not found")]
    NotFound,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid input: {0}")]
    InputError(String),
    #[error("Internal client error: {0}")]
    Internal(String),
    // Renamed RateLimited to RateLimitExceeded
    #[error("API rate limit exceeded. Please try again later.")]
    RateLimitExceeded, // Renamed from RateLimited

    // Add new variants from client.rs logic
    #[error("Network error: {0}")]
    Network(String),
    #[error("Backend error: {0}")]
    Backend(String), // For generic non-API errors from backend responses
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("User not found")]
    UserNotFound,
    #[error("Character upload error: {0}")]
    CharacterUploadError(String),
    #[error("Chat session error: {0}")]
    ChatSessionError(String),
    #[error("Operation failed: {0}")]
    OperationFailed(String),
    #[error("Conflict: {0}")]
    Conflict(String),
}
