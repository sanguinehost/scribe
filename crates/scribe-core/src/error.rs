use thiserror::Error;
use serde::{Serialize, Deserialize};

#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum CoreError {
    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Resource not found: {0}")]
    ResourceNotFound(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Rate limit exceeded")]
    RateLimited(Option<u64>), // Optional retry delay in seconds

    #[error("User not found")]
    UserNotFound,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Username taken")]
    UsernameTaken,

    #[error("Email taken")]
    EmailTaken,

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("Timeout: {0}")]
    Timeout(String),
}

impl CoreError {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::Internal(_) => "INTERNAL_ERROR",
            Self::NotFound(_) | Self::ResourceNotFound(_) => "NOT_FOUND",
            Self::Unauthorized(_) => "UNAUTHORIZED",
            Self::Forbidden(_) => "FORBIDDEN",
            Self::BadRequest(_) => "BAD_REQUEST",
            Self::Conflict(_) => "CONFLICT",
            Self::ValidationError(_) => "VALIDATION_ERROR",
            Self::RateLimited(_) => "RATE_LIMITED",
            Self::UserNotFound => "USER_NOT_FOUND",
            Self::InvalidCredentials => "INVALID_CREDENTIALS",
            Self::UsernameTaken => "USERNAME_TAKEN",
            Self::EmailTaken => "EMAIL_TAKEN",
            Self::NotImplemented(_) => "NOT_IMPLEMENTED",
            Self::Timeout(_) => "TIMEOUT",
        }
    }
}
