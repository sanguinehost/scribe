// use scribe_backend; // Keep backend types if needed by error variants - Removed
use reqwest;
use reqwest::Error as ReqwestError;
use reqwest::StatusCode;
use url;
use serde_json;
use thiserror::Error;

/// Custom Error type for the CLI client
#[derive(thiserror::Error, Debug)]
pub enum CliError { // Made pub
    #[error("Request failed: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("URL parsing error: {0}")]
    UrlParse(#[from] url::ParseError),
    #[error("JSON deserialization error: {0}")]
    JsonDeser(#[from] serde_json::Error),
    #[error("API returned an error: status={status}, message={message}")]
    ApiError { status: reqwest::StatusCode, message: String },
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
    #[error("API rate limit exceeded. Please try again later.")]
    RateLimited,
} 