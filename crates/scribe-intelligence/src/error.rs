use scribe_core::error::CoreError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IntelligenceError {
    #[error("LLM Provider error: {0}")]
    ProviderError(String),

    #[error("Vector DB error: {0}")]
    VectorDbError(String),

    #[error("Embedding error: {0}")]
    EmbeddingError(String),

    #[error("Tool error: {0}")]
    ToolError(String),

    #[error("Prompt injection detected")]
    PromptInjectionDetected,

    #[error("Token limit exceeded: {0}")]
    TokenLimitExceeded(String),

    #[error("Deduplication failure: {0}")]
    DeduplicationFailure(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<IntelligenceError> for CoreError {
    fn from(err: IntelligenceError) -> Self {
        match err {
            IntelligenceError::ProviderError(e) => CoreError::Internal(format!("LLM Provider error: {}", e)),
            IntelligenceError::VectorDbError(e) => CoreError::Internal(format!("Vector DB error: {}", e)),
            IntelligenceError::EmbeddingError(e) => CoreError::Internal(format!("Embedding error: {}", e)),
            IntelligenceError::ToolError(e) => CoreError::Internal(format!("Tool error: {}", e)),
            IntelligenceError::PromptInjectionDetected => CoreError::Forbidden("Prompt injection detected".to_string()),
            IntelligenceError::TokenLimitExceeded(e) => CoreError::BadRequest(format!("Token limit exceeded: {}", e)),
            IntelligenceError::DeduplicationFailure(e) => CoreError::Internal(format!("Deduplication failure: {}", e)),
            IntelligenceError::ConfigError(e) => CoreError::Internal(format!("Intelligence configuration error: {}", e)),
            IntelligenceError::Internal(e) => CoreError::Internal(e),
        }
    }
}
