use async_trait::async_trait;
use genai::{
    chat::{ChatOptions, ChatRequest, ChatResponse},
};
use crate::errors::AppError;

pub mod gemini_client;

/// Trait defining the interface for AI client operations.
#[async_trait]
pub trait AiClient: Send + Sync {
    /// Executes a chat request with the AI model.
    ///
    /// # Arguments
    ///
    /// * `model_name` - The identifier for the specific AI model to use.
    /// * `request` - The chat request containing messages, system prompt, and configuration.
    /// * `config_override` - Optional generation configuration to override parts of the request's config.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `ChatResponse` on success, or an `AppError` on failure.
    async fn exec_chat(
        &self,
        model_name: &str,
        request: ChatRequest,
        config_override: Option<ChatOptions>, // Use ChatOptions
    ) -> Result<ChatResponse, AppError>;
}