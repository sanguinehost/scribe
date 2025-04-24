use async_trait::async_trait;
use genai::{
    chat::{ChatOptions, ChatRequest, ChatResponse, ChatStreamEvent},
};
use crate::errors::AppError;
use futures::stream::Stream;
use std::pin::Pin;

// Type alias for the stream item (Event yielded by the stream)
pub type ChatStreamItem = Result<ChatStreamEvent, AppError>;
// Type alias for the stream itself (The stream implementor)
pub type ChatStream = Pin<Box<dyn Stream<Item = ChatStreamItem> + Send>>;

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

    // Add the streaming method signature
    async fn stream_chat(
        &self,
        model_name: &str,
        request: ChatRequest,
        config_override: Option<ChatOptions>,
    ) -> Result<ChatStream, AppError>; // Return type alias
}