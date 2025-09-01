use crate::errors::AppError;
use async_trait::async_trait;
use futures::stream::Stream;
use genai::chat::{ChatOptions, ChatRequest, ChatResponse, ChatStreamEvent};
use std::pin::Pin;

// Type alias for the stream item (Event yielded by the stream)
pub type ChatStreamItem = Result<ChatStreamEvent, AppError>;
// Type alias for the stream itself (The stream implementor)
pub type ChatStream = Pin<Box<dyn Stream<Item = ChatStreamItem> + Send>>;

pub mod gemini_client;
pub mod gemini_embedding_client;
pub mod model_registry;

// LlamaCpp integration (feature-gated)
#[cfg(feature = "local-llm")]
pub mod llamacpp;

// Import the public request struct for use in the trait
pub use gemini_embedding_client::BatchEmbeddingContentRequest;

// Re-export LlamaCpp types when feature is enabled
#[cfg(feature = "local-llm")]
pub use llamacpp::{
    LlamaCppClient, LlamaCppConfig, LocalLlmError,
    ModelManager, ModelSelection, HardwareCapabilities
};

// Re-export model registry types
pub use model_registry::{ModelCapabilities, ModelRegistry, RecommendedContextSettings};

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

#[async_trait]
pub trait EmbeddingClient: Send + Sync {
    async fn embed_content(
        &self,
        text: &str,
        task_type: &str,     // e.g., "RETRIEVAL_DOCUMENT", "RETRIEVAL_QUERY"
        title: Option<&str>, // Added title parameter
    ) -> Result<Vec<f32>, AppError>;

    async fn batch_embed_contents(
        &self,
        requests: Vec<BatchEmbeddingContentRequest<'_>>, // Use the imported struct
    ) -> Result<Vec<Vec<f32>>, AppError>;
}
