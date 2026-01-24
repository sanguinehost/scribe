use crate::errors::AppError;
use async_trait::async_trait;
use futures::stream::Stream;
use genai::chat::{ChatOptions, ChatRequest, ChatResponse, ChatStreamEvent};
use std::pin::Pin;

// Type alias for the stream item (Event yielded by the stream)
pub type ChatStreamItem = Result<ChatStreamEvent, AppError>;
// Type alias for the stream itself (The stream implementor)
pub type ChatStream = Pin<Box<dyn Stream<Item = ChatStreamItem> + Send>>;

pub mod cloud_embedding_client;
pub mod model_registry;
pub mod rig_client; // Added rig_client module

// LlamaCpp integration (feature-gated)
#[cfg(feature = "local-llm")]
pub mod llamacpp;

// Import the public request struct for use in the trait
pub use cloud_embedding_client::BatchEmbeddingContentRequest;
pub use rig_client::{RigChatResponse, RigCompletionRequest, RigStreamEvent}; // Import Rig types

// Re-export LlamaCpp types when feature is enabled
#[cfg(feature = "local-llm")]
pub use llamacpp::{
    HardwareCapabilities, LlamaCppClient, LlamaCppConfig, LocalLlmError, ModelManager,
    ModelSelection,
};

// Re-export model registry types
pub use model_registry::{ModelCapabilities, ModelRegistry, RecommendedContextSettings};

/// Trait for handling reasoning/thinking capabilities in a provider-agnostic way.
/// This allows configuring reasoning parameters for models that support them (like Gemini 2.0),
/// while safely ignoring them for models that don't (like local Llama models).
pub trait Reasoning {
    /// Sets the reasoning effort level (e.g., "low", "medium", "high").
    fn set_reasoning_effort(&mut self, effort: Option<String>);

    /// Sets the reasoning token budget.
    fn set_reasoning_budget(&mut self, budget: Option<i32>);

    /// Returns true if the implementation supports reasoning features.
    fn supports_reasoning(&self) -> bool {
        false
    }
}

impl Reasoning for ChatOptions {
    fn set_reasoning_effort(&mut self, effort: Option<String>) {
        if let Some(level_str) = effort {
            let level = match level_str.to_lowercase().as_str() {
                "low" => Some(genai::chat::ThinkingLevel::Low),
                "medium" => Some(genai::chat::ThinkingLevel::Medium),
                "high" => Some(genai::chat::ThinkingLevel::High),
                _ => None,
            };
            if let Some(l) = level {
                *self = self.clone().with_thinking_level(l);
            }
        }
    }

    fn set_reasoning_budget(&mut self, budget: Option<i32>) {
        if let Some(b) = budget {
            if b > 0 {
                if let Ok(b_u32) = u32::try_from(b) {
                    *self = self
                        .clone()
                        .with_reasoning_effort(genai::chat::ReasoningEffort::Budget(b_u32));
                }
            }
        }
    }

    fn supports_reasoning(&self) -> bool {
        true
    }
}

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

    // Rig-based completion method
    async fn completion(&self, req: RigCompletionRequest)
        -> Result<RigChatResponse, anyhow::Error>;

    // Rig-based streaming completion method
    async fn completion_stream(
        &self,
        req: RigCompletionRequest,
    ) -> Result<
        std::pin::Pin<Box<dyn Stream<Item = Result<RigStreamEvent, anyhow::Error>> + Send>>,
        anyhow::Error,
    >;
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
