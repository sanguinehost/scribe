use crate::errors::AppError;
use async_trait::async_trait;
use futures::stream::Stream;
use std::pin::Pin;

// Type alias for the stream item (Event yielded by the stream)
pub type ChatStreamItem = Result<RigStreamEvent, AppError>;
// Type alias for the stream itself (The stream implementor)
pub type ChatStream = Pin<Box<dyn Stream<Item = ChatStreamItem> + Send>>;

pub mod cloud_embedding_client;
pub mod mistralrs_adapter;
pub mod model_registry;
pub mod response_utils; // Utilities for handling LLM responses
pub mod rig_client;
pub mod unified_embedding; // Added unified_embedding module

pub use unified_embedding::UnifiedEmbeddingModel;

// MistralRs integration (feature-gated)
#[cfg(feature = "local-llm")]
pub mod mistralrs_adapter;

// Import the public request struct for use in the trait
pub use cloud_embedding_client::BatchEmbeddingContentRequest;
pub use rig_client::{RigChatResponse, RigCompletionRequest, RigStreamEvent}; // Import Rig types

// Re-export MistralRs types when feature is enabled
#[cfg(feature = "local-llm")]
pub use mistralrs_adapter::MistralRsRigAdapter;

// Re-export model registry types
pub use model_registry::{ModelCapabilities, ModelRegistry, RecommendedContextSettings};

/// Trait for handling reasoning/thinking capabilities in a provider-agnostic way.
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

/// Trait defining the interface for AI client operations.
#[async_trait]
pub trait AiClient: Send + Sync {
    /// Executes a chat request with the AI model.
    async fn completion(&self, req: RigCompletionRequest)
        -> Result<RigChatResponse, anyhow::Error>;

    /// Rig-based streaming completion method
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
