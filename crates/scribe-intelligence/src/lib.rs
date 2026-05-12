pub mod error;
pub mod llm;
pub mod vector;
pub mod rag;
pub mod mcp;
pub mod merlin;
pub mod security;
pub mod utils;

pub use error::IntelligenceError;

use async_trait::async_trait;
use futures::stream::Stream;
use std::pin::Pin;
use serde::{Serialize, Deserialize};

/// Rig-based stream event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntelligenceStreamEvent {
    Content(String),
    Reasoning(String),
    ToolCall {
        id: String,
        name: String,
        arguments: serde_json::Value,
    },
    TokenUsage {
        input_tokens: u64,
        output_tokens: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceChatResponse {
    pub content: String,
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub reasoning_content: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntelligenceCompletionRequest {
    pub model_name: String,
    pub provider: String,
    pub prompt: String,
    pub preamble: Option<String>,
    pub history: Vec<serde_json::Value>, // Using Value for flexibility, map to Rig message in implementation
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub max_tokens: Option<i32>,
    pub reasoning_budget: Option<i32>,
    pub thinking_level: Option<String>,
    pub capture_reasoning_content: bool,
}

#[async_trait]
pub trait IntelligenceClient: Send + Sync {
    async fn completion(&self, req: IntelligenceCompletionRequest) 
        -> Result<IntelligenceChatResponse, IntelligenceError>;

    async fn completion_stream(&self, req: IntelligenceCompletionRequest)
        -> Result<Pin<Box<dyn Stream<Item = Result<IntelligenceStreamEvent, IntelligenceError>> + Send>>, IntelligenceError>;
}
