// Use deadpool-diesel types for async pooling
// Import auth module
// Import AuthError enum
use deadpool_diesel::postgres::Pool as DeadpoolPool;
// Removed AppError import as it's not directly used here
use crate::config::Config; // Use Config instead
// use genai::Client as GeminiApiClient; // Remove Gemini client for now
use std::sync::Arc;
// Removed #[cfg(test)] - Mutex needed unconditionally now for tracker
use tokio::sync::Mutex; // Add Mutex for test tracking
// Use the AiClient trait from our llm module
use crate::llm::AiClient;
use crate::llm::EmbeddingClient; // Add this
use crate::services::embedding_pipeline::EmbeddingPipelineServiceTrait;
// Remove concrete service import, use trait
// use crate::vector_db::QdrantClientService; 
use crate::vector_db::qdrant_client::QdrantClientServiceTrait;

// --- DB Connection Pool Type ---
pub type DbPool = DeadpoolPool;
// Note: deadpool::Pool is already Cloneable.

// --- Shared application state ---
#[derive(Clone)]
pub struct AppState {
    pub pool: DeadpoolPool,
    // Change to Arc<Config> and make public
    pub config: Arc<Config>,
    // Remove gemini_client field for now
    // pub gemini_client: GeminiApiClient,
    // #[cfg(test)] // Remove cfg(test)
    // pub mock_llm_response: std::sync::Arc<tokio::sync::Mutex<Option<String>>>, // Keep for now if other tests use it
    // Change to use the AiClient trait object
    pub ai_client: Arc<dyn AiClient + Send + Sync>,
    pub embedding_client: Arc<dyn EmbeddingClient + Send + Sync>, // Add Send + Sync
    // Change to use the trait object for Qdrant service
    pub qdrant_service: Arc<dyn QdrantClientServiceTrait + Send + Sync>,
    pub embedding_pipeline_service: Arc<dyn EmbeddingPipelineServiceTrait + Send + Sync>, // Add Send + Sync
    // Remove #[cfg(test)]
    pub embedding_call_tracker: Arc<Mutex<Vec<uuid::Uuid>>>, // Track message IDs for embedding calls
}

impl AppState {
    // Update constructor signature to accept the trait object Arc
    pub fn new(
        pool: DeadpoolPool,
        config: Arc<Config>,
        ai_client: Arc<dyn AiClient + Send + Sync>, // Use trait object Arc here
        embedding_client: Arc<dyn EmbeddingClient + Send + Sync>, // Add Send + Sync
        // Accept the trait object Arc for Qdrant service
        qdrant_service: Arc<dyn QdrantClientServiceTrait + Send + Sync>,
        embedding_pipeline_service: Arc<dyn EmbeddingPipelineServiceTrait + Send + Sync>, // Add Send + Sync
    ) -> Self {
        Self {
            pool,
            config,
            // #[cfg(test)] // Remove cfg(test)
            // mock_llm_response: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
            ai_client,                  // Assign the passed-in client Arc
            embedding_client,           // Add this assignment
            qdrant_service,             // Assign the trait object
            embedding_pipeline_service, // Add this assignment
            // Remove #[cfg(test)]
            embedding_call_tracker: Arc::new(Mutex::new(Vec::new())), // Initialize tracker for tests
        }
    }
}
