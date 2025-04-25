// Use deadpool-diesel types for async pooling
// Import auth module
// Import AuthError enum
use deadpool_diesel::postgres::{Pool as DeadpoolPool};
// Removed AppError import as it's not directly used here
use crate::config::Config; // Use Config instead
// use genai::Client as GeminiApiClient; // Remove Gemini client for now
use std::sync::Arc;
// Removed #[cfg(test)] - Mutex needed unconditionally now for tracker
use tokio::sync::Mutex; // Add Mutex for test tracking
// Use the AiClient trait from our llm module
use crate::llm::AiClient;
use crate::llm::EmbeddingClient; // Add this
use crate::vector_db::QdrantClientService; // Add Qdrant service import
use crate::services::embedding_pipeline::EmbeddingPipelineServiceTrait; // Import the new trait

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
    pub embedding_client: Arc<dyn EmbeddingClient>, // Add this line
    pub qdrant_service: Arc<QdrantClientService>, // Add Qdrant service
    pub embedding_pipeline_service: Arc<dyn EmbeddingPipelineServiceTrait>, // Add Embedding Pipeline service trait object
    // Remove #[cfg(test)]
    pub embedding_call_tracker: Arc<Mutex<Vec<uuid::Uuid>>>, // Track message IDs for embedding calls
   }
   
impl AppState {
    // Update constructor signature to accept the trait object Arc
    pub fn new(
        pool: DeadpoolPool,
        config: Arc<Config>,
        ai_client: Arc<dyn AiClient + Send + Sync>, // Use trait object Arc here
        embedding_client: Arc<dyn EmbeddingClient>, // Add this parameter
        qdrant_service: Arc<QdrantClientService>, // Add Qdrant service parameter
        embedding_pipeline_service: Arc<dyn EmbeddingPipelineServiceTrait>, // Add Embedding Pipeline service parameter
       ) -> Self {
        Self {
            pool,
            config,
            // #[cfg(test)] // Remove cfg(test)
            // mock_llm_response: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
            ai_client, // Assign the passed-in client Arc
            embedding_client, // Add this assignment
            qdrant_service, // Add this assignment
            embedding_pipeline_service, // Add this assignment
            // Remove #[cfg(test)]
            embedding_call_tracker: Arc::new(Mutex::new(Vec::new())), // Initialize tracker for tests
           }
           }
}
