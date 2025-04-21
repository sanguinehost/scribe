// Use deadpool-diesel types for async pooling
// Import auth module
// Import AuthError enum
use deadpool_diesel::postgres::Pool as DeadpoolDieselPool;
// Removed AppError import as it's not directly used here
use crate::config::Config; // Use Config instead
// use genai::Client as GeminiApiClient; // Remove Gemini client for now
use std::sync::Arc;

// --- DB Connection Pool Type ---
pub type DbPool = DeadpoolDieselPool;
// Note: deadpool::Pool is already Cloneable.

// --- Shared application state ---
#[derive(Clone)] 
pub struct AppState {
    pub pool: DbPool,
    // Change to Arc<Config> and make public
    pub config: Arc<Config>, 
    // Remove gemini_client field for now
    // pub gemini_client: GeminiApiClient,
    #[cfg(test)] // Only include mock_response in test builds
    pub mock_llm_response: std::sync::Arc<tokio::sync::Mutex<Option<String>>>,
}

impl AppState {
    // Update constructor signature and body
    pub fn new(pool: DbPool, config: Arc<Config>) -> Self {
        // Remove gemini_client from arguments and initialization
        Self {
            pool: pool, // Assign DbPool directly
            config,
            #[cfg(test)]
            mock_llm_response: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        }
    }
}
