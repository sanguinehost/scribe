pub mod auth; // Added auth module
pub mod config; // Add config module
pub mod crypto; // Added crypto module
pub mod errors; // Corrected from 'error'
pub mod llm; // Added llm module
pub mod logging;
pub mod models;
pub mod prompt_builder;
pub mod routes;
pub mod schema;
pub mod services;
pub mod state;
pub mod text_processing;
pub mod vector_db; // Added vector_db module // Added text processing module

use deadpool_diesel::postgres::Pool as DeadpoolPool;

// Define PgPool type alias here for library-wide use
pub type PgPool = DeadpoolPool;

// You might add common error types or other shared utilities here later.

// Re-export AppState for convenience if needed elsewhere
pub use state::AppState;

// Conditionally compile test helpers only when testing
// pub mod test_helpers; // Now unconditionally compiled
pub mod test_helpers;
