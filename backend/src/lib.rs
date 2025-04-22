pub mod auth; // Added auth module
pub mod errors; // Corrected from 'error'
pub mod llm; // Added llm module
pub mod logging;
pub mod models;
pub mod routes;
pub mod schema;
pub mod services;
pub mod state;
pub mod prompt_builder;
pub mod config; // Add config module

use deadpool_diesel::postgres::Pool as DeadpoolPool;

// Define PgPool type alias here for library-wide use
pub type PgPool = DeadpoolPool;

// You might add common error types or other shared utilities here later.

// Re-export AppState for convenience if needed elsewhere
pub use state::AppState;

// Conditionally compile test helpers only when testing
#[cfg(test)]
pub mod test_helpers;
