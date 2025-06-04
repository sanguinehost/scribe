#![allow(clippy::literal_string_with_formatting_args)]
pub mod auth;
pub mod config;
pub mod crypto;
pub mod errors;
pub mod llm;
pub mod logging;
pub mod models;
pub mod prompt_builder;
pub mod routes;
pub mod schema;
pub mod services;
pub mod state;
pub mod text_processing;
pub mod vector_db;

use deadpool_diesel::postgres::Pool as DeadpoolPool;

// Define PgPool type alias here for library-wide use
pub type PgPool = DeadpoolPool;

// You might add common error types or other shared utilities here later.

// Re-export AppState for convenience if needed elsewhere
pub use state::AppState;

// Conditionally compile test helpers only when testing
// pub mod test_helpers; // Now unconditionally compiled
pub mod test_helpers;
