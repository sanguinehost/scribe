#![allow(clippy::literal_string_with_formatting_args)]
pub mod auth;
pub mod config;
pub mod crypto;
pub mod db;
pub mod errors;
pub mod features;
pub mod llm;
pub mod logging;
pub mod metrics;
pub mod middleware;
pub mod models;
pub mod privacy;
pub mod prompt_builder;
pub mod prompt_templates;
pub mod routes;
pub mod schema;
pub mod services;
pub mod state;
pub mod state_builder;
pub mod text_processing;
pub mod vector_db;

// Re-export database pool type from db module
// This provides a backend-agnostic pool type that resolves to:
// - PostgreSQL pool in cloud mode (postgres-backend feature)
// - SQLite pool in desktop mode (sqlite-backend feature)
pub use db::DbPool;

// Maintain backward compatibility with existing code that uses PgPool
// TODO: Gradually migrate all code to use DbPool directly
pub type PgPool = DbPool;

// You might add common error types or other shared utilities here later.

// Re-export AppState for convenience if needed elsewhere
pub use state::AppState;

// Conditionally compile test helpers only when testing
// pub mod test_helpers; // Now unconditionally compiled
pub mod test_helpers;

#[cfg(test)]
pub mod test_fixtures;
