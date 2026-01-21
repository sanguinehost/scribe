#![allow(clippy::literal_string_with_formatting_args)]
#![recursion_limit = "1024"]
pub mod auth;
pub mod config;
pub mod crypto;
pub mod db;
#[cfg(feature = "desktop")]
pub mod desktop;
pub mod errors;
pub mod extractors;
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
#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
#[path = "schema_sqlite.rs"]
pub mod schema;

#[cfg(any(feature = "postgres-backend", not(feature = "sqlite-backend")))]
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

// Re-export database type aliases for use in models
// These resolve to native types for PostgreSQL or newtype wrappers for SQLite
pub use db::{DbBigDecimal, DbBlob, DbConnection, DbDecimal, DbId, DbInt, DbJson, DbTimestamp};

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
