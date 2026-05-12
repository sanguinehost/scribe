// crates/scribe-identity/src/lib.rs

pub mod auth;
pub mod models;
pub mod middleware;
pub mod db;
pub mod error;
pub mod privacy;
pub mod email;
#[cfg(feature = "postgres-backend")]
pub mod schema;

#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
pub mod schema_sqlite;
#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
pub use schema_sqlite as schema;
pub mod state;

pub use auth::*;
pub use models::*;
pub use middleware::*;
pub use state::*;
pub use db::*;
