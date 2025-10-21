// Conditional schema selection based on backend feature flags

#[cfg(feature = "postgres-backend")]
#[path = "schema_postgres.rs"]
mod schema_postgres;

#[cfg(feature = "postgres-backend")]
pub use schema_postgres::*;

#[cfg(feature = "sqlite-backend")]
#[path = "schema_sqlite.rs"]
mod schema_sqlite;

#[cfg(feature = "sqlite-backend")]
pub use schema_sqlite::*;
