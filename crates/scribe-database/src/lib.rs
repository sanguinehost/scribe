//! Database abstraction layer
//!
//! This module provides a unified interface for working with different database backends
//! (PostgreSQL for cloud mode, SQLite for desktop mode).
//!
//! ## Feature Flags
//!
//! - `postgres-backend`: Enable PostgreSQL backend (cloud mode)
//! - `sqlite-backend`: Enable SQLite backend (desktop mode)
//!
//!
//! ## Architecture Notes
//!
//! **PostgreSQL (Cloud Mode)**:
//! - Uses `deadpool-diesel` for async connection pooling
//! - Network I/O benefits from async operations
//! - Usage: `pool.get().await?.interact(|conn| query).await?`
//!
//! **SQLite (Desktop Mode)**:
//! - Uses `diesel::r2d2` for synchronous connection pooling
//! - Local file I/O is fast enough that sync operations are pragmatic
//! - Queries are synchronous by nature, use `tokio::task::spawn_blocking` in async contexts
//! - Usage in async contexts: `spawn_blocking(move || pool.get()?.query()).await??`
//!
//! ## Usage
//!
//! - `DbConnection`: Resolves to `PgConnection` or `SqliteConnection`
//! - `DbPool`: Resolves to async pool (PostgreSQL) or sync pool (SQLite)
//! - `DefaultBackend`: Resolves to `PostgresBackend` or `SqliteBackend`

pub mod backend_trait;
pub mod backend_traits;
pub mod connection;
pub mod error;
pub use error::DatabaseError;
pub mod pool_helpers;
pub mod schema;
pub mod unified_types;

#[cfg(feature = "postgres-backend")]
pub mod postgres_backend;

#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
pub mod sqlite_backend;

#[cfg(feature = "postgres-backend")]
pub use diesel_migrations::{embed_migrations, EmbeddedMigrations};
#[cfg(feature = "postgres-backend")]
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
pub use diesel_migrations::{embed_migrations, EmbeddedMigrations};
#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations_sqlite");

// Always available because DbType trait requires both PgType and SqliteType
pub mod sqlite_types;

pub mod json_wrapper;

pub use backend_trait::DbBackend;
pub use pool_helpers::{get_conn, with_conn, with_conn_immediate};

// Export SQLite extension traits for compatibility
#[cfg(feature = "sqlite-backend")]
pub use pool_helpers::{SqliteInteractExt, SqlitePoolExt};

// Conditional exports based on feature flags
#[cfg(feature = "postgres-backend")]
pub use postgres_backend::PostgresBackend as DefaultBackend;

#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
pub use sqlite_backend::SqliteBackend as DefaultBackend;

// Connection type aliases
#[cfg(feature = "postgres-backend")]
pub type DbConnection = diesel::pg::PgConnection;

#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
pub type DbConnection = diesel::sqlite::SqliteConnection;

// Backwards-compatible alias
pub type DbConn = DbConnection;

// Pool type aliases
// PostgreSQL uses deadpool-diesel for async pooling
#[cfg(feature = "postgres-backend")]
pub type DbPool = deadpool_diesel::postgres::Pool;

// SQLite uses diesel::r2d2 for synchronous pooling
// (wrapped with spawn_blocking in async contexts)
#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
pub type DbPool = diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<DbConnection>>;

// Pool manager type aliases (only needed for deadpool-diesel)
#[cfg(feature = "postgres-backend")]
pub type DbManager = deadpool_diesel::postgres::Manager;

// Runtime type alias (only used by deadpool-diesel for PostgreSQL)
#[cfg(feature = "postgres-backend")]
pub type DbRuntime = deadpool_diesel::Runtime;

// Database type aliases - PostgreSQL uses native types, SQLite uses newtype wrappers
// Note: DbUuid and DbTimestamp are now provided by unified_types module

// Integer type - i32 for both PostgreSQL (Integer) and SQLite (Integer)
#[cfg(feature = "postgres-backend")]
pub type DbInt = i32;

#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
pub type DbInt = i32;

// BigInt type - DbBigInt is provided by unified_types module

// DbJson is now provided by unified_types module

#[cfg(feature = "postgres-backend")]
pub type DbBigDecimal = bigdecimal::BigDecimal;

#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
pub type DbBigDecimal = sqlite_types::SqliteBigDecimal;

// Compile-time checks to ensure exactly one backend is enabled
#[cfg(all(feature = "postgres-backend", feature = "sqlite-backend"))]
// compile_error!("Cannot enable both postgres-backend and sqlite-backend features simultaneously");
// We now prioritize postgres-backend if both are enabled (e.g. by dev-dependencies)
pub use postgres_backend as _conflict_resolution_postgres;

#[cfg(not(any(feature = "postgres-backend", feature = "sqlite-backend")))]
compile_error!("Must enable either postgres-backend or sqlite-backend feature");

// Export backend-agnostic Json<T> wrapper
pub use json_wrapper::Json;

// ============================================================================
// Export Unified Type System
// ============================================================================

/// Re-export the core DbType trait
pub use backend_traits::DbType;

/// Re-export all unified types
pub use unified_types::{DbBigInt, DbBlob, DbDecimal, DbId, DbJson, DbStringArray, DbTimestamp};
