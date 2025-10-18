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
//! ## Current Status (Task 1.2.1 Complete)
//!
//! ✅ **Complete**:
//! - Backend trait abstraction (`DbBackend`)
//! - PostgreSQL backend with `deadpool-diesel` async pooling
//! - SQLite backend with `diesel::r2d2` synchronous pooling
//! - Conditional type aliases for connections and pools
//! - **Cloud/PostgreSQL mode fully functional**
//! - **Desktop/SQLite mode fully functional**
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
pub mod pool_helpers;

#[cfg(feature = "postgres-backend")]
pub mod postgres_backend;

#[cfg(feature = "sqlite-backend")]
pub mod sqlite_backend;

pub use backend_trait::DbBackend;
pub use pool_helpers::{get_conn, with_conn};

// Conditional exports based on feature flags
#[cfg(feature = "postgres-backend")]
pub use postgres_backend::PostgresBackend as DefaultBackend;

#[cfg(feature = "sqlite-backend")]
pub use sqlite_backend::SqliteBackend as DefaultBackend;

// Connection type aliases
#[cfg(feature = "postgres-backend")]
pub type DbConnection = diesel::pg::PgConnection;

#[cfg(feature = "sqlite-backend")]
pub type DbConnection = diesel::sqlite::SqliteConnection;

// Pool type aliases
// PostgreSQL uses deadpool-diesel for async pooling
#[cfg(feature = "postgres-backend")]
pub type DbPool = deadpool_diesel::postgres::Pool;

// SQLite uses diesel::r2d2 for synchronous pooling
// (wrapped with spawn_blocking in async contexts)
#[cfg(feature = "sqlite-backend")]
pub type DbPool = diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<DbConnection>>;

// Pool manager type aliases (only needed for deadpool-diesel)
#[cfg(feature = "postgres-backend")]
pub type DbManager = deadpool_diesel::postgres::Manager;

// Runtime type alias (only used by deadpool-diesel for PostgreSQL)
#[cfg(feature = "postgres-backend")]
pub type DbRuntime = deadpool_diesel::Runtime;

// Compile-time checks to ensure exactly one backend is enabled
#[cfg(all(feature = "postgres-backend", feature = "sqlite-backend"))]
compile_error!("Cannot enable both postgres-backend and sqlite-backend features simultaneously");

#[cfg(not(any(feature = "postgres-backend", feature = "sqlite-backend")))]
compile_error!("Must enable either postgres-backend or sqlite-backend feature");
