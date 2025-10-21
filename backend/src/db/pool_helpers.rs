//! Pool operation helpers that provide unified async interface for both backends
//!
//! This module provides functions that work with both PostgreSQL (async) and SQLite (sync)
//! database pools, offering a consistent async interface throughout the application.
//!
//! ## Implementation Details
//!
//! - **PostgreSQL (deadpool-diesel)**: Operations are natively async, so we directly await
//! - **SQLite (diesel::r2d2)**: Operations are sync, so we wrap them in `spawn_blocking`
//!
//! This approach ensures SQLite operations don't block the Tokio runtime while maintaining
//! a unified async interface for all database operations.

use crate::db::DbPool;
use crate::errors::AppError;

#[cfg(feature = "sqlite-backend")]
use diesel::r2d2;

// Extension trait to provide async .get() for SQLite pools (compatibility with PostgreSQL async pools)
#[cfg(feature = "sqlite-backend")]
pub trait SqlitePoolExt {
    type Connection;
    async fn get(
        &self,
    ) -> Result<diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<crate::db::DbConnection>>, r2d2::Error>;
}

#[cfg(feature = "sqlite-backend")]
impl SqlitePoolExt for DbPool {
    type Connection = diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<crate::db::DbConnection>>;

    async fn get(&self) -> Result<Self::Connection, r2d2::Error> {
        let pool = self.clone();
        tokio::task::spawn_blocking(move || pool.get())
            .await
            .map_err(|e| r2d2::Error::from(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?
    }
}

// Extension trait to provide .interact() compatibility for SQLite connections
// Note: For SQLite, we don't actually need spawn_blocking here since the connection
// was already acquired via spawn_blocking in get(). The query itself runs synchronously.
#[cfg(feature = "sqlite-backend")]
pub trait SqliteInteractExt {
    async fn interact<F, T>(&mut self, f: F) -> Result<T, AppError>
    where
        F: FnOnce(&mut crate::db::DbConnection) -> Result<T, AppError> + Send + 'static,
        T: Send + 'static;
}

#[cfg(feature = "sqlite-backend")]
impl SqliteInteractExt
    for diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<crate::db::DbConnection>>
{
    async fn interact<F, T>(&mut self, f: F) -> Result<T, AppError>
    where
        F: FnOnce(&mut crate::db::DbConnection) -> Result<T, AppError> + Send + 'static,
        T: Send + 'static,
    {
        // For SQLite, queries are synchronous and fast (local file I/O)
        // Since we already paid the cost of spawn_blocking in get(), and queries
        // are typically very fast, we can just execute directly here
        // Wrap in a ready future to satisfy async fn requirement
        std::future::ready(f(self)).await
    }
}

/// Get a connection from the pool (async for all backends)
///
/// For PostgreSQL, this directly awaits the async pool operation.
/// For SQLite, this wraps the sync operation in `spawn_blocking`.
#[cfg(feature = "postgres-backend")]
pub async fn get_conn(pool: &DbPool) -> Result<deadpool_diesel::postgres::Object, AppError> {
    pool.get()
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to get connection: {}", e)))
}

#[cfg(feature = "sqlite-backend")]
pub async fn get_conn(
    pool: &DbPool,
) -> Result<
    diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<crate::db::DbConnection>>,
    AppError,
> {
    let pool = pool.clone();
    tokio::task::spawn_blocking(move || {
        pool.get()
            .map_err(|e| AppError::DatabaseQueryError(format!("Failed to get connection: {}", e)))
    })
    .await
    .map_err(|e| AppError::DatabaseQueryError(format!("Task join error: {}", e)))?
}

/// Execute a blocking database operation with a connection (unified interface)
///
/// This function provides a consistent way to execute database operations across both backends.
/// It handles the connection acquisition and operation execution, wrapping appropriately
/// for each backend type.
///
/// ## Usage
///
/// ```rust,ignore
/// use crate::db::with_conn;
///
/// let result = with_conn(&pool, |conn| {
///     // Your database operation here
///     users::table.load::<User>(conn)
///         .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
/// }).await?;
/// ```
#[cfg(feature = "postgres-backend")]
pub async fn with_conn<F, T>(pool: &DbPool, f: F) -> Result<T, AppError>
where
    F: FnOnce(&mut crate::db::DbConnection) -> Result<T, AppError> + Send + 'static,
    T: Send + 'static,
{
    let conn = pool
        .get()
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to get connection: {}", e)))?;
    conn.interact(f)
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Interaction error: {}", e)))?
}

#[cfg(feature = "sqlite-backend")]
pub async fn with_conn<F, T>(pool: &DbPool, f: F) -> Result<T, AppError>
where
    F: FnOnce(&mut crate::db::DbConnection) -> Result<T, AppError> + Send + 'static,
    T: Send + 'static,
{
    let pool = pool.clone();
    tokio::task::spawn_blocking(move || {
        let mut conn = pool.get().map_err(|e| {
            AppError::DatabaseQueryError(format!("Failed to get connection: {}", e))
        })?;
        f(&mut conn)
    })
    .await
    .map_err(|e| AppError::DatabaseQueryError(format!("Task join error: {}", e)))?
}
