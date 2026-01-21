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

// Extension trait to provide async .get() for SQLite pools (compatibility with PostgreSQL async pools)
#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
pub trait SqlitePoolExt {
    type Connection;
    async fn get(
        &self,
    ) -> Result<
        diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<crate::db::DbConnection>>,
        diesel::r2d2::Error,
    >;
}

#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
impl SqlitePoolExt for DbPool {
    type Connection =
        diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<crate::db::DbConnection>>;

    async fn get(&self) -> Result<Self::Connection, diesel::r2d2::Error> {
        let pool = self.clone();
        match tokio::task::spawn_blocking(move || pool.get()).await {
            Ok(result) => result.map_err(|e| {
                // Convert r2d2::Error to diesel::r2d2::Error
                // They're the same type, just accessed via different paths
                match e {
                    _ => diesel::r2d2::Error::ConnectionError(
                        diesel::ConnectionError::BadConnection(format!("r2d2 error: {}", e)),
                    ),
                }
            }),
            Err(_) => Err(diesel::r2d2::Error::ConnectionError(
                diesel::ConnectionError::BadConnection("spawn_blocking panicked".to_string()),
            )),
        }
    }
}

// Extension trait to provide .interact() compatibility for SQLite connections
// Note: For SQLite with r2d2, the connection is synchronous and not Send-safe.
// We require &mut self because r2d2::PooledConnection needs mutable access for Diesel queries.
//
// This differs from PostgreSQL's deadpool which takes &self and uses spawn_blocking internally,
// but r2d2::PooledConnection cannot be moved across thread boundaries (contains NonNull pointers).
//
// IMPORTANT: This means SQLite code must use `let mut conn` while PostgreSQL uses `let conn`.
// The trait signature matches the closure return type: T can be Result<U, E> to support ?? pattern.
#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
pub trait SqliteInteractExt {
    async fn interact<F, T>(&mut self, f: F) -> Result<T, AppError>
    where
        F: FnOnce(&mut crate::db::DbConnection) -> T + Send + 'static,
        T: Send + 'static;
}

#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
impl SqliteInteractExt
    for diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<crate::db::DbConnection>>
{
    async fn interact<F, T>(&mut self, f: F) -> Result<T, AppError>
    where
        F: FnOnce(&mut crate::db::DbConnection) -> T + Send + 'static,
        T: Send + 'static,
    {
        // For SQLite, the connection was already obtained via spawn_blocking in get().
        // Since we have mutable access, we can directly execute the query synchronously.
        // The connection implements DerefMut to get &mut SqliteConnection for Diesel.
        Ok(f(&mut **self))
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

#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
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

/// Execute a blocking database operation with an IMMEDIATE connection (SQLite only)
///
/// For PostgreSQL, this is an alias for with_conn.
/// For SQLite, this uses BEGIN IMMEDIATE to prevent "database is locked" errors.
#[cfg(feature = "postgres-backend")]
pub async fn with_conn_immediate<F, T>(pool: &DbPool, f: F) -> Result<T, AppError>
where
    F: FnOnce(&mut crate::db::DbConnection) -> Result<T, AppError> + Send + 'static,
    T: Send + 'static,
{
    with_conn(pool, f).await
}

#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
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

/// Execute a blocking database operation with an IMMEDIATE connection (SQLite only)
///
/// For SQLite, this uses BEGIN IMMEDIATE to prevent "database is locked" errors.
#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
pub async fn with_conn_immediate<F, T>(pool: &DbPool, f: F) -> Result<T, AppError>
where
    F: FnOnce(&mut crate::db::DbConnection) -> Result<T, AppError> + Send + 'static,
    T: Send + 'static,
{
    let pool = pool.clone();
    tokio::task::spawn_blocking(move || {
        use diesel::prelude::*;
        let mut conn = pool.get().map_err(|e| {
            AppError::DatabaseQueryError(format!("Failed to get connection: {}", e))
        })?;

        let mut attempts = 0;
        let max_attempts = 5;
        let mut delay = std::time::Duration::from_millis(50);

        loop {
            // Start an IMMEDIATE transaction manually to prevent "database is locked"
            let begin_result = diesel::sql_query("BEGIN IMMEDIATE").execute(&mut conn);

            match begin_result {
                Ok(_) => break,
                Err(e) => {
                    attempts += 1;
                    if attempts >= max_attempts {
                        return Err(AppError::DatabaseQueryError(format!(
                            "Failed to begin immediate transaction after {} attempts: {}",
                            max_attempts, e
                        )));
                    }

                    // Check if it's a busy/locked error
                    let error_string = e.to_string();
                    let is_locked = error_string.contains("database is locked")
                        || error_string.contains("database table is locked")
                        || error_string.contains("busy");
                    if !is_locked {
                        return Err(AppError::DatabaseQueryError(format!(
                            "Failed to begin immediate transaction: {}",
                            e
                        )));
                    }

                    // Wait and retry
                    std::thread::sleep(delay);
                    delay = std::cmp::min(delay * 2, std::time::Duration::from_millis(1000));
                }
            }
        }

        let result = f(&mut conn);

        if result.is_ok() {
            diesel::sql_query("COMMIT")
                .execute(&mut conn)
                .map_err(|e| {
                    AppError::DatabaseQueryError(format!(
                        "Failed to commit immediate transaction: {}",
                        e
                    ))
                })?;
        } else {
            // Rollback on error
            let _ = diesel::sql_query("ROLLBACK").execute(&mut conn);
        }

        result
    })
    .await
    .map_err(|e| AppError::DatabaseQueryError(format!("Task join error: {}", e)))?
}
