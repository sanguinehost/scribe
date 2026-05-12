//! Database pooling helpers for scribe-identity
//!
//! Provides a unified async interface for both PostgreSQL and SQLite.

pub use scribe_core::{DbBigInt, DbBlob, DbId, DbTimestamp};
use scribe_core::AppError;

#[cfg(feature = "postgres-backend")]
pub type DbConnection = diesel::pg::PgConnection;

#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
pub type DbConnection = diesel::sqlite::SqliteConnection;

pub type DbConn = DbConnection;

#[cfg(feature = "postgres-backend")]
pub type DbPool = deadpool_diesel::postgres::Pool;

#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
pub type DbPool = diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<DbConnection>>;

/// Pooled connection type alias
#[cfg(feature = "postgres-backend")]
pub type PooledConn = deadpool_diesel::postgres::Object;

#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
pub type PooledConn = diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<DbConnection>>;

/// Execute a blocking database operation with a connection (unified interface)
#[cfg(feature = "postgres-backend")]
pub async fn with_conn<F, T>(pool: &DbPool, f: F) -> Result<T, AppError>
where
    F: FnOnce(&mut DbConnection) -> Result<T, AppError> + Send + 'static,
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

#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
pub async fn with_conn<F, T>(pool: &DbPool, f: F) -> Result<T, AppError>
where
    F: FnOnce(&mut DbConnection) -> Result<T, AppError> + Send + 'static,
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

#[cfg(feature = "postgres-backend")]
pub async fn with_conn_immediate<F, T>(pool: &DbPool, f: F) -> Result<T, AppError>
where
    F: FnOnce(&mut DbConnection) -> Result<T, AppError> + Send + 'static,
    T: Send + 'static,
{
    with_conn(pool, f).await
}

#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
pub async fn with_conn_immediate<F, T>(pool: &DbPool, f: F) -> Result<T, AppError>
where
    F: FnOnce(&mut DbConnection) -> Result<T, AppError> + Send + 'static,
    T: Send + 'static,
{
    let pool = pool.clone();
    tokio::task::spawn_blocking(move || {
        use diesel::prelude::*;
        let mut conn = pool.get().map_err(|e| {
            AppError::DatabaseQueryError(format!("Failed to get connection: {}", e))
        })?;

        diesel::sql_query("BEGIN IMMEDIATE").execute(&mut conn)
            .map_err(|e| AppError::DatabaseQueryError(format!("Failed to begin immediate transaction: {}", e)))?;

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
            let _ = diesel::sql_query("ROLLBACK").execute(&mut conn);
        }

        result
    })
    .await
    .map_err(|e| AppError::DatabaseQueryError(format!("Task join error: {}", e)))?
}
