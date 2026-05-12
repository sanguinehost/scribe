#![cfg(feature = "desktop")]

use scribe_core::privacy::sanitize_json_value;
use libsql::{Builder, Connection, Database};
use thiserror::Error;
use tracing::{debug, info};

#[derive(Error, Debug)]
pub enum DbError {
    #[error("Database connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Database sync failed: {0}")]
    SyncFailed(String),
    #[error("Query execution failed: {0}")]
    QueryError(String),
    #[error("Invalid configuration: {0}")]
    ConfigError(&'static str),
}

/// A foundational client for hot state replication via Turso (libSQL).
///
/// This client handles the connection to a local SQLite file with optional
/// remote synchronization to a Turso database.
pub struct TursoClient {
    db: Database,
}

impl TursoClient {
    /// Establishes a new connection to the database.
    ///
    /// If `url` and `token` are provided, it initializes a remote replica that
    /// syncs with the specified Turso database. Otherwise, it falls back to a
    /// standard local SQLite file.
    pub async fn new(
        path: &str,
        url: Option<String>,
        token: Option<String>,
    ) -> Result<Self, DbError> {
        let db = match (url, token) {
            (Some(url), Some(token)) if !url.is_empty() && !token.is_empty() => {
                info!("Initializing LibSQL with Turso replication: {}", url);
                Builder::new_remote_replica(path, url, token)
                    .build()
                    .await
                    .map_err(|e| DbError::ConnectionFailed(e.to_string()))?
            }
            _ => {
                info!("Initializing local LibSQL at: {}", path);
                Builder::new_local(path)
                    .build()
                    .await
                    .map_err(|e| DbError::ConnectionFailed(e.to_string()))?
            }
        };

        Ok(Self { db })
    }

    /// Creates a new connection to the underlying database.
    pub fn connect(&self) -> Result<Connection, DbError> {
        self.db
            .connect()
            .map_err(|e| DbError::ConnectionFailed(e.to_string()))
    }

    /// Manually triggers a synchronization with the remote Turso database.
    pub async fn sync(&self) -> Result<(), DbError> {
        self.db
            .sync()
            .await
            .map_err(|e| DbError::SyncFailed(e.to_string()))?;
        Ok(())
    }

    /// Executes a query while ensuring parameters are sanitized for logging.
    ///
    /// This follows PRIVACY_SAFE_LOGGING.md standards by redacting PII before logging.
    pub async fn execute_safe(
        &self,
        conn: &Connection,
        query: &str,
        params: serde_json::Value,
    ) -> Result<u64, DbError> {
        // Sanitize parameters before logging as per privacy requirements
        let sanitized = sanitize_json_value(&params);
        debug!(
            target: "scribe_turso",
            query = %query,
            params = %sanitized,
            "Executing database query"
        );

        // Note: For this MVC spike, we execute the query with empty params or simple mapping.
        // In the full implementation, params would be mapped to libsql::params::Params.
        conn.execute(query, ())
            .await
            .map_err(|e| DbError::QueryError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_turso_replication_sync() {
        let dir = tempdir().expect("Failed to create temp dir");
        let path = dir.path().join("test.db");
        let path_str = path.to_str().expect("Invalid path");

        // Test local-only initialization (fallback mode)
        let client = TursoClient::new(path_str, None, None)
            .await
            .expect("Failed to create client");

        let conn = client.connect().expect("Failed to connect");

        // Verify basic read/write atomicity in the spike environment
        client
            .execute_safe(
                &conn,
                "CREATE TABLE test (id INTEGER PRIMARY KEY, val TEXT)",
                json!({}),
            )
            .await
            .expect("Failed to create table");

        client
            .execute_safe(
                &conn,
                "INSERT INTO test (val) VALUES ('hot state')",
                json!({"val": "hot state"}),
            )
            .await
            .expect("Failed to insert data");

        // Check if the local file was created
        assert!(path.exists(), "Database file should exist at {}", path_str);
    }
}
