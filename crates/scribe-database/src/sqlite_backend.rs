//! SQLite database backend implementation
//!
//! This module provides the SQLite-specific implementation of the DbBackend trait.
//! Used for desktop mode to provide an embedded database experience.

use super::backend_trait::DbBackend;
use crate::error::DatabaseError;
use diesel::sqlite::SqliteConnection;
use diesel::Connection;

/// SQLite backend implementation
pub struct SqliteBackend;

impl DbBackend for SqliteBackend {
    type Connection = SqliteConnection;

    fn establish_connection(url: &str) -> Result<Self::Connection, DatabaseError> {
        SqliteConnection::establish(url).map_err(|e| {
            DatabaseError::DatabaseQueryError(format!("Failed to connect to SQLite: {}", e))
        })
    }

    fn run_migrations(
        _conn: &mut Self::Connection,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // TODO: SQLite migrations will be implemented in Task 1.2.4
        // For now, this is a no-op to allow the backend to compile
        // Once migrations_sqlite/ directory is populated with converted migrations,
        // this will use: embed_migrations!("./migrations_sqlite")
        tracing::warn!(
            "SQLite migrations not yet implemented - database schema must be manually initialized"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqlite_connection_memory() {
        // Test in-memory SQLite database (doesn't require external setup)
        let result = SqliteBackend::establish_connection(":memory:");
        assert!(
            result.is_ok(),
            "Failed to establish in-memory SQLite connection"
        );
    }

    #[test]
    fn test_sqlite_connection_file() {
        // Test file-based SQLite database
        use std::env;
        let temp_dir = env::temp_dir();
        let db_path = temp_dir.join("test_scribe.db");
        let db_url = format!("file:{}", db_path.display());

        let result = SqliteBackend::establish_connection(&db_url);
        assert!(
            result.is_ok(),
            "Failed to establish file-based SQLite connection"
        );

        // Cleanup
        let _ = std::fs::remove_file(db_path);
    }
}
