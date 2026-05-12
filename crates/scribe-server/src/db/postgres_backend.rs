//! PostgreSQL database backend implementation
//!
//! This module provides the PostgreSQL-specific implementation of the DbBackend trait.

use super::backend_trait::DbBackend;
use crate::errors::AppError;
use diesel::pg::PgConnection;
use diesel::Connection;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

/// Embedded PostgreSQL migrations from the migrations directory
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

/// PostgreSQL backend implementation
pub struct PostgresBackend;

impl DbBackend for PostgresBackend {
    type Connection = PgConnection;

    fn establish_connection(url: &str) -> Result<Self::Connection, AppError> {
        PgConnection::establish(url).map_err(|e| {
            AppError::DatabaseQueryError(format!("Failed to connect to PostgreSQL: {}", e))
        })
    }

    fn run_migrations(
        conn: &mut Self::Connection,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        conn.run_pending_migrations(MIGRATIONS).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires actual PostgreSQL database
    fn test_postgres_connection() {
        // This test requires DATABASE_URL to be set
        let db_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set for PostgreSQL connection tests");

        let result = PostgresBackend::establish_connection(&db_url);
        assert!(result.is_ok(), "Failed to establish PostgreSQL connection");
    }
}
