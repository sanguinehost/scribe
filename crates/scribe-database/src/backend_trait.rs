//! Database backend trait for abstracting over PostgreSQL and SQLite
//!
//! This module defines the core abstraction that allows the application to work
//! with either PostgreSQL (cloud) or SQLite (desktop) backends.

use crate::DatabaseError;
use diesel::Connection;

/// Trait defining the interface for database backends
///
/// Implementors of this trait provide backend-specific logic for establishing
/// connections and running migrations.
pub trait DbBackend {
    /// The Diesel connection type for this backend (PgConnection or SqliteConnection)
    type Connection: Connection;

    /// Establish a connection to the database
    ///
    /// # Arguments
    /// * `url` - Database connection URL
    ///
    /// # Returns
    /// A connection to the database or an error
    fn establish_connection(url: &str) -> Result<Self::Connection, DatabaseError>;

    /// Run all pending migrations on the given connection
    ///
    /// # Arguments
    /// * `conn` - Mutable reference to a database connection
    ///
    /// # Returns
    /// Ok if migrations succeed, error otherwise
    fn run_migrations(
        conn: &mut Self::Connection,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}
