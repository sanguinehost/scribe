//! Backend-agnostic trait system for dual Postgres/SQLite support
//!
//! This module defines the core trait that enables writing database code that works
//! with both PostgreSQL and SQLite backends without runtime overhead. The trait system
//! provides compile-time guarantees about type safety while abstracting over backend-specific
//! type differences.
//!
//! # Architecture
//!
//! The `DbType` trait represents a logical database type (like "ID" or "Timestamp") that
//! has different physical representations in PostgreSQL vs SQLite:
//! - PostgreSQL: Native UUID, TIMESTAMPTZ, NUMERIC types
//! - SQLite: TEXT, INTEGER for everything (with newtype wrappers)
//!
//! Conditional compilation (`#[cfg(feature = "postgres-backend")]`) ensures only the
//! relevant backend's code is compiled, resulting in zero runtime overhead.
//!
//! # Example
//!
//! ```ignore
//! use crate::db::{DbId, DbTimestamp};
//!
//! #[derive(Queryable)]
//! struct User {
//!     id: DbId,              // PostgreSQL: Uuid, SQLite: SqliteUuid (TEXT)
//!     created_at: DbTimestamp, // PostgreSQL: DateTime<Utc>, SQLite: SqliteDateTime (INTEGER)
//! }
//! ```

use diesel::deserialize::FromSql;
use diesel::serialize::ToSql;
use diesel::sql_types::SqlType;

#[cfg(feature = "postgres-backend")]
use diesel::pg::Pg;

#[cfg(feature = "sqlite-backend")]
use diesel::sqlite::Sqlite;

// Backend type imports - conditionally compiled based on features
// When a backend isn't enabled, we don't import it, which means trait bounds
// referencing it will fail to compile. This is intentional - the DbType trait
// design requires restructuring to avoid this issue.
//
// TODO: Refactor DbType trait to use conditional compilation or type parameters
// instead of hardcoded Pg/Sqlite references in trait bounds.

/// Unified trait for database types that can be stored in both PostgreSQL and SQLite
///
/// This trait provides a clean abstraction over backend-specific type representations.
/// All database model fields should use types implementing this trait to ensure
/// dual-backend compatibility.
///
/// # Type Parameters
///
/// The trait uses associated types to define the backend-specific representations:
/// - `PgType`: The Rust type used for PostgreSQL (e.g., `uuid::Uuid`)
/// - `SqliteType`: The Rust type used for SQLite (e.g., `SqliteUuid`)
/// - `PgSqlType`: The Diesel SQL type for PostgreSQL (e.g., `diesel::sql_types::Uuid`)
/// - `SqliteSqlType`: The Diesel SQL type for SQLite (e.g., `diesel::sql_types::Text`)
///
/// # Backend-Agnostic Methods
///
/// The trait defines separate methods for each backend to avoid conditional compilation
/// issues. All types implementing DbType must provide conversions for both backends.
///
/// Convenience methods `to_backend_type()` and `from_backend_type()` are provided
/// via the `DbTypeExt` trait, which delegates to the correct backend method based
/// on feature flags at compile time.
pub trait DbType: Sized + Send + std::fmt::Debug {
    /// PostgreSQL representation of this type
    ///
    /// Must implement Diesel's FromSql and ToSql for the PostgreSQL backend.
    #[cfg(feature = "postgres-backend")]
    type PgType: FromSql<Self::PgSqlType, Pg>
        + ToSql<Self::PgSqlType, Pg>
        + Send;
    #[cfg(not(feature = "postgres-backend"))]
    type PgType: Send + std::fmt::Debug;

    /// SQLite representation of this type
    ///
    /// Must implement Diesel's FromSql and ToSql for the SQLite backend.
    #[cfg(feature = "sqlite-backend")]
    type SqliteType: FromSql<Self::SqliteSqlType, Sqlite>
        + ToSql<Self::SqliteSqlType, Sqlite>
        + Send;
    #[cfg(not(feature = "sqlite-backend"))]
    type SqliteType: Send + std::fmt::Debug;

    /// Diesel SQL type used in PostgreSQL
    #[cfg(feature = "postgres-backend")]
    type PgSqlType: SqlType;
    #[cfg(not(feature = "postgres-backend"))]
    type PgSqlType: std::fmt::Debug;

    /// Diesel SQL type used in SQLite
    #[cfg(feature = "sqlite-backend")]
    type SqliteSqlType: SqlType;
    #[cfg(not(feature = "sqlite-backend"))]
    type SqliteSqlType: std::fmt::Debug;

    /// Convert to PostgreSQL-specific type
    ///
    /// This method is always available but only called when using PostgreSQL backend.
    /// The conversion should be lightweight (ideally zero-cost through newtype unwrapping).
    fn to_pg_type(&self) -> Self::PgType;

    /// Create from PostgreSQL-specific type
    ///
    /// This method is always available but only called when using PostgreSQL backend.
    /// Used by Diesel when loading data from the database.
    fn from_pg_type(value: Self::PgType) -> Self;

    /// Convert to SQLite-specific type
    ///
    /// This method is always available but only called when using SQLite backend.
    /// The conversion should be lightweight (ideally zero-cost through newtype unwrapping).
    fn to_sqlite_type(&self) -> Self::SqliteType;

    /// Create from SQLite-specific type
    ///
    /// This method is always available but only called when using SQLite backend.
    /// Used by Diesel when loading data from the database.
    fn from_sqlite_type(value: Self::SqliteType) -> Self;
}

/// Helper trait for types that can appear in SQL WHERE clauses
///
/// This trait is automatically implemented for types that implement DbType and
/// provides the necessary Diesel expression traits for use in queries.
pub trait DbExpression: DbType {
    /// Check if this type can be used in expressions for the given backend
    #[cfg(feature = "postgres-backend")]
    fn is_pg_expression() -> bool {
        true
    }

    #[cfg(feature = "sqlite-backend")]
    fn is_sqlite_expression() -> bool {
        true
    }
}

// Automatically implement DbExpression for all DbType implementors
impl<T: DbType> DbExpression for T {}

#[cfg(all(test, feature = "postgres-backend"))]
mod tests {
    

    // Test that the trait compiles and basic usage works
    // (Actual implementations are tested in unified_types.rs)
    #[test]
    fn test_db_type_trait_compiles() {
        // This test just ensures the trait definition compiles
        // Real implementations will be tested in their respective modules
    }
}
