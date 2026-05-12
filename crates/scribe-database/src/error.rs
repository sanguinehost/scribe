use thiserror::Error;
use scribe_core::error::CoreError;

#[derive(Error, Debug, Clone)]
pub enum DatabaseError {
    #[error("Database query failed: {0}")]
    DatabaseQueryError(String),

    #[error("Database pool error: {0}")]
    DbPoolError(String),

    #[error("Database interaction error: {0}")]
    DbInteractError(String),

    #[error("Database migration error: {0}")]
    DbMigrationError(String),

    #[error("Entity not found: {0}")]
    NotFound(String),

    #[error("Constraint violation: {0}")]
    Conflict(String),
    
    #[error("Internal database error: {0}")]
    Internal(String),
}

impl From<DatabaseError> for CoreError {
    fn from(err: DatabaseError) -> Self {
        match err {
            DatabaseError::NotFound(msg) => CoreError::NotFound(msg),
            DatabaseError::Conflict(msg) => CoreError::Conflict(msg),
            _ => CoreError::Internal(err.to_string()),
        }
    }
}

// Diesel error conversion
impl From<diesel::result::Error> for DatabaseError {
    fn from(err: diesel::result::Error) -> Self {
        match err {
            diesel::result::Error::NotFound => DatabaseError::NotFound("Entity not found".to_string()),
            diesel::result::Error::DatabaseError(kind, info) => {
                use diesel::result::DatabaseErrorKind;
                match kind {
                    DatabaseErrorKind::UniqueViolation => DatabaseError::Conflict(info.message().to_string()),
                    DatabaseErrorKind::ForeignKeyViolation => DatabaseError::Conflict(info.message().to_string()),
                    _ => DatabaseError::DatabaseQueryError(info.message().to_string()),
                }
            }
            _ => DatabaseError::DatabaseQueryError(err.to_string()),
        }
    }
}

// Deadpool pool error conversion
#[cfg(feature = "postgres-backend")]
impl From<deadpool_diesel::PoolError> for DatabaseError {
    fn from(err: deadpool_diesel::PoolError) -> Self {
        DatabaseError::DbPoolError(err.to_string())
    }
}

#[cfg(feature = "postgres-backend")]
impl From<deadpool_diesel::InteractError> for DatabaseError {
    fn from(err: deadpool_diesel::InteractError) -> Self {
        DatabaseError::DbInteractError(err.to_string())
    }
}

// r2d2 error conversion
#[cfg(feature = "sqlite-backend")]
impl From<diesel::r2d2::Error> for DatabaseError {
    fn from(err: diesel::r2d2::Error) -> Self {
        DatabaseError::DbPoolError(err.to_string())
    }
}
