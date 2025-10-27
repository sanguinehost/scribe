//! Backend-agnostic JSON wrapper type for Diesel
//!
//! This module provides a generic `Json<T>` type that works across both PostgreSQL and SQLite backends.
//! - PostgreSQL: Uses diesel_json::Json<T> which stores data in JSONB columns
//! - SQLite: Uses a custom wrapper that stores JSON as TEXT
//!
//! This allows the same code to work with both backends without conditional compilation at usage sites.

// ============================================================================
// PostgreSQL Backend: Re-export diesel_json
// ============================================================================

#[cfg(feature = "postgres-backend")]
pub use diesel_json::Json;

// ============================================================================
// SQLite Backend: Custom Generic JSON Wrapper
// ============================================================================

#[cfg(feature = "sqlite-backend")]
use diesel::{
    backend::Backend,
    deserialize::{self, FromSql},
    serialize::{self, IsNull, Output, ToSql},
    sql_types::Text,
    sqlite::Sqlite,
};

#[cfg(feature = "sqlite-backend")]
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[cfg(feature = "sqlite-backend")]
use std::ops::{Deref, DerefMut};

/// Generic JSON wrapper for SQLite backend
///
/// Stores any serializable type T as JSON TEXT in the database.
/// Provides Deref/DerefMut for ergonomic access to the inner value.
///
/// # Type Requirements
/// - `T` must implement `Serialize` for database storage
/// - `T` must implement `DeserializeOwned` for database retrieval
///
/// # Examples
/// ```ignore
/// use crate::db::Json;
///
/// #[derive(Serialize, Deserialize)]
/// struct MyData {
///     field: String,
/// }
///
/// let json_data = Json::new(MyData { field: "value".to_string() });
/// // Access inner value via Deref
/// let field_value = &json_data.field;
/// ```
#[cfg(feature = "sqlite-backend")]
#[derive(
    Clone, PartialEq, Eq, diesel::expression::AsExpression, diesel::deserialize::FromSqlRow,
)]
#[diesel(sql_type = Text)]
#[repr(transparent)]
pub struct Json<T>(pub T);

// Manual Debug implementation to allow T that don't implement Debug
#[cfg(feature = "sqlite-backend")]
impl<T> std::fmt::Debug for Json<T>
where
    T: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Json").field(&self.0).finish()
    }
}

#[cfg(feature = "sqlite-backend")]
impl<T> Json<T> {
    /// Create a new Json wrapper around a value
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Consume the wrapper and return the inner value
    pub fn into_inner(self) -> T {
        self.0
    }
}

// ============================================================================
// Deref Implementations for Ergonomic Access
// ============================================================================

#[cfg(feature = "sqlite-backend")]
impl<T> Deref for Json<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(feature = "sqlite-backend")]
impl<T> DerefMut for Json<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// ============================================================================
// AsRef / AsMut Implementations
// ============================================================================

#[cfg(feature = "sqlite-backend")]
impl<T> AsRef<T> for Json<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

#[cfg(feature = "sqlite-backend")]
impl<T> AsMut<T> for Json<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

// ============================================================================
// Diesel FromSql Implementation: TEXT → T
// ============================================================================

/// Deserialize from SQLite TEXT column to Json<T>
///
/// Reads JSON string from TEXT column and deserializes to T
#[cfg(feature = "sqlite-backend")]
impl<T> FromSql<Text, Sqlite> for Json<T>
where
    T: DeserializeOwned,
{
    fn from_sql(bytes: <Sqlite as Backend>::RawValue<'_>) -> deserialize::Result<Self> {
        let text = <String as FromSql<Text, Sqlite>>::from_sql(bytes)?;
        let value = serde_json::from_str(&text)
            .map_err(|e| format!("Failed to parse JSON from TEXT: {}", e))?;
        Ok(Json(value))
    }
}

/// Support for nullable TEXT columns
#[cfg(feature = "sqlite-backend")]
impl<T> FromSql<diesel::sql_types::Nullable<Text>, Sqlite> for Json<T>
where
    T: DeserializeOwned,
{
    fn from_sql(bytes: <Sqlite as Backend>::RawValue<'_>) -> deserialize::Result<Self> {
        let text = <String as FromSql<Text, Sqlite>>::from_sql(bytes)?;
        let value = serde_json::from_str(&text)
            .map_err(|e| format!("Failed to parse JSON from TEXT: {}", e))?;
        Ok(Json(value))
    }
}

// ============================================================================
// Diesel ToSql Implementation: T → TEXT
// ============================================================================

/// Serialize Json<T> to SQLite TEXT column
///
/// Serializes T to JSON string and stores as TEXT
#[cfg(feature = "sqlite-backend")]
impl<T> ToSql<Text, Sqlite> for Json<T>
where
    T: Serialize + std::fmt::Debug,
{
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
        let json_str = serde_json::to_string(&self.0)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        out.set_value(json_str);
        Ok(IsNull::No)
    }
}

// ============================================================================
// Additional Trait Implementations
// ============================================================================

#[cfg(feature = "sqlite-backend")]
impl<T: Default> Default for Json<T> {
    fn default() -> Self {
        Self(T::default())
    }
}

#[cfg(feature = "sqlite-backend")]
impl<T> From<T> for Json<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

// ============================================================================
// Serialization Support
// ============================================================================

/// Serialize Json<T> by serializing the inner T
///
/// This allows Json<T> to be used in structs that derive Serialize
#[cfg(feature = "sqlite-backend")]
impl<T: Serialize> Serialize for Json<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

/// Deserialize Json<T> by deserializing the inner T
///
/// This allows Json<T> to be used in structs that derive Deserialize
#[cfg(feature = "sqlite-backend")]
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Json<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Json)
    }
}
