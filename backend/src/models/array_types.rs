//! Cross-database array type support
//!
//! PostgreSQL has native ARRAY support, but SQLite stores arrays as JSON TEXT.
//! This module provides a newtype wrapper that handles serialization/deserialization
//! for both backends transparently.

use diesel::deserialize::{self, FromSql};
use diesel::serialize::{self, Output, ToSql};
use diesel::sql_types::{Nullable, Text};
use serde::{Deserialize, Serialize};

#[cfg(feature = "postgres-backend")]
use diesel::pg::Pg;
#[cfg(feature = "postgres-backend")]
use diesel::sql_types::Array;

#[cfg(feature = "sqlite-backend")]
use diesel::sqlite::Sqlite;

/// Wrapper for `Option<Vec<Option<String>>>` that works with both PostgreSQL ARRAY
/// and SQLite JSON TEXT storage.
///
/// PostgreSQL: Uses native ARRAY<TEXT> type
/// SQLite: Serializes to/from JSON TEXT
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    diesel::expression::AsExpression,
    diesel::deserialize::FromSqlRow,
)]
#[cfg_attr(feature = "postgres-backend", diesel(sql_type = Array<Nullable<Text>>))]
#[cfg_attr(feature = "sqlite-backend", diesel(sql_type = Nullable<Text>))]
#[serde(transparent)]
pub struct OptionalStringArray(pub Option<Vec<Option<String>>>);

impl OptionalStringArray {
    /// Create a new OptionalStringArray
    pub fn new(data: Option<Vec<Option<String>>>) -> Self {
        Self(data)
    }

    /// Get the inner value
    pub fn into_inner(self) -> Option<Vec<Option<String>>> {
        self.0
    }

    /// Get a reference to the inner value
    pub fn as_ref(&self) -> Option<&Vec<Option<String>>> {
        self.0.as_ref()
    }
}

impl Default for OptionalStringArray {
    fn default() -> Self {
        Self(None)
    }
}

// Implement From trait for easy conversion
impl From<Option<Vec<Option<String>>>> for OptionalStringArray {
    fn from(value: Option<Vec<Option<String>>>) -> Self {
        Self(value)
    }
}

impl From<OptionalStringArray> for Option<Vec<Option<String>>> {
    fn from(value: OptionalStringArray) -> Self {
        value.0
    }
}

// PostgreSQL: Native ARRAY support
#[cfg(feature = "postgres-backend")]
impl FromSql<Array<Nullable<Text>>, Pg> for OptionalStringArray {
    fn from_sql(bytes: diesel::pg::PgValue) -> deserialize::Result<Self> {
        let value =
            <Option<Vec<Option<String>>> as FromSql<Array<Nullable<Text>>, Pg>>::from_sql(bytes)?;
        Ok(Self(value))
    }
}

#[cfg(feature = "postgres-backend")]
impl ToSql<Array<Nullable<Text>>, Pg> for OptionalStringArray {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        <Option<Vec<Option<String>>> as ToSql<Array<Nullable<Text>>, Pg>>::to_sql(&self.0, out)
    }
}

// SQLite: JSON TEXT storage
#[cfg(feature = "sqlite-backend")]
impl FromSql<Nullable<Text>, Sqlite> for OptionalStringArray {
    fn from_sql(bytes: diesel::sqlite::SqliteValue) -> deserialize::Result<Self> {
        let text = <Option<String> as FromSql<Nullable<Text>, Sqlite>>::from_sql(bytes)?;

        match text {
            None => Ok(Self(None)),
            Some(json_str) => {
                let parsed: Option<Vec<Option<String>>> = serde_json::from_str(&json_str)
                    .map_err(|e| format!("Failed to parse JSON array: {}", e))?;
                Ok(Self(parsed))
            }
        }
    }
}

#[cfg(feature = "sqlite-backend")]
impl ToSql<Nullable<Text>, Sqlite> for OptionalStringArray {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
        match &self.0 {
            None => out.set_value(None::<String>),
            Some(vec) => {
                let json_str = serde_json::to_string(vec)
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
                out.set_value(json_str)
            }
        }
        Ok(serialize::IsNull::No)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optional_string_array_creation() {
        let arr = OptionalStringArray::new(Some(vec![Some("test".to_string()), None]));
        assert_eq!(arr.0, Some(vec![Some("test".to_string()), None]));
    }

    #[test]
    fn test_optional_string_array_default() {
        let arr = OptionalStringArray::default();
        assert_eq!(arr.0, None);
    }

    #[test]
    fn test_from_conversion() {
        let data = Some(vec![Some("test".to_string())]);
        let arr: OptionalStringArray = data.clone().into();
        assert_eq!(arr.0, data);
    }

    #[cfg(feature = "sqlite-backend")]
    #[test]
    fn test_sqlite_json_roundtrip() {
        let original = OptionalStringArray::new(Some(vec![
            Some("hello".to_string()),
            None,
            Some("world".to_string()),
        ]));

        // Serialize to JSON
        let json = serde_json::to_string(&original.0).unwrap();
        assert!(json.contains("hello"));
        assert!(json.contains("world"));

        // Deserialize back
        let parsed: Option<Vec<Option<String>>> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original.0);
    }
}
