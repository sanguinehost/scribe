//! Backend-agnostic JSON wrapper type for Diesel
//!
//! This module provides a generic `Json<T>` type that works across both PostgreSQL and SQLite backends.
//! - PostgreSQL: Stores data in JSONB columns
//! - SQLite: Stores JSON as TEXT
//!
//! This allows the same code to work with both backends without conditional compilation at usage sites.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

#[cfg(feature = "postgres-backend")]
use diesel::sql_types::Jsonb;
#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
use diesel::sql_types::Text;

/// Generic JSON wrapper for database storage
///
/// Stores any serializable type T as JSON in the database.
/// Provides Deref/DerefMut for ergonomic access to the inner value.
#[derive(Clone, PartialEq, Eq, Default)]
#[cfg_attr(
    feature = "postgres-backend",
    derive(diesel::expression::AsExpression, diesel::deserialize::FromSqlRow)
)]
#[cfg_attr(feature = "postgres-backend", diesel(sql_type = Jsonb))]
#[cfg_attr(
    all(feature = "sqlite-backend", not(feature = "postgres-backend")),
    derive(diesel::expression::AsExpression, diesel::deserialize::FromSqlRow)
)]
#[cfg_attr(all(feature = "sqlite-backend", not(feature = "postgres-backend")), diesel(sql_type = Text))]
#[repr(transparent)]
pub struct Json<T>(pub T);

impl<T> std::fmt::Debug for Json<T>
where
    T: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Json").field(&self.0).finish()
    }
}

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

impl<T> Deref for Json<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Json<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> AsRef<T> for Json<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T> AsMut<T> for Json<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> From<T> for Json<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T: Serialize> Serialize for Json<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Json<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Json)
    }
}

// ============================================================================
// PostgreSQL Backend Implementations
// ============================================================================

#[cfg(feature = "postgres-backend")]
mod pg_impl {
    use super::*;
    use diesel::{
        deserialize::{self, FromSql},
        pg::{Pg, PgValue},
        serialize::{self, IsNull, Output, ToSql},
        sql_types::Text,
    };
    use std::io::Write;

    impl<T> FromSql<Jsonb, Pg> for Json<T>
    where
        T: DeserializeOwned,
    {
        fn from_sql(bytes: PgValue<'_>) -> deserialize::Result<Self> {
            let bytes = bytes.as_bytes();
            if bytes[0] != 1 {
                return Err("Unsupported JSONB version".into());
            }
            let value = serde_json::from_slice(&bytes[1..])
                .map_err(|e| format!("Failed to parse JSON from JSONB: {}", e))?;
            Ok(Json(value))
        }
    }

    impl<T> ToSql<Jsonb, Pg> for Json<T>
    where
        T: Serialize + std::fmt::Debug,
    {
        fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
            out.write_all(&[1])?; // JSONB version 1
            serde_json::to_writer(out, &self.0)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            Ok(IsNull::No)
        }
    }

    impl<T> FromSql<Text, Pg> for Json<T>
    where
        T: DeserializeOwned,
    {
        fn from_sql(bytes: PgValue<'_>) -> deserialize::Result<Self> {
            let text = <String as FromSql<Text, Pg>>::from_sql(bytes)?;
            let value = serde_json::from_str(&text)
                .map_err(|e| format!("Failed to parse JSON from TEXT: {}", e))?;
            Ok(Json(value))
        }
    }

    impl<T> ToSql<Text, Pg> for Json<T>
    where
        T: Serialize + std::fmt::Debug,
    {
        fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
            let json_str = serde_json::to_string(&self.0)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            out.write_all(json_str.as_bytes())?;
            Ok(IsNull::No)
        }
    }
}

// ============================================================================
// SQLite Backend Implementations
// ============================================================================

#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
mod sqlite_impl {
    use super::*;
    use diesel::{
        backend::Backend,
        deserialize::{self, FromSql},
        serialize::{self, IsNull, Output, ToSql},
        sqlite::Sqlite,
    };

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
}
