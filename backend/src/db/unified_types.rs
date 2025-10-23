//! Unified database types for dual Postgres/SQLite support
//!
//! This module provides backend-agnostic wrappers for common database types.
//! Each type implements the `DbType` trait and provides seamless conversion
//! between PostgreSQL and SQLite representations.
//!
//! # Design Philosophy
//!
//! - **Zero Runtime Overhead**: Newtype wrappers with `#[repr(transparent)]` ensure no memory overhead
//! - **Type Safety**: Compile-time guarantees prevent mixing backend-specific types
//! - **Ergonomics**: Deref/DerefMut implementations allow transparent access to inner values
//! - **Serializability**: All types implement Serialize/Deserialize for API boundaries
//!
//! # Types Provided
//!
//! - `DbId`: UUID wrapper (Postgres: UUID, SQLite: TEXT)
//! - `DbTimestamp`: DateTime wrapper (Postgres: TIMESTAMPTZ, SQLite: INTEGER as Unix timestamp)
//! - `DbDecimal`: BigDecimal wrapper (Postgres: NUMERIC, SQLite: TEXT)
//! - `DbBlob`: Binary data wrapper (Postgres: BYTEA, SQLite: BLOB)
//! - `DbStringArray`: String array wrapper (Postgres: TEXT[], SQLite: JSON array as TEXT)

use super::backend_traits::DbType;

#[cfg(feature = "sqlite-backend")]
use super::sqlite_types::{SqliteBigDecimal, SqliteDateTime, SqliteUuid};

use bigdecimal::BigDecimal;
use chrono::{DateTime, Utc};
use diesel::deserialize::{self, FromSql, FromSqlRow};
use diesel::expression::AsExpression;
use diesel::serialize::{self, Output, ToSql};
use diesel::sql_types::{BigInt, Binary, Nullable, Numeric, Text, Timestamp};

#[cfg(feature = "postgres-backend")]
use diesel::pg::Pg;
#[cfg(feature = "postgres-backend")]
use diesel::sql_types::{Bytea, Timestamptz, Uuid as PgUuid};

#[cfg(feature = "sqlite-backend")]
use diesel::sqlite::Sqlite;
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};
use uuid::Uuid;

// ============================================================================
// DbId - Unified UUID Type
// ============================================================================

/// Backend-agnostic unique identifier
///
/// Stores UUIDs in both PostgreSQL (native UUID type) and SQLite (TEXT).
/// Provides transparent access to the underlying `uuid::Uuid` value.
///
/// # Examples
///
/// ```ignore
/// use crate::db::DbId;
/// use uuid::Uuid;
///
/// let id = DbId::new();
/// let uuid: &Uuid = &id;  // Deref to Uuid
/// ```
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, AsExpression, FromSqlRow,
)]
#[cfg_attr(feature = "postgres-backend", diesel(sql_type = PgUuid))]
#[cfg_attr(feature = "sqlite-backend", diesel(sql_type = Text))]
#[repr(transparent)]
pub struct DbId(Uuid);

impl DbId {
    /// Create a new random DbId
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a DbId from a UUID
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner UUID
    pub fn into_uuid(self) -> Uuid {
        self.0
    }

    /// Parse a DbId from a string
    pub fn parse_str(s: &str) -> Result<Self, uuid::Error> {
        Uuid::parse_str(s).map(Self)
    }

    /// Create a nil/zero DbId (all zeros)
    pub fn nil() -> Self {
        Self(Uuid::nil())
    }
}

impl Default for DbId {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for DbId {
    type Target = Uuid;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DbId {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Uuid> for DbId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<DbId> for Uuid {
    fn from(db_id: DbId) -> Self {
        db_id.0
    }
}

impl std::fmt::Display for DbId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl DbType for DbId {
    type PgType = Uuid;
    type SqliteType = SqliteUuid;
    type PgSqlType = PgUuid;
    type SqliteSqlType = Text;

    fn to_pg_type(&self) -> Self::PgType {
        self.0
    }

    fn from_pg_type(value: Self::PgType) -> Self {
        Self(value)
    }

    fn to_sqlite_type(&self) -> Self::SqliteType {
        SqliteUuid(self.0)
    }

    fn from_sqlite_type(value: Self::SqliteType) -> Self {
        Self(value.0)
    }
}

// Diesel trait implementations for DbId
#[cfg(feature = "postgres-backend")]
impl FromSql<PgUuid, Pg> for DbId {
    fn from_sql(
        bytes: <Pg as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let uuid = <Uuid as FromSql<PgUuid, Pg>>::from_sql(bytes)?;
        Ok(Self(uuid))
    }
}

#[cfg(feature = "postgres-backend")]
impl ToSql<PgUuid, Pg> for DbId {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        <Uuid as ToSql<PgUuid, Pg>>::to_sql(&self.0, out)
    }
}

#[cfg(feature = "sqlite-backend")]
impl FromSql<Text, Sqlite> for DbId {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let sqlite_uuid = <SqliteUuid as FromSql<Text, Sqlite>>::from_sql(bytes)?;
        Ok(Self(sqlite_uuid.0))
    }
}

#[cfg(feature = "sqlite-backend")]
impl ToSql<Text, Sqlite> for DbId {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
        let sqlite_uuid = SqliteUuid(self.0);
        <SqliteUuid as ToSql<Text, Sqlite>>::to_sql(&sqlite_uuid, out)
    }
}

// ============================================================================
// DbTimestamp - Unified DateTime Type
// ============================================================================

/// Backend-agnostic timestamp
///
/// Stores UTC timestamps in both PostgreSQL (TIMESTAMPTZ) and SQLite (INTEGER as Unix timestamp).
/// Provides transparent access to the underlying `chrono::DateTime<Utc>` value.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    AsExpression,
    FromSqlRow,
)]
#[cfg_attr(feature = "postgres-backend", diesel(sql_type = Timestamptz))]
#[cfg_attr(feature = "sqlite-backend", diesel(sql_type = Timestamp))]
#[repr(transparent)]
pub struct DbTimestamp(DateTime<Utc>);

impl DbTimestamp {
    /// Create a DbTimestamp from the current time
    pub fn now() -> Self {
        Self(Utc::now())
    }

    /// Create a DbTimestamp from a DateTime
    pub fn from_datetime(dt: DateTime<Utc>) -> Self {
        Self(dt)
    }

    /// Get the inner DateTime
    pub fn into_datetime(self) -> DateTime<Utc> {
        self.0
    }
}

impl Deref for DbTimestamp {
    type Target = DateTime<Utc>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DbTimestamp {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<DateTime<Utc>> for DbTimestamp {
    fn from(dt: DateTime<Utc>) -> Self {
        Self(dt)
    }
}

impl From<DbTimestamp> for DateTime<Utc> {
    fn from(ts: DbTimestamp) -> Self {
        ts.0
    }
}

impl std::fmt::Display for DbTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.to_rfc3339())
    }
}

impl DbType for DbTimestamp {
    type PgType = DateTime<Utc>;
    type SqliteType = SqliteDateTime;
    type PgSqlType = Timestamptz;
    type SqliteSqlType = BigInt;

    fn to_pg_type(&self) -> Self::PgType {
        self.0
    }

    fn from_pg_type(value: Self::PgType) -> Self {
        Self(value)
    }

    fn to_sqlite_type(&self) -> Self::SqliteType {
        SqliteDateTime(self.0)
    }

    fn from_sqlite_type(value: Self::SqliteType) -> Self {
        Self(value.0)
    }
}

#[cfg(feature = "postgres-backend")]
impl FromSql<Timestamptz, Pg> for DbTimestamp {
    fn from_sql(
        bytes: <Pg as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let dt = <DateTime<Utc> as FromSql<Timestamptz, Pg>>::from_sql(bytes)?;
        Ok(Self(dt))
    }
}

#[cfg(feature = "postgres-backend")]
impl ToSql<Timestamptz, Pg> for DbTimestamp {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        <DateTime<Utc> as ToSql<Timestamptz, Pg>>::to_sql(&self.0, out)
    }
}

#[cfg(feature = "sqlite-backend")]
impl FromSql<BigInt, Sqlite> for DbTimestamp {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let sqlite_dt = <SqliteDateTime as FromSql<BigInt, Sqlite>>::from_sql(bytes)?;
        Ok(Self(sqlite_dt.0))
    }
}

#[cfg(feature = "sqlite-backend")]
impl ToSql<BigInt, Sqlite> for DbTimestamp {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
        let sqlite_dt = SqliteDateTime(self.0);
        <SqliteDateTime as ToSql<BigInt, Sqlite>>::to_sql(&sqlite_dt, out)
    }
}

// Diesel's Timestamp type in SQLite stores as string, so we need FromSql<Timestamp, Sqlite>
#[cfg(feature = "sqlite-backend")]
impl FromSql<Timestamp, Sqlite> for DbTimestamp {
    fn from_sql(
        mut value: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        value.parse_string(|text| {
            // Try ISO 8601 formats
            if let Ok(dt) = DateTime::parse_from_rfc3339(text) {
                return Ok(Self(dt.with_timezone(&Utc)));
            }

            // Try parsing as Unix timestamp (seconds since epoch)
            if let Ok(timestamp) = text.parse::<i64>() {
                if let Some(dt) = DateTime::from_timestamp(timestamp, 0) {
                    return Ok(Self(dt));
                }
            }

            Err(format!("Invalid timestamp string: {}", text).into())
        })
    }
}

#[cfg(feature = "sqlite-backend")]
impl ToSql<Timestamp, Sqlite> for DbTimestamp {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
        // Serialize as ISO 8601 string for Timestamp type
        let formatted = self.0.to_rfc3339();
        ToSql::<Text, Sqlite>::to_sql(&formatted, out)
    }
}

// ============================================================================
// DbDecimal - Unified BigDecimal Type
// ============================================================================

/// Backend-agnostic arbitrary-precision decimal
///
/// Stores decimal numbers in both PostgreSQL (NUMERIC) and SQLite (TEXT).
/// Used for monetary values and other high-precision calculations.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, AsExpression, FromSqlRow,
)]
#[cfg_attr(feature = "postgres-backend", diesel(sql_type = Numeric))]
#[cfg_attr(feature = "sqlite-backend", diesel(sql_type = Text))]
#[repr(transparent)]
pub struct DbDecimal(BigDecimal);

impl DbDecimal {
    /// Create a DbDecimal from a BigDecimal
    pub fn from_bigdecimal(bd: BigDecimal) -> Self {
        Self(bd)
    }

    /// Get the inner BigDecimal
    pub fn into_bigdecimal(self) -> BigDecimal {
        self.0
    }

    /// Parse from string
    pub fn parse_str(s: &str) -> Result<Self, bigdecimal::ParseBigDecimalError> {
        s.parse::<BigDecimal>().map(Self)
    }

    /// Create from i64
    pub fn from_i64(value: i64) -> Self {
        Self(BigDecimal::from(value))
    }
}

impl Deref for DbDecimal {
    type Target = BigDecimal;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DbDecimal {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<BigDecimal> for DbDecimal {
    fn from(bd: BigDecimal) -> Self {
        Self(bd)
    }
}

impl From<DbDecimal> for BigDecimal {
    fn from(db_decimal: DbDecimal) -> Self {
        db_decimal.0
    }
}

impl From<i64> for DbDecimal {
    fn from(value: i64) -> Self {
        Self(BigDecimal::from(value))
    }
}

impl std::fmt::Display for DbDecimal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl DbType for DbDecimal {
    type PgType = BigDecimal;
    type SqliteType = SqliteBigDecimal;
    type PgSqlType = Numeric;
    type SqliteSqlType = Text;

    fn to_pg_type(&self) -> Self::PgType {
        self.0.clone()
    }

    fn from_pg_type(value: Self::PgType) -> Self {
        Self(value)
    }

    fn to_sqlite_type(&self) -> Self::SqliteType {
        SqliteBigDecimal(self.0.clone())
    }

    fn from_sqlite_type(value: Self::SqliteType) -> Self {
        Self(value.0)
    }
}

#[cfg(feature = "postgres-backend")]
impl FromSql<Numeric, Pg> for DbDecimal {
    fn from_sql(
        bytes: <Pg as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let bd = <BigDecimal as FromSql<Numeric, Pg>>::from_sql(bytes)?;
        Ok(Self(bd))
    }
}

#[cfg(feature = "postgres-backend")]
impl ToSql<Numeric, Pg> for DbDecimal {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        <BigDecimal as ToSql<Numeric, Pg>>::to_sql(&self.0, out)
    }
}

#[cfg(feature = "sqlite-backend")]
impl FromSql<Text, Sqlite> for DbDecimal {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let sqlite_bd = <SqliteBigDecimal as FromSql<Text, Sqlite>>::from_sql(bytes)?;
        Ok(Self(sqlite_bd.0))
    }
}

#[cfg(feature = "sqlite-backend")]
impl ToSql<Text, Sqlite> for DbDecimal {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
        let sqlite_bd = SqliteBigDecimal(self.0.clone());
        <SqliteBigDecimal as ToSql<Text, Sqlite>>::to_sql(&sqlite_bd, out)
    }
}

// ============================================================================
// DbBlob - Unified Binary Data Type
// ============================================================================

/// Backend-agnostic binary data
///
/// Stores binary data in both PostgreSQL (BYTEA) and SQLite (BLOB).
/// Used for encrypted data, hashes, and other binary content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, AsExpression, FromSqlRow)]
#[cfg_attr(feature = "postgres-backend", diesel(sql_type = Bytea))]
#[cfg_attr(feature = "sqlite-backend", diesel(sql_type = Binary))]
#[repr(transparent)]
pub struct DbBlob(Vec<u8>);

impl DbBlob {
    /// Create a DbBlob from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the inner bytes
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Get a slice of the bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for DbBlob {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DbBlob {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Default for DbBlob {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl From<Vec<u8>> for DbBlob {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<DbBlob> for Vec<u8> {
    fn from(blob: DbBlob) -> Self {
        blob.0
    }
}

impl DbType for DbBlob {
    type PgType = Vec<u8>;
    type SqliteType = Vec<u8>; // SQLite supports BLOB natively
    type PgSqlType = Bytea;
    type SqliteSqlType = diesel::sql_types::Binary;

    fn to_pg_type(&self) -> Self::PgType {
        self.0.clone()
    }

    fn from_pg_type(value: Self::PgType) -> Self {
        Self(value)
    }

    fn to_sqlite_type(&self) -> Self::SqliteType {
        self.0.clone()
    }

    fn from_sqlite_type(value: Self::SqliteType) -> Self {
        Self(value)
    }
}

#[cfg(feature = "postgres-backend")]
impl FromSql<Bytea, Pg> for DbBlob {
    fn from_sql(
        bytes: <Pg as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let vec = <Vec<u8> as FromSql<Bytea, Pg>>::from_sql(bytes)?;
        Ok(Self(vec))
    }
}

#[cfg(feature = "postgres-backend")]
impl ToSql<Bytea, Pg> for DbBlob {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        <Vec<u8> as ToSql<Bytea, Pg>>::to_sql(&self.0, out)
    }
}

#[cfg(feature = "sqlite-backend")]
impl FromSql<diesel::sql_types::Binary, Sqlite> for DbBlob {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let vec = <Vec<u8> as FromSql<diesel::sql_types::Binary, Sqlite>>::from_sql(bytes)?;
        Ok(Self(vec))
    }
}

#[cfg(feature = "sqlite-backend")]
impl ToSql<diesel::sql_types::Binary, Sqlite> for DbBlob {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
        <Vec<u8> as ToSql<diesel::sql_types::Binary, Sqlite>>::to_sql(&self.0, out)
    }
}

// ============================================================================
// DbStringArray - Unified String Array Type
// ============================================================================

/// Backend-agnostic optional string array
///
/// Stores arrays of optional strings in both PostgreSQL (TEXT[]) and SQLite (JSON array as TEXT).
/// Used for tags, keywords, and other list-based string fields.
///
/// # PostgreSQL Representation
/// Native array type: `TEXT[]` with nullable elements
///
/// # SQLite Representation
/// JSON array stored as TEXT: `["string1", "string2", null, "string3"]`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[repr(transparent)]
pub struct DbStringArray(Option<Vec<Option<String>>>);

impl DbStringArray {
    /// Create an empty DbStringArray (None)
    pub fn empty() -> Self {
        Self(None)
    }

    /// Create from a vector of optional strings
    pub fn from_vec(vec: Vec<Option<String>>) -> Self {
        Self(Some(vec))
    }

    /// Create from a vector of strings (all non-null)
    pub fn from_strings(strings: Vec<String>) -> Self {
        Self(Some(strings.into_iter().map(Some).collect()))
    }

    /// Get the inner optional vector
    pub fn into_option(self) -> Option<Vec<Option<String>>> {
        self.0
    }

    /// Get as a slice (if present)
    pub fn as_slice(&self) -> Option<&[Option<String>]> {
        self.0.as_deref()
    }

    /// Check if empty (None or empty vec)
    pub fn is_empty(&self) -> bool {
        self.0.as_ref().map_or(true, |v| v.is_empty())
    }

    /// Get length (0 if None)
    pub fn len(&self) -> usize {
        self.0.as_ref().map_or(0, |v| v.len())
    }

    /// Create from iterator
    pub fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = Option<String>>,
    {
        Self(Some(iter.into_iter().collect()))
    }
}

impl Default for DbStringArray {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<Option<Vec<Option<String>>>> for DbStringArray {
    fn from(opt: Option<Vec<Option<String>>>) -> Self {
        Self(opt)
    }
}

impl From<DbStringArray> for Option<Vec<Option<String>>> {
    fn from(arr: DbStringArray) -> Self {
        arr.0
    }
}

impl From<Vec<Option<String>>> for DbStringArray {
    fn from(vec: Vec<Option<String>>) -> Self {
        Self(Some(vec))
    }
}

impl From<Vec<String>> for DbStringArray {
    fn from(vec: Vec<String>) -> Self {
        Self::from_strings(vec)
    }
}

impl DbType for DbStringArray {
    type PgType = Option<Vec<Option<String>>>;
    type SqliteType = Option<String>; // JSON array as TEXT
    type PgSqlType = Nullable<diesel::sql_types::Array<Nullable<Text>>>;
    type SqliteSqlType = Nullable<Text>;

    fn to_pg_type(&self) -> Self::PgType {
        self.0.clone()
    }

    fn from_pg_type(value: Self::PgType) -> Self {
        Self(value)
    }

    fn to_sqlite_type(&self) -> Self::SqliteType {
        // Serialize to JSON array
        self.0
            .as_ref()
            .map(|vec| serde_json::to_string(vec).unwrap_or_else(|_| "[]".to_string()))
    }

    fn from_sqlite_type(value: Self::SqliteType) -> Self {
        match value {
            None => Self(None),
            Some(json_str) => {
                // Deserialize from JSON array
                match serde_json::from_str::<Vec<Option<String>>>(&json_str) {
                    Ok(vec) => Self(Some(vec)),
                    Err(_) => {
                        // Fallback: treat as empty array on parse error
                        tracing::warn!(
                            "Failed to parse DbStringArray from JSON, using empty array"
                        );
                        Self(None)
                    }
                }
            }
        }
    }
}

#[cfg(feature = "postgres-backend")]
impl FromSql<Nullable<diesel::sql_types::Array<Nullable<Text>>>, Pg> for DbStringArray {
    fn from_sql(
        bytes: <Pg as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let opt_vec = <Option<Vec<Option<String>>> as FromSql<
            Nullable<diesel::sql_types::Array<Nullable<Text>>>,
            Pg,
        >>::from_sql(bytes)?;
        Ok(Self(opt_vec))
    }
}

#[cfg(feature = "postgres-backend")]
impl ToSql<Nullable<diesel::sql_types::Array<Nullable<Text>>>, Pg> for DbStringArray {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        <Option<Vec<Option<String>>> as ToSql<
            Nullable<diesel::sql_types::Array<Nullable<Text>>>,
            Pg,
        >>::to_sql(&self.0, out)
    }
}

#[cfg(feature = "sqlite-backend")]
impl FromSql<Nullable<Text>, Sqlite> for DbStringArray {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let opt_json = <Option<String> as FromSql<Nullable<Text>, Sqlite>>::from_sql(bytes)?;
        Ok(Self::from_sqlite_type(opt_json))
    }
}

#[cfg(feature = "sqlite-backend")]
impl ToSql<Nullable<Text>, Sqlite> for DbStringArray {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
        let json_str = self.to_sqlite_type();
        <Option<String> as ToSql<Nullable<Text>, Sqlite>>::to_sql(&json_str, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_id_creation() {
        let id1 = DbId::new();
        let id2 = DbId::new();
        assert_ne!(id1, id2, "Each DbId should be unique");
    }

    #[test]
    fn test_db_id_from_uuid() {
        let uuid = Uuid::new_v4();
        let db_id = DbId::from_uuid(uuid);
        assert_eq!(*db_id, uuid);
    }

    #[test]
    fn test_db_timestamp_now() {
        let ts = DbTimestamp::now();
        assert!(ts.timestamp() > 0);
    }

    #[test]
    fn test_db_decimal_from_i64() {
        let dec = DbDecimal::from_i64(12345);
        assert_eq!(dec.to_string(), "12345");
    }

    #[test]
    fn test_db_blob_from_bytes() {
        let bytes = vec![1, 2, 3, 4, 5];
        let blob = DbBlob::from_bytes(bytes.clone());
        assert_eq!(blob.as_bytes(), &bytes[..]);
    }

    #[test]
    fn test_db_string_array_empty() {
        let arr = DbStringArray::empty();
        assert!(arr.is_empty());
        assert_eq!(arr.len(), 0);
    }

    #[test]
    fn test_db_string_array_from_strings() {
        let arr = DbStringArray::from_strings(vec!["a".to_string(), "b".to_string()]);
        assert_eq!(arr.len(), 2);
        assert!(!arr.is_empty());
    }

    #[test]
    #[cfg(feature = "sqlite-backend")]
    fn test_db_string_array_json_roundtrip() {
        let original = DbStringArray::from_vec(vec![
            Some("test1".to_string()),
            None,
            Some("test2".to_string()),
        ]);

        // Convert to JSON
        let json_str = original.to_backend_type();
        assert!(json_str.is_some());

        // Convert back
        let restored = DbStringArray::from_backend_type(json_str);
        assert_eq!(original, restored);
    }
}
