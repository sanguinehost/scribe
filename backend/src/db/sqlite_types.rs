//! SQLite custom type mappings using newtype wrappers
//!
//! This module provides newtype wrappers for types that don't have built-in
//! SQLite support in Diesel. The newtype pattern allows us to implement
//! Diesel's FromSql and ToSql traits without violating the orphan rule.
//!
//! NOTE: This module is always compiled (not feature-gated) because the DbType trait
//! in backend_traits.rs requires both PgType and SqliteType to be available even when
//! only one backend is active. The trait impls within this module ARE feature-gated
//! to ensure Diesel-specific code only compiles for the SQLite backend.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Import DbId for helper methods
use super::unified_types::DbId;

#[cfg(feature = "sqlite-backend")]
use diesel::deserialize::{self, FromSql};
#[cfg(feature = "sqlite-backend")]
use diesel::serialize::{self, IsNull, Output, ToSql};
#[cfg(feature = "sqlite-backend")]
use diesel::sql_types::{BigInt, Text, Timestamp};
#[cfg(feature = "sqlite-backend")]
use diesel::sqlite::Sqlite;

/// Newtype wrapper for UUID to enable SQLite TEXT mapping
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(
    feature = "sqlite-backend",
    derive(diesel::expression::AsExpression, diesel::deserialize::FromSqlRow),
    diesel(sql_type = diesel::sql_types::Text)
)]
#[repr(transparent)]
#[serde(transparent)]
pub struct SqliteUuid(pub Uuid);

impl SqliteUuid {
    pub fn new(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn nil() -> Self {
        Self(Uuid::nil())
    }

    pub fn parse_str(input: &str) -> Result<Self, uuid::Error> {
        DbId::parse_str(input).map(|db_id| Self(db_id.into_uuid()))
    }

    pub fn into_inner(self) -> Uuid {
        self.0
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl From<Uuid> for SqliteUuid {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<SqliteUuid> for Uuid {
    fn from(wrapper: SqliteUuid) -> Self {
        wrapper.0
    }
}

impl std::ops::Deref for SqliteUuid {
    type Target = Uuid;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for SqliteUuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for SqliteUuid {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DbId::parse_str(s).map(|db_id| SqliteUuid(db_id.into_uuid()))
    }
}

#[cfg(feature = "sqlite-backend")]
impl FromSql<Text, Sqlite> for SqliteUuid {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let text = <String as FromSql<Text, Sqlite>>::from_sql(bytes)?;
        let db_id =
            DbId::parse_str(&text).map_err(|e| format!("Failed to parse UUID from TEXT: {}", e))?;
        Ok(SqliteUuid(db_id.into_uuid()))
    }
}

#[cfg(feature = "sqlite-backend")]
impl ToSql<Text, Sqlite> for SqliteUuid {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
        out.set_value(self.0.to_string());
        Ok(IsNull::No)
    }
}

#[cfg(feature = "sqlite-backend")]
impl FromSql<diesel::sql_types::Nullable<Text>, Sqlite> for SqliteUuid {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let text = <String as FromSql<Text, Sqlite>>::from_sql(bytes)?;
        let db_id =
            DbId::parse_str(&text).map_err(|e| format!("Failed to parse UUID from TEXT: {}", e))?;
        Ok(SqliteUuid(db_id.into_uuid()))
    }
}

impl Default for SqliteUuid {
    fn default() -> Self {
        Self(Uuid::nil())
    }
}

/// Newtype wrapper for DateTime<Utc> to enable SQLite Timestamp mapping
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(
    feature = "sqlite-backend",
    derive(diesel::expression::AsExpression, diesel::deserialize::FromSqlRow),
    diesel(sql_type = diesel::sql_types::Timestamp)
)]
#[repr(transparent)]
#[serde(transparent)]
pub struct SqliteDateTime(pub DateTime<Utc>);

impl SqliteDateTime {
    pub fn new(dt: DateTime<Utc>) -> Self {
        Self(dt)
    }

    pub fn now() -> Self {
        Self(Utc::now())
    }

    pub fn into_inner(self) -> DateTime<Utc> {
        self.0
    }

    pub fn as_datetime(&self) -> &DateTime<Utc> {
        &self.0
    }
}

impl From<DateTime<Utc>> for SqliteDateTime {
    fn from(dt: DateTime<Utc>) -> Self {
        Self(dt)
    }
}

impl From<SqliteDateTime> for DateTime<Utc> {
    fn from(wrapper: SqliteDateTime) -> Self {
        wrapper.0
    }
}

impl std::ops::Deref for SqliteDateTime {
    type Target = DateTime<Utc>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for SqliteDateTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "sqlite-backend")]
impl FromSql<Timestamp, Sqlite> for SqliteDateTime {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let timestamp = <i64 as FromSql<diesel::sql_types::BigInt, Sqlite>>::from_sql(bytes)?;
        let dt = DateTime::from_timestamp(timestamp, 0)
            .ok_or_else(|| format!("Invalid timestamp: {}", timestamp))?;
        Ok(SqliteDateTime(dt))
    }
}

#[cfg(feature = "sqlite-backend")]
impl ToSql<Timestamp, Sqlite> for SqliteDateTime {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
        out.set_value(self.0.timestamp());
        Ok(IsNull::No)
    }
}

#[cfg(feature = "sqlite-backend")]
impl FromSql<diesel::sql_types::Nullable<Timestamp>, Sqlite> for SqliteDateTime {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let timestamp = <i64 as FromSql<diesel::sql_types::BigInt, Sqlite>>::from_sql(bytes)?;
        let dt = DateTime::from_timestamp(timestamp, 0)
            .ok_or_else(|| format!("Invalid timestamp: {}", timestamp))?;
        Ok(SqliteDateTime(dt))
    }
}

// Additional FromSql/ToSql implementations for BigInt (used by unified types)
#[cfg(feature = "sqlite-backend")]
impl FromSql<BigInt, Sqlite> for SqliteDateTime {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let timestamp = <i64 as FromSql<BigInt, Sqlite>>::from_sql(bytes)?;
        let dt = DateTime::from_timestamp(timestamp, 0)
            .ok_or_else(|| format!("Invalid timestamp: {}", timestamp))?;
        Ok(SqliteDateTime(dt))
    }
}

#[cfg(feature = "sqlite-backend")]
impl ToSql<BigInt, Sqlite> for SqliteDateTime {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
        out.set_value(self.0.timestamp());
        Ok(IsNull::No)
    }
}

#[cfg(feature = "sqlite-backend")]
impl FromSql<diesel::sql_types::Nullable<BigInt>, Sqlite> for SqliteDateTime {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let timestamp = <i64 as FromSql<BigInt, Sqlite>>::from_sql(bytes)?;
        let dt = DateTime::from_timestamp(timestamp, 0)
            .ok_or_else(|| format!("Invalid timestamp: {}", timestamp))?;
        Ok(SqliteDateTime(dt))
    }
}

impl PartialOrd for SqliteDateTime {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SqliteDateTime {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

// Arithmetic operations for DateTime
impl std::ops::Sub for SqliteDateTime {
    type Output = chrono::Duration;

    fn sub(self, other: Self) -> Self::Output {
        self.0 - other.0
    }
}

impl std::ops::Sub<SqliteDateTime> for DateTime<Utc> {
    type Output = chrono::Duration;

    fn sub(self, other: SqliteDateTime) -> Self::Output {
        self - other.0
    }
}

impl std::ops::Add<chrono::Duration> for SqliteDateTime {
    type Output = SqliteDateTime;

    fn add(self, duration: chrono::Duration) -> Self::Output {
        SqliteDateTime(self.0 + duration)
    }
}

impl std::ops::Sub<chrono::Duration> for SqliteDateTime {
    type Output = SqliteDateTime;

    fn sub(self, duration: chrono::Duration) -> Self::Output {
        SqliteDateTime(self.0 - duration)
    }
}

impl Default for SqliteDateTime {
    fn default() -> Self {
        Self(Utc::now())
    }
}

/// Newtype wrapper for serde_json::Value to enable SQLite TEXT mapping
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "sqlite-backend",
    derive(diesel::expression::AsExpression, diesel::deserialize::FromSqlRow),
    diesel(sql_type = diesel::sql_types::Text)
)]
#[repr(transparent)]
#[serde(transparent)]
pub struct SqliteJson(pub serde_json::Value);

impl SqliteJson {
    pub fn new(value: serde_json::Value) -> Self {
        Self(value)
    }

    pub fn into_inner(self) -> serde_json::Value {
        self.0
    }

    pub fn as_value(&self) -> &serde_json::Value {
        &self.0
    }

    // Constructor functions matching serde_json::Value enum variants
    pub fn String(s: String) -> Self {
        Self(serde_json::Value::String(s))
    }

    pub fn Object(map: serde_json::Map<String, serde_json::Value>) -> Self {
        Self(serde_json::Value::Object(map))
    }

    pub fn Array(arr: Vec<serde_json::Value>) -> Self {
        Self(serde_json::Value::Array(arr))
    }

    pub fn Number(n: serde_json::Number) -> Self {
        Self(serde_json::Value::Number(n))
    }

    pub fn Bool(b: bool) -> Self {
        Self(serde_json::Value::Bool(b))
    }

    pub const Null: Self = Self(serde_json::Value::Null);

    // Convenience accessors delegating to serde_json::Value methods
    pub fn as_str(&self) -> Option<&str> {
        self.0.as_str()
    }

    pub fn as_object(&self) -> Option<&serde_json::Map<String, serde_json::Value>> {
        self.0.as_object()
    }

    pub fn as_object_mut(&mut self) -> Option<&mut serde_json::Map<String, serde_json::Value>> {
        self.0.as_object_mut()
    }

    pub fn as_array(&self) -> Option<&Vec<serde_json::Value>> {
        self.0.as_array()
    }

    pub fn as_array_mut(&mut self) -> Option<&mut Vec<serde_json::Value>> {
        self.0.as_array_mut()
    }

    pub fn as_bool(&self) -> Option<bool> {
        self.0.as_bool()
    }

    pub fn as_i64(&self) -> Option<i64> {
        self.0.as_i64()
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.0.as_u64()
    }

    pub fn as_f64(&self) -> Option<f64> {
        self.0.as_f64()
    }

    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }

    pub fn is_object(&self) -> bool {
        self.0.is_object()
    }

    pub fn is_array(&self) -> bool {
        self.0.is_array()
    }

    pub fn is_string(&self) -> bool {
        self.0.is_string()
    }

    pub fn is_number(&self) -> bool {
        self.0.is_number()
    }

    pub fn is_boolean(&self) -> bool {
        self.0.is_boolean()
    }

    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.0.get(key)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut serde_json::Value> {
        self.0.get_mut(key)
    }
}

impl From<serde_json::Value> for SqliteJson {
    fn from(value: serde_json::Value) -> Self {
        Self(value)
    }
}

impl From<SqliteJson> for serde_json::Value {
    fn from(wrapper: SqliteJson) -> Self {
        wrapper.0
    }
}

impl std::ops::Deref for SqliteJson {
    type Target = serde_json::Value;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Default for SqliteJson {
    fn default() -> Self {
        // Default to empty JSON object to prevent NULL values
        Self(serde_json::json!({}))
    }
}

impl std::fmt::Display for SqliteJson {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "sqlite-backend")]
impl FromSql<Text, Sqlite> for SqliteJson {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let text = <String as FromSql<Text, Sqlite>>::from_sql(bytes)?;
        let value = serde_json::from_str(&text)
            .map_err(|e| format!("Failed to parse JSON from TEXT: {}", e))?;
        Ok(SqliteJson(value))
    }
}

#[cfg(feature = "sqlite-backend")]
impl ToSql<Text, Sqlite> for SqliteJson {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
        // CRITICAL: Always write JSON, never NULL
        let json_str = serde_json::to_string(&self.0)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        out.set_value(json_str);
        Ok(IsNull::No)
    }
}

#[cfg(feature = "sqlite-backend")]
impl FromSql<diesel::sql_types::Nullable<Text>, Sqlite> for SqliteJson {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        // Handle NULL by trying to deserialize as Option<String>
        let opt_text =
            <Option<String> as FromSql<diesel::sql_types::Nullable<Text>, Sqlite>>::from_sql(
                bytes,
            )?;

        match opt_text {
            None => {
                // NULL value - return empty JSON object
                tracing::warn!("NULL value encountered for SqliteJson, using empty object");
                Ok(SqliteJson(serde_json::json!({})))
            }
            Some(text) => {
                // Parse JSON string
                let value = serde_json::from_str(&text)
                    .map_err(|e| format!("Failed to parse JSON from TEXT: {}", e))?;
                Ok(SqliteJson(value))
            }
        }
    }
}

/// Newtype wrapper for BigDecimal to enable SQLite Double mapping
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(
    feature = "sqlite-backend",
    derive(diesel::expression::AsExpression, diesel::deserialize::FromSqlRow),
    diesel(sql_type = diesel::sql_types::Double)
)]
#[repr(transparent)]
#[serde(transparent)]
pub struct SqliteBigDecimal(pub bigdecimal::BigDecimal);

impl SqliteBigDecimal {
    pub fn new(value: bigdecimal::BigDecimal) -> Self {
        Self(value)
    }

    pub fn from_str(s: &str) -> Result<Self, bigdecimal::ParseBigDecimalError> {
        use std::str::FromStr;
        bigdecimal::BigDecimal::from_str(s).map(Self)
    }

    pub fn into_inner(self) -> bigdecimal::BigDecimal {
        self.0
    }

    pub fn as_bigdecimal(&self) -> &bigdecimal::BigDecimal {
        &self.0
    }
}

impl From<bigdecimal::BigDecimal> for SqliteBigDecimal {
    fn from(value: bigdecimal::BigDecimal) -> Self {
        Self(value)
    }
}

impl From<SqliteBigDecimal> for bigdecimal::BigDecimal {
    fn from(wrapper: SqliteBigDecimal) -> Self {
        wrapper.0
    }
}

impl std::ops::Deref for SqliteBigDecimal {
    type Target = bigdecimal::BigDecimal;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for SqliteBigDecimal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "sqlite-backend")]
impl FromSql<diesel::sql_types::Double, Sqlite> for SqliteBigDecimal {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let value = <f64 as FromSql<diesel::sql_types::Double, Sqlite>>::from_sql(bytes)?;
        let decimal = bigdecimal::BigDecimal::try_from(value)
            .map_err(|e| format!("Failed to convert f64 to BigDecimal: {}", e))?;
        Ok(SqliteBigDecimal(decimal))
    }
}

#[cfg(feature = "sqlite-backend")]
impl ToSql<diesel::sql_types::Double, Sqlite> for SqliteBigDecimal {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
        use std::str::FromStr;
        let value = f64::from_str(&self.0.to_string())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        out.set_value(value);
        Ok(IsNull::No)
    }
}

#[cfg(feature = "sqlite-backend")]
impl FromSql<diesel::sql_types::Nullable<diesel::sql_types::Double>, Sqlite> for SqliteBigDecimal {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let value = <f64 as FromSql<diesel::sql_types::Double, Sqlite>>::from_sql(bytes)?;
        let decimal = bigdecimal::BigDecimal::try_from(value)
            .map_err(|e| format!("Failed to convert f64 to BigDecimal: {}", e))?;
        Ok(SqliteBigDecimal(decimal))
    }
}

// Additional FromSql implementation for Integer (used for credit/payment fields in SQLite)
#[cfg(feature = "sqlite-backend")]
impl FromSql<diesel::sql_types::Integer, Sqlite> for SqliteBigDecimal {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let value = <i32 as FromSql<diesel::sql_types::Integer, Sqlite>>::from_sql(bytes)?;
        let decimal = bigdecimal::BigDecimal::from(value);
        Ok(SqliteBigDecimal(decimal))
    }
}

#[cfg(feature = "sqlite-backend")]
impl FromSql<diesel::sql_types::Nullable<diesel::sql_types::Integer>, Sqlite> for SqliteBigDecimal {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let value = <i32 as FromSql<diesel::sql_types::Integer, Sqlite>>::from_sql(bytes)?;
        let decimal = bigdecimal::BigDecimal::from(value);
        Ok(SqliteBigDecimal(decimal))
    }
}

#[cfg(feature = "sqlite-backend")]
impl ToSql<diesel::sql_types::Integer, Sqlite> for SqliteBigDecimal {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
        use std::str::FromStr;
        let value = i32::from_str(&self.0.to_string())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        out.set_value(value);
        Ok(IsNull::No)
    }
}

// Additional FromSql/ToSql implementations for Text (used by unified types)
#[cfg(feature = "sqlite-backend")]
impl FromSql<Text, Sqlite> for SqliteBigDecimal {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        use std::str::FromStr;
        let text = <String as FromSql<Text, Sqlite>>::from_sql(bytes)?;
        let decimal = bigdecimal::BigDecimal::from_str(&text)
            .map_err(|e| format!("Failed to parse BigDecimal from TEXT: {}", e))?;
        Ok(SqliteBigDecimal(decimal))
    }
}

#[cfg(feature = "sqlite-backend")]
impl ToSql<Text, Sqlite> for SqliteBigDecimal {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
        out.set_value(self.0.to_string());
        Ok(IsNull::No)
    }
}

#[cfg(feature = "sqlite-backend")]
impl FromSql<diesel::sql_types::Nullable<Text>, Sqlite> for SqliteBigDecimal {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        use std::str::FromStr;
        let text = <String as FromSql<Text, Sqlite>>::from_sql(bytes)?;
        let decimal = bigdecimal::BigDecimal::from_str(&text)
            .map_err(|e| format!("Failed to parse BigDecimal from TEXT: {}", e))?;
        Ok(SqliteBigDecimal(decimal))
    }
}

impl Default for SqliteBigDecimal {
    fn default() -> Self {
        Self(bigdecimal::BigDecimal::from(0))
    }
}

// From<{integer}> implementations for common literal types
impl From<i32> for SqliteBigDecimal {
    fn from(value: i32) -> Self {
        Self(bigdecimal::BigDecimal::from(value))
    }
}

impl From<i64> for SqliteBigDecimal {
    fn from(value: i64) -> Self {
        Self(bigdecimal::BigDecimal::from(value))
    }
}

impl From<u32> for SqliteBigDecimal {
    fn from(value: u32) -> Self {
        Self(bigdecimal::BigDecimal::from(value))
    }
}

impl From<u64> for SqliteBigDecimal {
    fn from(value: u64) -> Self {
        Self(bigdecimal::BigDecimal::from(value))
    }
}
