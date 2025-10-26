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

// sqlite_types is always available for DbType trait implementations
use super::sqlite_types::{SqliteBigDecimal, SqliteDateTime, SqliteUuid};

use bigdecimal::BigDecimal;
use chrono::{DateTime, Utc};
use diesel::deserialize::{self, FromSql, FromSqlRow};
use diesel::expression::AsExpression;
use diesel::serialize::{self, IsNull, Output, ToSql};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(
    feature = "postgres-backend",
    derive(FromSqlRow)
)]
#[cfg_attr(
    feature = "sqlite-backend",
    derive(FromSqlRow)
)]
#[repr(transparent)]
pub struct DbId(Uuid);

impl DbId {
    /// Create a new random DbId
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a new random DbId (alias for new())
    pub fn new_v4() -> Self {
        Self::new()
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

impl std::str::FromStr for DbId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_str(s)
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

    #[cfg(feature = "postgres-backend")]
    type PgSqlType = PgUuid;
    #[cfg(not(feature = "postgres-backend"))]
    type PgSqlType = ();

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
        out.set_value(self.0.to_string());
        Ok(IsNull::No)
    }
}

// Nullable<Text> support for SQLite
#[cfg(feature = "sqlite-backend")]
impl FromSql<Nullable<Text>, Sqlite> for DbId {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let sqlite_uuid = <SqliteUuid as FromSql<Text, Sqlite>>::from_sql(bytes)?;
        Ok(Self(sqlite_uuid.0))
    }
}

// Expression trait implementation for DbId to enable it in WHERE clauses
#[cfg(feature = "postgres-backend")]
impl diesel::expression::Expression for DbId {
    type SqlType = PgUuid;
}

#[cfg(feature = "sqlite-backend")]
impl diesel::expression::Expression for DbId {
    type SqlType = Text;
}

// Implement ValidGrouping to enable DbId in GROUP BY and other aggregation contexts
impl<GB> diesel::expression::ValidGrouping<GB> for DbId {
    type IsAggregate = diesel::expression::is_aggregate::No;
}

// Implement QueryId for query caching
impl diesel::query_builder::QueryId for DbId {
    type QueryId = Self;
    const HAS_STATIC_QUERY_ID: bool = false;
}

// Implement AppearsOnTable for all tables (allows DbId to be used in any query context)
impl<QS> diesel::expression::AppearsOnTable<QS> for DbId where Self: diesel::Expression {}

// Implement QueryFragment to enable SQL generation
#[cfg(feature = "postgres-backend")]
impl diesel::query_builder::QueryFragment<diesel::pg::Pg> for DbId {
    fn walk_ast<'b>(
        &'b self,
        mut pass: diesel::query_builder::AstPass<'_, 'b, diesel::pg::Pg>,
    ) -> diesel::QueryResult<()> {
        pass.push_bind_param::<PgUuid, _>(&self.0)?;
        Ok(())
    }
}

//#[cfg(feature = "sqlite-backend")]
//impl diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite> for DbId {
//    fn walk_ast<'b>(
//        &'b self,
//        mut pass: diesel::query_builder::AstPass<'_, 'b, diesel::sqlite::Sqlite>,
//    ) -> diesel::QueryResult<()> {
//        pass.push_bind_param::<Text, _>(&self.to_string())?;
//        Ok(())
//    }
//}

// Note: AsExpression<SqlType> is automatically implemented by Diesel via blanket impl
// However, for Nullable<SqlType>, we need manual implementations since SqlType != Nullable<SqlType>

#[cfg(feature = "postgres-backend")]
impl diesel::expression::AsExpression<diesel::sql_types::Nullable<PgUuid>> for DbId {
    type Expression = <Option<uuid::Uuid> as diesel::expression::AsExpression<diesel::sql_types::Nullable<PgUuid>>>::Expression;
    fn as_expression(self) -> Self::Expression {
        <Option<uuid::Uuid> as diesel::expression::AsExpression<diesel::sql_types::Nullable<PgUuid>>>::as_expression(Some(self.0))
    }
}

#[cfg(feature = "postgres-backend")]
impl<'a> diesel::expression::AsExpression<diesel::sql_types::Nullable<PgUuid>> for &'a DbId {
    type Expression = <Option<&'a uuid::Uuid> as diesel::expression::AsExpression<diesel::sql_types::Nullable<PgUuid>>>::Expression;
    fn as_expression(self) -> Self::Expression {
        <Option<&uuid::Uuid> as diesel::expression::AsExpression<diesel::sql_types::Nullable<PgUuid>>>::as_expression(Some(&self.0))
    }
}

#[cfg(feature = "sqlite-backend")]
impl diesel::expression::AsExpression<diesel::sql_types::Nullable<Text>> for DbId {
    type Expression = <Option<String> as diesel::expression::AsExpression<diesel::sql_types::Nullable<Text>>>::Expression;
    fn as_expression(self) -> Self::Expression {
        <Option<String> as diesel::expression::AsExpression<diesel::sql_types::Nullable<Text>>>::as_expression(Some(self.to_string()))
    }
}

#[cfg(feature = "sqlite-backend")]
impl<'a> diesel::expression::AsExpression<diesel::sql_types::Nullable<Text>> for &'a DbId {
    type Expression = <Option<String> as diesel::expression::AsExpression<diesel::sql_types::Nullable<Text>>>::Expression;
    fn as_expression(self) -> Self::Expression {
        <Option<String> as diesel::expression::AsExpression<diesel::sql_types::Nullable<Text>>>::as_expression(Some(self.to_string()))
    }
}

// ============================================================================
// DbTimestamp - Unified DateTime Type
// ============================================================================

/// Backend-agnostic timestamp
///
/// Stores UTC timestamps in both PostgreSQL (TIMESTAMPTZ) and SQLite (INTEGER as Unix timestamp).
/// Provides transparent access to the underlying `chrono::DateTime<Utc>` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(
    feature = "postgres-backend",
    derive(AsExpression, FromSqlRow),
    diesel(sql_type = Timestamptz)
)]
#[cfg_attr(
    feature = "sqlite-backend",
    derive(AsExpression, FromSqlRow),
    diesel(sql_type = Timestamp)
)]
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

impl Default for DbTimestamp {
    fn default() -> Self {
        Self::now()
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

// Arithmetic operations for DbTimestamp
impl std::ops::Sub<DbTimestamp> for DbTimestamp {
    type Output = chrono::TimeDelta;

    fn sub(self, rhs: DbTimestamp) -> Self::Output {
        self.0 - rhs.0
    }
}

impl std::ops::Sub<chrono::TimeDelta> for DbTimestamp {
    type Output = DbTimestamp;

    fn sub(self, rhs: chrono::TimeDelta) -> Self::Output {
        DbTimestamp(self.0 - rhs)
    }
}

impl std::ops::Sub<DbTimestamp> for DateTime<Utc> {
    type Output = chrono::TimeDelta;

    fn sub(self, rhs: DbTimestamp) -> Self::Output {
        self - rhs.0
    }
}

impl DbType for DbTimestamp {
    type PgType = DateTime<Utc>;
    type SqliteType = SqliteDateTime;

    #[cfg(feature = "postgres-backend")]
    type PgSqlType = Timestamptz;
    #[cfg(not(feature = "postgres-backend"))]
    type PgSqlType = ();

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
        out.set_value(self.0.timestamp());
        Ok(IsNull::No)
    }
}

// Diesel's Timestamp type in SQLite stores as string, so we need FromSql<Timestamp, Sqlite>
#[cfg(feature = "sqlite-backend")]
impl FromSql<Timestamp, Sqlite> for DbTimestamp {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let text = <String as FromSql<Text, Sqlite>>::from_sql(bytes)?;

        // Try ISO 8601 formats
        if let Ok(dt) = DateTime::parse_from_rfc3339(&text) {
            return Ok(Self(dt.with_timezone(&Utc)));
        }

        // Try parsing as Unix timestamp (seconds since epoch)
        if let Ok(timestamp) = text.parse::<i64>() {
            if let Some(dt) = DateTime::from_timestamp(timestamp, 0) {
                return Ok(Self(dt));
            }
        }

        Err(format!("Invalid timestamp string: {}", text).into())
    }
}

#[cfg(feature = "sqlite-backend")]
impl ToSql<Timestamp, Sqlite> for DbTimestamp {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
        // Serialize as ISO 8601 string for Timestamp type
        out.set_value(self.0.to_rfc3339());
        Ok(IsNull::No)
    }
}

// Nullable<Timestamp> support for SQLite
#[cfg(feature = "sqlite-backend")]
impl FromSql<Nullable<Timestamp>, Sqlite> for DbTimestamp {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let text = <String as FromSql<Text, Sqlite>>::from_sql(bytes)?;

        // Try ISO 8601 formats
        if let Ok(dt) = DateTime::parse_from_rfc3339(&text) {
            return Ok(Self(dt.with_timezone(&Utc)));
        }

        // Try parsing as Unix timestamp (seconds since epoch)
        if let Ok(timestamp) = text.parse::<i64>() {
            if let Some(dt) = DateTime::from_timestamp(timestamp, 0) {
                return Ok(Self(dt));
            }
        }

        Err(format!("Invalid timestamp string: {}", text).into())
    }
}

// ============================================================================
// DbDecimal - Unified BigDecimal Type
// ============================================================================

/// Backend-agnostic arbitrary-precision decimal
///
/// Stores decimal numbers in both PostgreSQL (NUMERIC) and SQLite (TEXT).
/// Used for monetary values and other high-precision calculations.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(
    feature = "postgres-backend",
    derive(FromSqlRow),
    diesel(sql_type = Numeric)
)]
#[cfg_attr(
    feature = "sqlite-backend",
    derive(AsExpression, FromSqlRow),
    diesel(sql_type = Text)
)]
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

#[cfg(feature = "postgres-backend")]
impl ToSql<Nullable<Numeric>, Pg> for DbDecimal {
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
        out.set_value(self.0.to_string());
        Ok(IsNull::No)
    }
}

// SQLite Double type support for DbDecimal
#[cfg(feature = "sqlite-backend")]
impl FromSql<diesel::sql_types::Double, Sqlite> for DbDecimal {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let f64_val = <f64 as FromSql<diesel::sql_types::Double, Sqlite>>::from_sql(bytes)?;
        let big_decimal = BigDecimal::try_from(f64_val)
            .map_err(|e| format!("Failed to convert f64 to BigDecimal: {}", e))?;
        Ok(Self(big_decimal))
    }
}

#[cfg(feature = "sqlite-backend")]
impl ToSql<diesel::sql_types::Double, Sqlite> for DbDecimal {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
        use bigdecimal::ToPrimitive;
        use std::str::FromStr;
        let value = f64::from_str(&self.0.to_string())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        out.set_value(value);
        Ok(IsNull::No)
    }
}

// SQLite Integer type support for DbDecimal (for schema compatibility)
#[cfg(feature = "sqlite-backend")]
impl FromSql<diesel::sql_types::Integer, Sqlite> for DbDecimal {
    fn from_sql(
        bytes: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        let i32_val = <i32 as FromSql<diesel::sql_types::Integer, Sqlite>>::from_sql(bytes)?;
        Ok(Self(BigDecimal::from(i32_val)))
    }
}

#[cfg(feature = "sqlite-backend")]
impl ToSql<diesel::sql_types::Integer, Sqlite> for DbDecimal {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
        use std::str::FromStr;
        let value = i32::from_str(&self.0.to_string())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        out.set_value(value);
        Ok(IsNull::No)
    }
}

// Expression trait implementation for DbDecimal
#[cfg(feature = "postgres-backend")]
impl diesel::expression::Expression for DbDecimal {
    type SqlType = diesel::sql_types::Numeric;
}

#[cfg(feature = "sqlite-backend")]
impl diesel::expression::Expression for DbDecimal {
    type SqlType = diesel::sql_types::Double;
}

// Implement ValidGrouping for DbDecimal
impl<GB> diesel::expression::ValidGrouping<GB> for DbDecimal {
    type IsAggregate = diesel::expression::is_aggregate::No;
}

// Implement QueryId for DbDecimal
impl diesel::query_builder::QueryId for DbDecimal {
    type QueryId = Self;
    const HAS_STATIC_QUERY_ID: bool = false;
}

// Implement AppearsOnTable for DbDecimal
impl<QS> diesel::expression::AppearsOnTable<QS> for DbDecimal where Self: diesel::Expression {}

// Implement QueryFragment to enable SQL generation
#[cfg(feature = "postgres-backend")]
impl diesel::query_builder::QueryFragment<diesel::pg::Pg> for DbDecimal {
    fn walk_ast<'b>(
        &'b self,
        mut pass: diesel::query_builder::AstPass<'_, 'b, diesel::pg::Pg>,
    ) -> diesel::QueryResult<()> {
        pass.push_bind_param::<Numeric, _>(&self.0)?;
        Ok(())
    }
}

// Note: AsExpression<Numeric> is automatically implemented by Diesel via blanket impl from diesel(sql_type = Numeric)
// However, for Nullable<Numeric>, we need manual implementations since Numeric != Nullable<Numeric>
#[cfg(feature = "postgres-backend")]
impl AsExpression<Nullable<Numeric>> for DbDecimal {
    type Expression = <Option<BigDecimal> as AsExpression<Nullable<Numeric>>>::Expression;

    fn as_expression(self) -> Self::Expression {
        <Option<BigDecimal> as AsExpression<Nullable<Numeric>>>::as_expression(Some(self.0))
    }
}

#[cfg(feature = "postgres-backend")]
impl<'a> AsExpression<Nullable<Numeric>> for &'a DbDecimal {
    type Expression = <Option<&'a BigDecimal> as AsExpression<Nullable<Numeric>>>::Expression;

    fn as_expression(self) -> Self::Expression {
        <Option<&BigDecimal> as AsExpression<Nullable<Numeric>>>::as_expression(Some(&self.0))
    }
}

//#[cfg(feature = "sqlite-backend")]
//impl diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite> for DbDecimal {
//    fn walk_ast<'b>(
//        &'b self,
//        mut pass: diesel::query_builder::AstPass<'_, 'b, diesel::sqlite::Sqlite>,
//    ) -> diesel::QueryResult<()> {
//        ToSql::<diesel::sql_types::Double, Sqlite>::to_sql(self, &mut pass.to_sql_literal())?;
//        Ok(())
//    }
//}

// AsExpression implementations for Nullable<Double> (SQLite)
#[cfg(feature = "sqlite-backend")]
impl diesel::expression::AsExpression<diesel::sql_types::Nullable<diesel::sql_types::Double>> for DbDecimal {
    type Expression = <Option<f64> as diesel::expression::AsExpression<diesel::sql_types::Nullable<diesel::sql_types::Double>>>::Expression;
    fn as_expression(self) -> Self::Expression {
        use bigdecimal::ToPrimitive;
        use std::str::FromStr;
        let value = f64::from_str(&self.0.to_string()).ok();
        <Option<f64> as diesel::expression::AsExpression<diesel::sql_types::Nullable<diesel::sql_types::Double>>>::as_expression(value)
    }
}

#[cfg(feature = "sqlite-backend")]
impl<'a> diesel::expression::AsExpression<diesel::sql_types::Nullable<diesel::sql_types::Double>> for &'a DbDecimal {
    type Expression = <Option<f64> as diesel::expression::AsExpression<diesel::sql_types::Nullable<diesel::sql_types::Double>>>::Expression;
    fn as_expression(self) -> Self::Expression {
        use bigdecimal::ToPrimitive;
        use std::str::FromStr;
        let value = f64::from_str(&self.0.to_string()).ok();
        <Option<f64> as diesel::expression::AsExpression<diesel::sql_types::Nullable<diesel::sql_types::Double>>>::as_expression(value)
    }
}

// AsExpression implementations for Integer (SQLite schema compatibility)
#[cfg(feature = "sqlite-backend")]
impl diesel::expression::AsExpression<diesel::sql_types::Integer> for DbDecimal {
    type Expression = <i32 as diesel::expression::AsExpression<diesel::sql_types::Integer>>::Expression;
    fn as_expression(self) -> Self::Expression {
        use std::str::FromStr;
        let value = i32::from_str(&self.0.to_string()).unwrap_or(0);
        <i32 as diesel::expression::AsExpression<diesel::sql_types::Integer>>::as_expression(value)
    }
}

#[cfg(feature = "sqlite-backend")]
impl<'a> diesel::expression::AsExpression<diesel::sql_types::Integer> for &'a DbDecimal {
    type Expression = <i32 as diesel::expression::AsExpression<diesel::sql_types::Integer>>::Expression;
    fn as_expression(self) -> Self::Expression {
        use std::str::FromStr;
        let value = i32::from_str(&self.0.to_string()).unwrap_or(0);
        <i32 as diesel::expression::AsExpression<diesel::sql_types::Integer>>::as_expression(value)
    }
}

// ============================================================================
// DbBlob - Unified Binary Data Type
// ============================================================================

/// Backend-agnostic binary data
///
/// Stores binary data in both PostgreSQL (BYTEA) and SQLite (BLOB).
/// Used for encrypted data, hashes, and other binary content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "postgres-backend",
    derive(AsExpression, FromSqlRow),
    diesel(sql_type = Bytea)
)]
#[cfg_attr(
    feature = "sqlite-backend",
    derive(AsExpression, FromSqlRow),
    diesel(sql_type = Binary)
)]
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

    #[cfg(feature = "postgres-backend")]
    type PgSqlType = Bytea;
    #[cfg(not(feature = "postgres-backend"))]
    type PgSqlType = ();

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
#[cfg_attr(
    feature = "postgres-backend",
    derive(AsExpression, FromSqlRow),
    diesel(sql_type = Nullable<diesel::sql_types::Array<Nullable<Text>>>)
)]
#[cfg_attr(
    feature = "sqlite-backend",
    derive(AsExpression, FromSqlRow),
    diesel(sql_type = Text)
)]
#[repr(transparent)]
pub struct DbStringArray(pub Option<Vec<Option<String>>>);

impl DbStringArray {
    /// Create a new DbStringArray from the raw inner value
    pub fn new(data: Option<Vec<Option<String>>>) -> Self {
        Self(data)
    }

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

    /// Create from a vector of strings (backwards compatibility alias for from_strings)
    pub fn from_vec_string(strings: Vec<String>) -> Self {
        Self::from_strings(strings)
    }

    /// Get the inner optional vector
    pub fn into_option(self) -> Option<Vec<Option<String>>> {
        self.0
    }

    /// Get a reference to the inner optional vector (for compatibility with old .as_ref() pattern)
    pub fn as_ref(&self) -> Option<&Vec<Option<String>>> {
        self.0.as_ref()
    }

    /// Get a direct reference to the inner Option (for pattern matching)
    pub fn inner_ref(&self) -> &Option<Vec<Option<String>>> {
        &self.0
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

    #[cfg(feature = "postgres-backend")]
    type PgSqlType = Nullable<diesel::sql_types::Array<Nullable<Text>>>;
    #[cfg(not(feature = "postgres-backend"))]
    type PgSqlType = ();

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
        match self.to_sqlite_type() {
            Some(json_str) => {
                out.set_value(json_str);
                Ok(IsNull::No)
            }
            None => Ok(IsNull::Yes),
        }
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
