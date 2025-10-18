//! SQLite type mappings for custom types
//!
//! This module provides type conversions for SQLite backend, mapping PostgreSQL types
//! to SQLite equivalents:
//! - UUID → TEXT
//! - JSONB → TEXT
//! - ARRAY<TEXT> → TEXT (JSON array serialization)

use diesel::deserialize::{self, FromSql};
use diesel::serialize::{self, Output, ToSql};
use diesel::sql_types::Text;
use diesel::sqlite::Sqlite;
use serde::{Deserialize, Serialize};
use std::io::Write;
use uuid::Uuid;

/// Implement FromSql for Uuid to read from SQLite TEXT column
impl FromSql<Text, Sqlite> for Uuid {
    fn from_sql(bytes: diesel::sqlite::SqliteValue) -> deserialize::Result<Self> {
        let text = <String as FromSql<Text, Sqlite>>::from_sql(bytes)?;
        Uuid::parse_str(&text).map_err(|e| e.into())
    }
}

/// Implement ToSql for Uuid to write to SQLite TEXT column
impl ToSql<Text, Sqlite> for Uuid {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
        out.set_value(self.to_string());
        Ok(serialize::IsNull::No)
    }
}

/// Wrapper type for JSON values (maps JSONB → TEXT in SQLite)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonValue(pub serde_json::Value);

impl FromSql<Text, Sqlite> for JsonValue {
    fn from_sql(bytes: diesel::sqlite::SqliteValue) -> deserialize::Result<Self> {
        let text = <String as FromSql<Text, Sqlite>>::from_sql(bytes)?;
        let value: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("Failed to parse JSON: {}", e))?;
        Ok(JsonValue(value))
    }
}

impl ToSql<Text, Sqlite> for JsonValue {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
        let json_string = serde_json::to_string(&self.0)
            .map_err(|e| format!("Failed to serialize JSON: {}", e))?;
        out.set_value(json_string);
        Ok(serialize::IsNull::No)
    }
}

/// Wrapper type for string arrays (maps ARRAY<TEXT> → TEXT in SQLite)
/// Stores arrays as JSON arrays in TEXT columns
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TextArray(pub Vec<String>);

impl FromSql<Text, Sqlite> for TextArray {
    fn from_sql(bytes: diesel::sqlite::SqliteValue) -> deserialize::Result<Self> {
        let text = <String as FromSql<Text, Sqlite>>::from_sql(bytes)?;
        let vec: Vec<String> = serde_json::from_str(&text)
            .map_err(|e| format!("Failed to parse string array: {}", e))?;
        Ok(TextArray(vec))
    }
}

impl ToSql<Text, Sqlite> for TextArray {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
        let json_string = serde_json::to_string(&self.0)
            .map_err(|e| format!("Failed to serialize string array: {}", e))?;
        out.set_value(json_string);
        Ok(serialize::IsNull::No)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diesel::prelude::*;
    use diesel::sql_types::Text;

    // Helper function to create a test SQLite database connection
    fn establish_test_connection() -> SqliteConnection {
        SqliteConnection::establish(":memory:").expect("Failed to create in-memory database")
    }

    #[test]
    fn test_uuid_roundtrip_sqlite() {
        let conn = &mut establish_test_connection();

        // Create test table
        diesel::sql_query("CREATE TABLE test_uuids (id TEXT PRIMARY KEY)")
            .execute(conn)
            .expect("Failed to create table");

        // Test UUID
        let test_uuid = Uuid::new_v4();

        // Insert UUID
        diesel::sql_query("INSERT INTO test_uuids (id) VALUES (?)")
            .bind::<Text, _>(test_uuid.to_string())
            .execute(conn)
            .expect("Failed to insert UUID");

        // Retrieve UUID
        let retrieved: String = diesel::sql_query("SELECT id FROM test_uuids")
            .get_result::<(String,)>(conn)
            .expect("Failed to retrieve UUID")
            .0;

        let retrieved_uuid = Uuid::parse_str(&retrieved).expect("Failed to parse retrieved UUID");

        assert_eq!(test_uuid, retrieved_uuid, "UUID roundtrip failed");
    }

    #[test]
    fn test_jsonb_roundtrip_sqlite() {
        let conn = &mut establish_test_connection();

        // Create test table
        diesel::sql_query("CREATE TABLE test_json (data TEXT)")
            .execute(conn)
            .expect("Failed to create table");

        // Test JSON value
        let test_json = JsonValue(serde_json::json!({
            "name": "Test User",
            "age": 30,
            "active": true,
            "tags": ["rust", "diesel", "sqlite"]
        }));

        // Insert JSON
        let json_string = serde_json::to_string(&test_json.0).expect("Failed to serialize JSON");
        diesel::sql_query("INSERT INTO test_json (data) VALUES (?)")
            .bind::<Text, _>(json_string)
            .execute(conn)
            .expect("Failed to insert JSON");

        // Retrieve JSON
        let retrieved: String = diesel::sql_query("SELECT data FROM test_json")
            .get_result::<(String,)>(conn)
            .expect("Failed to retrieve JSON")
            .0;

        let retrieved_json: serde_json::Value =
            serde_json::from_str(&retrieved).expect("Failed to parse retrieved JSON");

        assert_eq!(test_json.0, retrieved_json, "JSON roundtrip failed");
    }

    #[test]
    fn test_array_roundtrip_sqlite() {
        let conn = &mut establish_test_connection();

        // Create test table
        diesel::sql_query("CREATE TABLE test_arrays (tags TEXT)")
            .execute(conn)
            .expect("Failed to create table");

        // Test string array
        let test_array = TextArray(vec![
            "rust".to_string(),
            "diesel".to_string(),
            "sqlite".to_string(),
        ]);

        // Insert array
        let array_string = serde_json::to_string(&test_array.0).expect("Failed to serialize array");
        diesel::sql_query("INSERT INTO test_arrays (tags) VALUES (?)")
            .bind::<Text, _>(array_string)
            .execute(conn)
            .expect("Failed to insert array");

        // Retrieve array
        let retrieved: String = diesel::sql_query("SELECT tags FROM test_arrays")
            .get_result::<(String,)>(conn)
            .expect("Failed to retrieve array")
            .0;

        let retrieved_array: Vec<String> =
            serde_json::from_str(&retrieved).expect("Failed to parse retrieved array");

        assert_eq!(test_array.0, retrieved_array, "Array roundtrip failed");
    }
}
