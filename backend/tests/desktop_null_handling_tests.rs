#[cfg(all(test, feature = "sqlite-backend"))]
mod desktop_null_handling_tests {
    use diesel::prelude::*;
    use diesel::sql_types::Text;
    use diesel_migrations::MigrationHarness;
    use scribe_backend::db::{DbId, DbStringArray, DbType};
    use scribe_backend::models::OptionalStringArray;

    // Helper structs for raw SQL queries
    #[derive(QueryableByName)]
    struct TwoStrings {
        #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
        tags: Option<String>,
        #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
        greetings: Option<String>,
    }

    #[derive(QueryableByName)]
    struct SingleString {
        #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
        tags: Option<String>,
    }

    // ================== Unit Tests for DbStringArray ===================

    #[test]
    fn test_db_string_array_from_null_becomes_empty_array() {
        // Test that NULL deserializes to empty array
        let db_array = DbStringArray::from_sqlite_type(None);
        assert_eq!(db_array.0, Some(Vec::new()));
    }

    #[test]
    fn test_db_string_array_from_empty_json_array() {
        // Test that "[]" deserializes correctly
        let db_array = DbStringArray::from_sqlite_type(Some("[]".to_string()));
        assert_eq!(db_array.0, Some(Vec::new()));
    }

    #[test]
    fn test_db_string_array_from_json_array_with_values() {
        // Test that valid JSON array deserializes correctly
        let db_array = DbStringArray::from_sqlite_type(Some(r#"["tag1","tag2"]"#.to_string()));
        assert_eq!(
            db_array.0,
            Some(vec![Some("tag1".to_string()), Some("tag2".to_string())])
        );
    }

    #[test]
    fn test_db_string_array_from_invalid_json_becomes_empty() {
        // Test that invalid JSON deserializes to empty array (fallback)
        let db_array = DbStringArray::from_sqlite_type(Some("not valid json".to_string()));
        assert_eq!(db_array.0, Some(Vec::new()));
    }

    #[test]
    fn test_db_string_array_to_sqlite_empty_writes_empty_array() {
        // Test that empty array serializes to "[]" not NULL
        let db_array = DbStringArray(Some(Vec::new()));
        let json_opt = db_array.to_sqlite_type();
        assert_eq!(json_opt, Some("[]".to_string()));
    }

    #[test]
    fn test_db_string_array_to_sqlite_none_writes_empty_array() {
        // CRITICAL: None should also serialize to "[]" to prevent NULL writes
        let db_array = DbStringArray(None);
        let json_opt = db_array.to_sqlite_type();
        // This test will FAIL with current implementation - we'll fix it
        // Expected: Some("[]")
        // Current: None (writes NULL to database)
        assert_eq!(
            json_opt,
            Some("[]".to_string()),
            "DbStringArray(None) should serialize to empty array, not NULL"
        );
    }

    #[test]
    fn test_optional_string_array_default_is_empty() {
        // Test that OptionalStringArray::default() creates empty array
        let default_array = OptionalStringArray::default();
        assert_eq!(default_array.0, Some(Vec::new()));
    }

    // ================== Database Integration Tests ===================

    /// Helper to create a test database pool
    async fn create_test_pool(
    ) -> diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::SqliteConnection>> {
        use diesel::r2d2::{ConnectionManager, Pool};

        let database_url = format!(":memory:?cache=private&uuid={}", DbId::new());
        let manager = ConnectionManager::<diesel::SqliteConnection>::new(database_url);
        let pool = Pool::builder()
            .max_size(1)
            .build(manager)
            .expect("Failed to create SQLite test pool");

        // Run migrations
        let mut conn = pool.get().expect("Failed to get connection for migrations");
        const MIGRATIONS: diesel_migrations::EmbeddedMigrations =
            diesel_migrations::embed_migrations!("migrations_sqlite");
        conn.run_pending_migrations(MIGRATIONS)
            .expect("Failed to run SQLite migrations");

        pool
    }

    #[tokio::test]
    async fn test_direct_database_null_handling() {
        let pool = create_test_pool().await;
        let mut conn = pool.get().expect("Failed to get connection");

        // Create a temporary test table to verify NULL handling
        diesel::sql_query(
            r#"
            CREATE TEMPORARY TABLE test_arrays (
                id TEXT PRIMARY KEY,
                tags TEXT,
                greetings TEXT
            )
            "#,
        )
        .execute(&mut conn)
        .expect("Failed to create test table");

        let test_id = DbId::new().to_string();

        // Insert with NULL values directly
        diesel::sql_query(
            r#"
            INSERT INTO test_arrays (id, tags, greetings)
            VALUES (?, NULL, NULL)
            "#,
        )
        .bind::<Text, _>(&test_id)
        .execute(&mut conn)
        .expect("Failed to insert test row with NULLs");

        // Read back as raw strings
        let result: TwoStrings = diesel::sql_query(
            r#"
            SELECT tags, greetings
            FROM test_arrays
            WHERE id = ?
            "#,
        )
        .bind::<Text, _>(&test_id)
        .get_result(&mut conn)
        .expect("Failed to query test row");

        // Verify NULLs were stored
        assert_eq!(result.tags, None, "Raw NULL should be NULL in database");
        assert_eq!(
            result.greetings, None,
            "Raw NULL should be NULL in database"
        );

        // Now test that DbStringArray can deserialize these NULLs
        let tags_deserialized = DbStringArray::from_sqlite_type(result.tags);
        let greetings_deserialized = DbStringArray::from_sqlite_type(result.greetings);

        // Both should become empty arrays
        assert_eq!(
            tags_deserialized.0,
            Some(Vec::new()),
            "DbStringArray should deserialize NULL to empty array"
        );
        assert_eq!(
            greetings_deserialized.0,
            Some(Vec::new()),
            "DbStringArray should deserialize NULL to empty array"
        );
    }

    #[tokio::test]
    async fn test_roundtrip_empty_array_not_null() {
        let pool = create_test_pool().await;
        let mut conn = pool.get().expect("Failed to get connection");

        // Create test table
        diesel::sql_query(
            r#"
            CREATE TEMPORARY TABLE test_roundtrip (
                id TEXT PRIMARY KEY,
                tags TEXT
            )
            "#,
        )
        .execute(&mut conn)
        .expect("Failed to create test table");

        let test_id = DbId::new().to_string();

        // Create empty array
        let empty_array = DbStringArray(Some(Vec::new()));
        let serialized = empty_array.to_sqlite_type();

        // Insert using the serialized value
        diesel::sql_query(
            r#"
            INSERT INTO test_roundtrip (id, tags)
            VALUES (?, ?)
            "#,
        )
        .bind::<Text, _>(&test_id)
        .bind::<diesel::sql_types::Nullable<Text>, _>(serialized.as_deref())
        .execute(&mut conn)
        .expect("Failed to insert roundtrip row");

        // Read back as raw string
        let result: SingleString = diesel::sql_query(
            r#"
            SELECT tags
            FROM test_roundtrip
            WHERE id = ?
            "#,
        )
        .bind::<Text, _>(&test_id)
        .get_result(&mut conn)
        .expect("Failed to query roundtrip row");

        // Should be "[]" not NULL
        assert_eq!(
            result.tags,
            Some("[]".to_string()),
            "Empty array should write '[]' to database, not NULL"
        );
    }

    #[tokio::test]
    async fn test_roundtrip_none_writes_empty_array() {
        let pool = create_test_pool().await;
        let mut conn = pool.get().expect("Failed to get connection");

        // Create test table
        diesel::sql_query(
            r#"
            CREATE TEMPORARY TABLE test_none_roundtrip (
                id TEXT PRIMARY KEY,
                tags TEXT
            )
            "#,
        )
        .execute(&mut conn)
        .expect("Failed to create test table");

        let test_id = DbId::new().to_string();

        // Create DbStringArray(None)
        let none_array = DbStringArray(None);
        let serialized = none_array.to_sqlite_type();

        // Insert using the serialized value
        diesel::sql_query(
            r#"
            INSERT INTO test_none_roundtrip (id, tags)
            VALUES (?, ?)
            "#,
        )
        .bind::<Text, _>(&test_id)
        .bind::<diesel::sql_types::Nullable<Text>, _>(serialized.as_deref())
        .execute(&mut conn)
        .expect("Failed to insert None roundtrip row");

        // Read back as raw string
        let result: SingleString = diesel::sql_query(
            r#"
            SELECT tags
            FROM test_none_roundtrip
            WHERE id = ?
            "#,
        )
        .bind::<Text, _>(&test_id)
        .get_result(&mut conn)
        .expect("Failed to query None roundtrip row");

        // CRITICAL TEST: DbStringArray(None) should write "[]" not NULL
        assert_eq!(
            result.tags,
            Some("[]".to_string()),
            "DbStringArray(None) should write '[]' to database, not NULL"
        );
    }
}
