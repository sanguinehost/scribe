# SQLite Schema Generation Workflow

This document describes the automated workflow for generating and maintaining the SQLite schema for the dual-database backend architecture.

## Overview

The backend supports both PostgreSQL and SQLite through conditional compilation:
- PostgreSQL: Production backend with full feature set
- SQLite: Desktop/local backend for offline use

Both backends share the same code but use different schemas (`schema_postgres.rs` vs `schema_sqlite.rs`).

## Workflow

### 1. Create PostgreSQL Migration First

Always create migrations for PostgreSQL first, as it's the primary backend:

```bash
diesel migration generate my_feature_name
# Edit migrations/{timestamp}_my_feature_name/up.sql and down.sql
diesel migration run --database-url=postgresql://...
```

### 2. Convert to SQLite Migration

Use the automated conversion script:

```bash
python3 scripts/convert_migrations.py migrations/{timestamp}_my_feature_name
```

This handles:
- Type conversions (UUID→TEXT, TIMESTAMP→INTEGER, DECIMAL→REAL, etc.)
- Constraint syntax differences
- SQL dialect differences

**Manual adjustments needed:**
- Table renames (IF EXISTS only works for tables that exist in backend schema)
- Complex ALTER statements (SQLite has limited ALTER TABLE support)
- Check constraints (may need adjustment)

### 3. Run SQLite Migrations

```bash
rm -f scribe_dev.db  # Start fresh for clean generation
diesel migration run --database-url=sqlite://scribe_dev.db --migration-dir=migrations_sqlite
```

### 4. Generate SQLite Schema

```bash
diesel print-schema --database-url=sqlite://scribe_dev.db --config-file=diesel_sqlite.toml > src/schema_sqlite_new.rs
```

### 5. Fix Generated Schema Automatically

The diesel print-schema output needs fixes for our custom type system:

```bash
python3 scripts/fix_sqlite_schema.py src/schema_sqlite_new.rs
```

This script automatically:
1. **Adds sql_types module** with custom type re-exports and MessageType enum
2. **Fixes Float→Double** for BigDecimal cost tracking fields (REAL is f64, not f32)
3. **Updates message_type** to use MessageType enum instead of Text

**Why these fixes are needed:**
- SQLite REAL is 8-byte IEEE float (f64/Double), but diesel generates Float (f32)
- Our custom types (SqliteBigDecimal, SqliteUuid, etc.) need to be imported
- MessageType is a custom enum that needs explicit type definition

### 6. Replace Schema File

```bash
mv src/schema_sqlite_new.rs src/schema_sqlite.rs
```

### 7. Verify Conditional Wrapper

Ensure `src/schema.rs` remains a conditional wrapper (NOT actual schema content):

```rust
// Conditional schema selection based on backend feature flags

#[cfg(feature = "postgres-backend")]
#[path = "schema_postgres.rs"]
mod schema_postgres;

#[cfg(feature = "postgres-backend")]
pub use schema_postgres::*;

#[cfg(feature = "sqlite-backend")]
#[path = "schema_sqlite.rs"]
mod schema_sqlite;

#[cfg(feature = "sqlite-backend")]
pub use schema_sqlite::*;
```

**⚠️ Important:** diesel print-schema may overwrite this file. Always verify after schema generation.

### 8. Verify Compilation

Check both backends compile successfully:

```bash
# PostgreSQL backend
cargo check --features postgres-backend

# SQLite backend
cargo check --no-default-features --features sqlite-backend,desktop
```

## Type Mapping Reference

| PostgreSQL | SQLite | Rust (Postgres) | Rust (SQLite) |
|------------|--------|-----------------|---------------|
| UUID | TEXT | `uuid::Uuid` | `SqliteUuid` |
| TIMESTAMP | INTEGER | `DateTime<Utc>` | `SqliteDateTime` |
| DECIMAL/NUMERIC | REAL (f64) | `BigDecimal` | `SqliteBigDecimal` |
| JSON/JSONB | TEXT | `serde_json::Value` | `SqliteJson` |
| VARCHAR/TEXT | TEXT | `String` | `String` |
| INTEGER | INTEGER | `i32` | `i32` |
| BIGINT | INTEGER | `i64` | `i64` |
| BOOLEAN | BOOL | `bool` | `bool` |

**Critical:** Cost tracking fields use DECIMAL (Postgres) → REAL (SQLite) → `Double` in schema → `SqliteBigDecimal` in code

## Troubleshooting

### "Float vs Double" Type Errors

**Symptom:** Errors like `expected Double, found Float` for cost fields

**Fix:** Run `python3 scripts/fix_sqlite_schema.py` on the schema file

### "sql_types module not found"

**Symptom:** Can't find MessageType or custom types

**Fix:** Ensure `fix_sqlite_schema.py` ran successfully and added the module

### "Table not found in schema"

**Symptom:** Code references old table names (e.g., `votes` instead of `old_votes`)

**Fix:** Check the rename migration (`migrations_sqlite/*_rename_tables/up.sql`) executed correctly

### Schema.rs Overwritten

**Symptom:** schema.rs contains actual schema instead of conditional wrapper

**Fix:** Restore the conditional wrapper (see step 7 above)

## Scripts Reference

### `scripts/convert_migrations.py`

Converts PostgreSQL migrations to SQLite format.

```bash
python3 scripts/convert_migrations.py migrations/{timestamp}_name
```

Handles type conversions, constraint syntax, and SQL dialect differences.

### `scripts/fix_sqlite_schema.py`

Fixes diesel print-schema output for our custom type system.

```bash
python3 scripts/fix_sqlite_schema.py src/schema_sqlite_new.rs
```

Makes three critical fixes:
1. Adds sql_types module
2. Float → Double for cost fields
3. Text → MessageType for message_type

## Future Improvements

Potential automation enhancements:

1. **Single command workflow:**
   ```bash
   ./scripts/regenerate_sqlite_schema.sh
   ```

2. **Pre-commit hook** to verify schema consistency

3. **CI/CD checks** for both backends

4. **Automated testing** of migration conversion accuracy
