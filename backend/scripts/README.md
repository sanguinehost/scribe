# Backend Scripts

## Active Scripts

These scripts are part of the current SQLite backend workflow:

### `convert_migrations.py` - PostgreSQL → SQLite Migration Converter

**Purpose:** Automatically convert PostgreSQL migrations to SQLite format

**Usage:**
```bash
python3 scripts/convert_migrations.py migrations/{timestamp}_feature_name
```

**What it does:**
- Type conversions (UUID→TEXT, TIMESTAMP→INTEGER, DECIMAL→REAL, etc.)
- Constraint syntax fixes
- SQL dialect differences
- Creates `migrations_sqlite/{timestamp}_feature_name/` with converted up.sql and down.sql

**When to use:** After creating a new PostgreSQL migration

---

### `fix_sqlite_schema.py` - Schema Post-Processor

**Purpose:** Fix diesel print-schema output for SQLite custom type system

**Usage:**
```bash
diesel print-schema --database-url=sqlite://scribe_dev.db > src/schema_sqlite_new.rs
python3 scripts/fix_sqlite_schema.py src/schema_sqlite_new.rs
mv src/schema_sqlite_new.rs src/schema_sqlite.rs
```

**What it does:**
1. Adds `sql_types` module with custom type re-exports and MessageType enum
2. Fixes Float→Double for BigDecimal cost tracking fields
3. Updates message_type to use MessageType enum

**When to use:** After regenerating schema from database

---

### `regenerate_sqlite_schema.sh` - Complete Workflow Script

**Purpose:** One-command schema regeneration from migrations

**Usage:**
```bash
./scripts/regenerate_sqlite_schema.sh
```

**What it does:**
1. Drops and recreates scribe_dev.db
2. Runs all SQLite migrations
3. Generates schema via diesel print-schema
4. Applies fixes via fix_sqlite_schema.py
5. Verifies schema.rs conditional wrapper
6. Tests compilation

**When to use:** When you've added new migrations and need to regenerate the schema

---

## Workflow

### Adding a New Feature

1. **Create PostgreSQL migration:**
   ```bash
   diesel migration generate my_feature
   # Edit migrations/{timestamp}_my_feature/up.sql and down.sql
   diesel migration run  # Test on PostgreSQL
   ```

2. **Convert to SQLite:**
   ```bash
   python3 scripts/convert_migrations.py migrations/{timestamp}_my_feature
   ```

3. **Regenerate SQLite schema:**
   ```bash
   ./scripts/regenerate_sqlite_schema.sh
   ```

4. **Verify both backends compile:**
   ```bash
   cargo check --features postgres-backend
   cargo check --no-default-features --features sqlite-backend
   ```

---

## Legacy Scripts (Archived)

The `migration_fixers/` directory contains older scripts from an earlier conversion approach:
- `fix_sqlite_migrations.py` - Batch migration fixer (replaced by convert_migrations.py)
- `fix_nullable_columns.py` - Nullable column fixer (manual approach)

**Status:** Kept for reference but not used in current workflow. The newer `convert_migrations.py` handles these cases during initial conversion.

---

## Key Files

- `convert_migrations.py` - **Migration converter** (used after creating PostgreSQL migration)
- `fix_sqlite_schema.py` - **Schema fixer** (used after diesel print-schema)
- `regenerate_sqlite_schema.sh` - **Complete workflow** (one command to regenerate everything)

**Rule of thumb:**
- Creating/modifying a migration? → Use `convert_migrations.py`
- Regenerating schema? → Use `regenerate_sqlite_schema.sh`
- That's it. Don't overthink it.
