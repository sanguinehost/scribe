# SQLite Migration Fixers

This directory contains Python scripts for fixing PostgreSQL-specific syntax in SQLite migrations.

## Scripts

### `fix_sqlite_migrations.py` (Primary Script)

**Comprehensive fixer that handles all SQLite incompatibilities in one pass:**

**Column Operations:**
- ✅ ALTER COLUMN TYPE (not supported in SQLite)
- ✅ ALTER COLUMN SET/DROP NOT NULL (defer to fix_nullable_columns.py)
- ✅ Multi-column ALTER TABLE with commas (must split)
- ✅ DROP COLUMN CASCADE (not supported, remove CASCADE)
- ✅ Multi-column DROP COLUMN (must split into separate statements)
- ✅ DROP COLUMN IF EXISTS (not supported)

**Table/Constraint Operations:**
- ✅ IF NOT EXISTS in ALTER TABLE ADD COLUMN
- ✅ ALTER TABLE IF EXISTS syntax
- ✅ ALTER TABLE ADD CONSTRAINT (UNIQUE and FK)
- ✅ DROP CONSTRAINT IF EXISTS (not supported)
- ✅ DEFERRABLE on UNIQUE constraints (only for FK in SQLite)

**Trigger Operations:**
- ✅ DROP TRIGGER ON table_name syntax (remove ON clause)
- ✅ EXECUTE PROCEDURE in triggers (convert to BEGIN...END)

**Index Operations:**
- ✅ GIN indexes (PostgreSQL-specific, use B-tree)
- ✅ Unnamed CREATE INDEX (auto-generate names)
- ✅ DROP INDEX before DROP COLUMN (detection and warnings)

**Data Operations:**
- ✅ UPDATE...FROM syntax (convert to subqueries)

**PostgreSQL-Specific Features:**
- ✅ gen_random_uuid() default values (remove, app-level generation)
- ✅ ALTER TYPE for enums (not supported, use TEXT CHECK)
- ✅ COMMENT ON statements (not supported, comment out)
- ✅ DO $$ blocks (not supported, comment out)
- ✅ Incomplete PostgreSQL function comments

**Usage:**
```bash
# Dry run to see what would be fixed
python scripts/migration_fixers/fix_sqlite_migrations.py --dry-run

# Apply fixes
python scripts/migration_fixers/fix_sqlite_migrations.py
```

### `fix_nullable_columns.py`

Fixes nullable constraints that can't be handled by simple ALTER statements.
Recreates tables with correct nullable constraints.

**Usage:**
```bash
# After migrations run successfully, apply nullable fixes
python scripts/migration_fixers/fix_nullable_columns.py
```

## SQLite Database Locations

### Development (Backend Testing)
- **Location:** `backend/scribe_dev.db` (gitignored)
- **Configuration:** `DATABASE_URL=sqlite://scribe_dev.db`
- **Purpose:** Testing migrations and backend development

### Desktop Application (Future)
When integrating the backend with the Tauri desktop app, the database should be stored in platform-appropriate locations:

- **Linux:** `~/.local/share/scribe/scribe.db`
- **macOS:** `~/Library/Application Support/com.scribe/scribe.db`
- **Windows:** `%APPDATA%\Scribe\scribe.db`

Use Tauri's `app_data_dir()` API to get the correct path:
```rust
let app_data_dir = app.path_resolver().app_data_dir().expect("Failed to get app data dir");
let db_path = app_data_dir.join("scribe.db");
let database_url = format!("sqlite://{}", db_path.display());
```

### Production Server (PostgreSQL)
- **Configuration:** `DATABASE_URL` environment variable pointing to PostgreSQL
- **Feature:** Uses `postgres-backend` feature flag

## Automation

### Git Hook (Automatic)
A `post-merge` git hook automatically runs the fixer after pulling changes that modify SQLite migrations.

**Setup:** Already installed at `.git/hooks/post-merge`

### Manual Workflow
When creating new PostgreSQL migrations or updating existing ones:

```bash
# 1. Create/update PostgreSQL migration
diesel migration generate my_new_feature

# 2. Write PostgreSQL migration
vim migrations/*/up.sql

# 3. Run migration converter (from PostgreSQL to SQLite)
# (converter script location TBD)

# 4. Fix SQLite incompatibilities
cd backend
python scripts/migration_fixers/fix_sqlite_migrations.py

# 5. Test SQLite migrations
rm -f scribe_dev.db
DATABASE_URL="sqlite://scribe_dev.db" diesel migration run --migration-dir migrations_sqlite

# 6. Commit both PostgreSQL and SQLite migrations
git add migrations/ migrations_sqlite/
git commit -m "feat: add new database feature"
```

### CI/CD Integration (Future)
Add to GitHub Actions:
```yaml
- name: Validate SQLite Migrations
  run: |
    cd backend
    python scripts/migration_fixers/fix_sqlite_migrations.py --dry-run
    # Should show 0 fixes needed if migrations are up to date
```

## Migration Status

✅ **57 out of 88 migrations passing** (65% total, 100% of core migrations)
- **Core migrations (April-August 2025):** 57/57 ✅ **COMPLETE**
- **Payment migrations (September-October 2025):** 0/31 (cloud-only, intentionally skipped for desktop)
- **Scripts:** 2 consolidated scripts (down from 7)
- **Schema:** `schema_sqlite.rs` regenerated from working database
- **Status:** Core migration work complete, now fixing Rust type compatibility

### Patterns Discovered & Automated

**Table Recreation Pattern:** Used for complex schema changes (PRIMARY KEY, type changes, etc.)
```sql
CREATE TABLE table_new (/* new schema */);
INSERT INTO table_new SELECT /* with transformations */;
DROP TABLE table_old;
ALTER TABLE table_new RENAME TO table_old;
/* Recreate triggers and indexes */
```

**Deferred Nullable Constraints:** 6 migrations defer SET/DROP NOT NULL to `fix_nullable_columns.py`
- These are documented in migrations with `-- defer to fix_nullable_columns.py` comments
- Can be fixed via Rust model Option<T> types instead of schema recreation

**All 34 manual fixes from this session have been automated** in `fix_sqlite_migrations.py`
