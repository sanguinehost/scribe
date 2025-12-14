#!/bin/bash
# SQLite Schema Regeneration Workflow
#
# This script automates the complete SQLite schema regeneration process:
# 1. Run all SQLite migrations
# 2. Generate schema from database
# 3. Apply necessary fixes (Float→Double, MessageType, sql_types module)
# 4. Verify schema.rs conditional wrapper
#
# Usage: ./scripts/regenerate_sqlite_schema.sh

set -e  # Exit on error

echo "🔄 SQLite Schema Regeneration Workflow"
echo "======================================="

# Step 1: Clean and run migrations
echo ""
echo "📦 Step 1: Running SQLite migrations..."
rm -f scribe_dev.db
diesel migration run --database-url=sqlite://scribe_dev.db --migration-dir=migrations_sqlite
echo "✓ All migrations applied"

# Step 2: Generate schema
echo ""
echo "📝 Step 2: Generating schema..."
diesel print-schema --database-url=sqlite://scribe_dev.db --config-file=diesel_sqlite.toml > src/schema_sqlite_new.rs
echo "✓ Schema generated"

# Step 3: Apply fixes
echo ""
echo "🔧 Step 3: Applying schema fixes..."
python3 scripts/fix_sqlite_schema.py src/schema_sqlite_new.rs

# Step 4: Replace schema
echo ""
echo "📋 Step 4: Replacing schema file..."
mv src/schema_sqlite_new.rs src/schema_sqlite.rs
echo "✓ Schema replaced"

# Step 5: Verify conditional wrapper
echo ""
echo "🔍 Step 5: Verifying schema.rs..."
if ! grep -q "#\[cfg(feature = \"sqlite-backend\")]" src/schema.rs; then
    echo "⚠️  WARNING: schema.rs is not a conditional wrapper!"
    echo "   Restoring conditional wrapper..."
    cat > src/schema.rs << 'EOF'
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
EOF
    echo "✓ Restored conditional wrapper"
else
    echo "✓ schema.rs is correct"
fi

# Step 6: Quick compile check
echo ""
echo "🧪 Step 6: Testing compilation..."
if cargo check --no-default-features --features sqlite-backend --message-format=short 2>&1 | head -20 | grep -q "^error"; then
    echo "⚠️  Compilation has errors (expected if code needs DbUuid/DbDateTime conversions)"
    echo "   Run: cargo check --no-default-features --features sqlite-backend 2>&1 | tee /tmp/sqlite_errors.log"
else
    echo "✓ SQLite backend compiles successfully!"
fi

echo ""
echo "✅ Schema regeneration complete!"
echo ""
echo "Next steps:"
echo "  - Review changes: git diff src/schema_sqlite.rs"
echo "  - Full check: cargo check --no-default-features --features sqlite-backend"
echo "  - Commit: git add src/schema_sqlite.rs migrations_sqlite/"
