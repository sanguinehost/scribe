#!/usr/bin/env python3
"""
Fix nullable/non-nullable column mismatches in SQLite database.

This script recreates tables that have incorrect NOT NULL constraints due to
SQLite's inability to handle ALTER COLUMN DROP NOT NULL.

Usage:
    python fix_nullable_columns.py --db-path scribe_dev.db
"""

import argparse
import sqlite3
import sys
from pathlib import Path

# Known problematic columns that need fixing
# Format: (table_name, column_name, should_be_nullable, reason)
FIXES_NEEDED = [
    # Phase 2 comprehensive fixes - all ALTER COLUMN operations detected
    ('character_assets', 'uri', True, 'Migration 2025-06-06 tried to DROP NOT NULL'),
    ('chat_sessions', 'character_id', True, 'Migration 2025-06-17 tried to DROP NOT NULL'),
    ('chat_sessions', 'prompt_template_id', True, 'Optional template selection'),
    ('chat_messages', 'model_name', True, 'Added in later migration, should be nullable'),
    ('characters', 'alternate_greetings', True, 'JSON array field, should be nullable'),
    ('agent_context_analysis', 'message_id', False, 'Made required in migration 2025-08-11-093707'),
    ('chronicle_events', 'timestamp_iso8601', True, 'Timestamp field with auto-generation'),
    ('lorebook_entries', 'lorebook_id', False, 'Foreign key, must reference parent lorebook'),
    ('lorebooks', 'character_id', True, 'Standalone lorebooks allowed, character_id optional'),
    ('lorebooks', 'name', False, 'Required field for lorebook identification'),
]

def get_table_schema(conn, table_name):
    """Get the current schema of a table using PRAGMA"""
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = cursor.fetchall()

    # Format: (cid, name, type, notnull, dflt_value, pk)
    return [
        {
            'name': col[1],
            'type': col[2],
            'not_null': bool(col[3]),
            'default': col[4],
            'primary_key': bool(col[5])
        }
        for col in columns
    ]

def get_table_indexes(conn, table_name):
    """Get all indexes for a table"""
    cursor = conn.cursor()
    cursor.execute(f"""
        SELECT name, sql
        FROM sqlite_master
        WHERE type='index' AND tbl_name=? AND sql IS NOT NULL
    """, (table_name,))
    return cursor.fetchall()

def get_table_triggers(conn, table_name):
    """Get all triggers for a table"""
    cursor = conn.cursor()
    cursor.execute(f"""
        SELECT name, sql
        FROM sqlite_master
        WHERE type='trigger' AND tbl_name=?
    """, (table_name,))
    return cursor.fetchall()

def get_foreign_keys(conn, table_name):
    """Get foreign key constraints"""
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA foreign_key_list({table_name})")
    return cursor.fetchall()

def generate_create_table_sql(table_name, columns):
    """Generate CREATE TABLE SQL from column definitions"""
    col_defs = []

    for col in columns:
        parts = [col['name'], col['type']]

        if col['primary_key']:
            if col['type'] == 'INTEGER':
                parts.append('PRIMARY KEY AUTOINCREMENT')
            else:
                parts.append('PRIMARY KEY')

        if col['not_null'] and not col['primary_key']:
            parts.append('NOT NULL')

        if col['default'] is not None:
            parts.append(f"DEFAULT {col['default']}")

        col_defs.append(' '.join(parts))

    return f"CREATE TABLE {table_name}_new (\n    " + ',\n    '.join(col_defs) + "\n)"

def fix_table(conn, table_name, column_name, should_be_nullable):
    """Recreate a table with corrected nullable constraint"""
    print(f"Fixing {table_name}.{column_name} (nullable={should_be_nullable})")

    # Get current schema
    columns = get_table_schema(conn, table_name)
    indexes = get_table_indexes(conn, table_name)
    triggers = get_table_triggers(conn, table_name)

    # Find and modify the column
    found = False
    for col in columns:
        if col['name'] == column_name:
            print(f"  Current: {col['name']} {col['type']} NOT NULL={col['not_null']}")
            col['not_null'] = not should_be_nullable
            print(f"  Fixed:   {col['name']} {col['type']} NOT NULL={col['not_null']}")
            found = True
            break

    if not found:
        print(f"  WARNING: Column '{column_name}' not found in table '{table_name}'")
        return False

    # Generate recreation SQL
    create_sql = generate_create_table_sql(table_name, columns)

    print(f"  Recreating table...")
    print(f"  CREATE SQL: {create_sql[:100]}...")

    try:
        # Disable foreign keys during recreation
        conn.execute("PRAGMA foreign_keys = OFF")

        # Begin transaction
        conn.execute("BEGIN TRANSACTION")

        # Create new table
        conn.execute(create_sql)

        # Copy data
        column_names = [col['name'] for col in columns]
        columns_str = ', '.join(column_names)
        conn.execute(f"""
            INSERT INTO {table_name}_new ({columns_str})
            SELECT {columns_str} FROM {table_name}
        """)

        # Drop old table
        conn.execute(f"DROP TABLE {table_name}")

        # Rename new table
        conn.execute(f"ALTER TABLE {table_name}_new RENAME TO {table_name}")

        # Recreate indexes
        for index_name, index_sql in indexes:
            if index_sql:  # Skip auto-generated indexes
                print(f"  Recreating index: {index_name}")
                conn.execute(index_sql)

        # Recreate triggers
        for trigger_name, trigger_sql in triggers:
            print(f"  Recreating trigger: {trigger_name}")
            conn.execute(trigger_sql)

        # Commit transaction
        conn.execute("COMMIT")

        # Re-enable foreign keys
        conn.execute("PRAGMA foreign_keys = ON")

        print(f"  ✓ Successfully fixed {table_name}.{column_name}")
        return True

    except Exception as e:
        print(f"  ✗ Error fixing {table_name}: {e}")
        conn.execute("ROLLBACK")
        conn.execute("PRAGMA foreign_keys = ON")
        return False

def main():
    parser = argparse.ArgumentParser(
        description='Fix nullable/non-nullable column mismatches in SQLite database'
    )
    parser.add_argument('--db-path', type=str, default='scribe_dev.db',
                        help='Path to SQLite database file')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would be done without making changes')

    args = parser.parse_args()

    db_path = Path(args.db_path)
    if not db_path.exists():
        print(f"Error: Database file '{db_path}' not found")
        sys.exit(1)

    print(f"Connecting to database: {db_path}")
    conn = sqlite3.connect(str(db_path))

    print(f"Found {len(FIXES_NEEDED)} tables/columns to fix:")
    for table_name, column_name, should_be_nullable, reason in FIXES_NEEDED:
        print(f"  • {table_name}.{column_name} (nullable={should_be_nullable}) - {reason}")

    if args.dry_run:
        print("\n[DRY RUN] No changes will be made")
        return

    print("\nApplying fixes...")
    success_count = 0

    for table_name, column_name, should_be_nullable, reason in FIXES_NEEDED:
        if fix_table(conn, table_name, column_name, should_be_nullable):
            success_count += 1

    conn.close()

    print(f"\n✓ Successfully fixed {success_count}/{len(FIXES_NEEDED)} tables")

    if success_count == len(FIXES_NEEDED):
        print("\n✓ All fixes applied successfully!")
        print("Next steps:")
        print("  1. Regenerate schema: cd backend && diesel print-schema --database-url sqlite:///path/to/scribe_dev.db > src/schema_sqlite.rs")
        print("  2. Run cargo check to verify error reduction")
    else:
        print("\n⚠ Some fixes failed - review errors above")
        sys.exit(1)

if __name__ == '__main__':
    main()
