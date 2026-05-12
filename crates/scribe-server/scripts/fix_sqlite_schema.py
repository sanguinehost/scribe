#!/usr/bin/env python3
"""
Automated SQLite Schema Fixer

This script fixes diesel print-schema output for SQLite to match our custom type system:
1. Float -> Double for BigDecimal fields (REAL is 8-byte f64, not f32)
2. Adds sql_types module with MessageType enum
3. Updates chat_messages.message_type to use MessageType

Usage:
    python3 scripts/fix_sqlite_schema.py src/schema_sqlite_new.rs

The script modifies the file in-place.
"""

import re
import sys
from pathlib import Path


def fix_schema(schema_path: Path) -> None:
    """Fix the generated SQLite schema file."""

    with open(schema_path, 'r') as f:
        content = f.read()

    original_content = content

    # Step 1: Add sql_types module at the top (after the @generated comment)
    # Only add if it doesn't already exist
    if 'pub mod sql_types' not in content:
        sql_types_module = '''
pub mod sql_types {
    // Re-export custom SQLite types for use in table definitions
    pub use crate::db::sqlite_types::{SqliteUuid, SqliteDateTime, SqliteJson, SqliteBigDecimal};

    // MessageType: SQLite doesn't have native enums, so we just use Text
    // The application layer (models/chats.rs) handles the enum conversion
    pub type MessageType = diesel::sql_types::Text;

    // Binary: SQLite BLOB type for binary data (Vec<u8>)
    pub type Binary = diesel::sql_types::Binary;
}
'''

        content = re.sub(
            r'(// @generated automatically by Diesel CLI\.)\n',
            r'\1\n' + sql_types_module,
            content,
            count=1
        )

    # Step 2: Fix Float -> Double for cost tracking fields
    # These fields use BigDecimal which maps to Double (f64), not Float (f32)
    cost_fields = [
        'actual_cost',
        'modified_cost',
        'actual_charge',
        'total_actual_cost',
        'total_modified_cost',
        'total_actual_charge',
    ]

    for field in cost_fields:
        # Match pattern: field_name -> Float,
        content = re.sub(
            rf'(\s+{field} -> )Float,',
            r'\1Double,',
            content
        )

    # Step 3: Update chat_messages table to use MessageType for message_type field
    # Note: We no longer need diesel_derive_enum since MessageType is just a type alias
    # The pattern should still work without adding the use statement

    # Update message_type field to use MessageType enum
    content = re.sub(
        r'(\s+message_type -> )Text,',
        r'\1crate::schema::sql_types::MessageType,',
        content
    )

    # Step 4: Verify we made changes
    if content == original_content:
        print("Warning: No changes made to schema file. Check if patterns match.")
        return

    # Write back the fixed content
    with open(schema_path, 'w') as f:
        f.write(content)

    print(f"✓ Fixed schema file: {schema_path}")
    print(f"  - Added sql_types module")
    print(f"  - Fixed {len([f for f in cost_fields if f in original_content])} cost fields: Float -> Double")
    print(f"  - Updated chat_messages.message_type to use MessageType enum")


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 scripts/fix_sqlite_schema.py <schema_file>")
        print("Example: python3 scripts/fix_sqlite_schema.py src/schema_sqlite_new.rs")
        sys.exit(1)

    schema_path = Path(sys.argv[1])

    if not schema_path.exists():
        print(f"Error: Schema file not found: {schema_path}")
        sys.exit(1)

    fix_schema(schema_path)
    print("\nDone! You can now:")
    print(f"  mv {schema_path} src/schema_sqlite.rs")
    print("  cargo check --no-default-features --features sqlite-backend")


if __name__ == "__main__":
    main()
