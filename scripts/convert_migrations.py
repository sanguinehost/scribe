#!/usr/bin/env python3
"""
PostgreSQL to SQLite Migration Converter

Converts Diesel PostgreSQL migrations to SQLite-compatible format.
Handles type mappings, extension removal, function conversion, and index optimization.

Usage:
    python convert_migrations.py --all                    # Convert all migrations
    python convert_migrations.py --core                   # Convert core MVP migrations only
    python convert_migrations.py --migration <name>       # Convert specific migration
    python convert_migrations.py --input migrations --output migrations_sqlite  # Custom paths
"""

import argparse
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple

# ANSI color codes for terminal output
class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'

@dataclass
class ConversionResult:
    """Results from a migration conversion"""
    warnings: List[str] = field(default_factory=list)
    changes: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def has_errors(self) -> bool:
        return len(self.errors) > 0

    def summary(self) -> str:
        return (f"Changes: {len(self.changes)}, "
                f"Warnings: {len(self.warnings)}, "
                f"Errors: {len(self.errors)}")

class MigrationConverter:
    """Converts PostgreSQL migrations to SQLite format"""

    # Type mappings: PostgreSQL → SQLite
    TYPE_MAPPINGS = {
        r'\bUUID\b': 'TEXT',
        r'\bBYTEA\b': 'BLOB',
        r'\bJSONB\b': 'TEXT',
        r'\bTEXT\s*\[\s*\]': 'TEXT',  # TEXT[] arrays
        r'\bVARCHAR\s*\(\s*\d+\s*\)': 'TEXT',
        r'\bCHARACTER\s+VARYING\s*\(\s*\d+\s*\)': 'TEXT',
        r'\bTIMESTAMPTZ\b': 'DATETIME',
        r'\bTIMESTAMP\s+WITH\s+TIME\s+ZONE\b': 'DATETIME',
        r'\bTIMESTAMP\b': 'DATETIME',
        r'\bBIGSERIAL\b': 'INTEGER',
        r'\bSERIAL\b': 'INTEGER',
        r'\bBIGINT\b': 'INTEGER',
        # Custom enum types (convert to TEXT)
        r'\buser_role\b': 'TEXT',
        r'\baccount_status\b': 'TEXT',
        r'\bmessage_type\b': 'TEXT',
    }

    # Core migrations needed for MVP (identified from Task 1.2.4)
    CORE_MIGRATIONS = [
        '00000000000000_diesel_initial_setup',
        '2025-04-18-103148_create_sessions_table',
        '2025-04-21-111127_add_missing_character_fields',
        '2025-04-23-233746_add_chat_session_settings',
        '2025-04-25-095032_add_user_id_to_chat_messages',
        '2025-05-03-145838_add_email_to_users',
        '2025-05-09-004621_add_encryption_fields_to_users',
        '2025-05-09-015708_update_sensitive_fields_to_bytea',
        '2025-05-09-100210_add_nonce_fields_for_encryption',
        '2025-05-10-130917_add_nonce_fields_to_users',
        '2025-05-14-234601_add_user_roles',
        '2025-05-15-020047_add_account_status_to_users',
        '2025-05-19-023621_create_chat_character_overrides',
        '2025-05-21-073445_create_user_personas_table',
        '2025-05-21-073459_modify_chat_sessions_table_for_personas',
        '2025-05-22-030543_add_default_persona_id_to_users',
        '2025-05-22-134803_alter_lorebooks_table',
        '2025-05-22-134814_alter_lorebook_entries_table',
        '2025-05-22-134824_create_chat_session_lorebooks_table',
        '2025-05-25-074649_add_timestamps_to_chat_session_lorebooks',
        '2025-05-25-124404_encrypt_chat_sessions_user_data',
        '2025-06-03-091600_create_character_lorebooks_table',
        '2025-06-04-084735_fix_alternate_greetings_nullable',
        '2025-06-05-123407_create_chat_character_lorebook_overrides',
        '2025-06-15-151918_create_message_variants_table',
        '2025-06-17-084930_add_chat_mode_to_sessions',
        '2025-06-21-115453_create_chronicle_tables',
        '2025-06-22-111407_add_model_name_to_chat_messages',
        '2025-06-25-113023_encrypt_chronicle_events',
        '2025-06-26-004000_enhance_chronicle_events_ars_fabula',
    ]

    def __init__(self):
        self.result = ConversionResult()

    def convert(self, sql: str) -> str:
        """Main conversion method - applies all transformations"""
        sql = self._remove_extensions(sql)
        sql = self._remove_enum_types(sql)
        sql = self._remove_functions(sql)
        sql = self._convert_create_tables(sql)
        sql = self._convert_alter_tables(sql)
        sql = self._convert_indexes(sql)
        sql = self._convert_triggers(sql)
        sql = self._convert_defaults(sql)
        sql = self._apply_type_mappings(sql)

        return sql

    def _remove_extensions(self, sql: str) -> str:
        """Remove PostgreSQL extension creation"""
        pattern = r'CREATE EXTENSION.*?;'

        def replace_fn(match):
            extension = match.group(0)
            self.result.changes.append(f"Removed PostgreSQL extension: {extension[:50]}...")
            return '-- ' + extension + ' -- Removed: SQLite does not support extensions'

        return re.sub(pattern, replace_fn, sql, flags=re.IGNORECASE | re.DOTALL)

    def _remove_enum_types(self, sql: str) -> str:
        """Remove CREATE TYPE ... AS ENUM statements"""
        pattern = r'CREATE TYPE\s+(\w+)\s+AS\s+ENUM\s*\(([^)]+)\)\s*;'

        def replace_fn(match):
            type_name = match.group(1)
            enum_values = match.group(2)
            self.result.changes.append(f"Removed ENUM type '{type_name}': values {enum_values[:50]}")
            self.result.warnings.append(
                f"ENUM type '{type_name}' removed - fields using this type will be TEXT. "
                f"Consider adding CHECK constraints if validation needed."
            )
            return f'-- CREATE TYPE {type_name} -- Removed: SQLite uses TEXT for enums'

        return re.sub(pattern, replace_fn, sql, flags=re.IGNORECASE | re.DOTALL)

    def _remove_functions(self, sql: str) -> str:
        """Remove PL/pgSQL functions"""
        # Match CREATE OR REPLACE FUNCTION ... $$ LANGUAGE plpgsql;
        pattern = r'CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION.*?\$\$\s*LANGUAGE\s+plpgsql\s*;'

        def replace_fn(match):
            func = match.group(0)
            func_name_match = re.search(r'FUNCTION\s+(\w+)', func, re.IGNORECASE)
            func_name = func_name_match.group(1) if func_name_match else 'unknown'
            self.result.changes.append(f"Removed PostgreSQL function: {func_name}")
            return f'-- {func[:100]}... -- Removed: SQLite does not support PL/pgSQL'

        return re.sub(pattern, replace_fn, sql, flags=re.IGNORECASE | re.DOTALL)

    def _convert_create_tables(self, sql: str) -> str:
        """Convert CREATE TABLE statements"""
        # This is complex - handle SERIAL, DEFAULT uuid_generate_v4(), etc.

        # Convert SERIAL PRIMARY KEY to INTEGER PRIMARY KEY AUTOINCREMENT
        sql = re.sub(
            r'\bSERIAL\s+PRIMARY\s+KEY\b',
            'INTEGER PRIMARY KEY AUTOINCREMENT',
            sql,
            flags=re.IGNORECASE
        )

        sql = re.sub(
            r'\bBIGSERIAL\s+PRIMARY\s+KEY\b',
            'INTEGER PRIMARY KEY AUTOINCREMENT',
            sql,
            flags=re.IGNORECASE
        )

        # Remove DEFAULT uuid_generate_v4() (SQLite can't generate UUIDs)
        def remove_uuid_default(match):
            self.result.warnings.append(
                f"Removed 'DEFAULT uuid_generate_v4()' - UUIDs must be generated in application code"
            )
            return match.group(1)  # Just the column definition without DEFAULT

        sql = re.sub(
            r'(UUID\s+(?:PRIMARY\s+KEY\s+)?(?:NOT\s+NULL\s+)?)DEFAULT\s+uuid_generate_v4\(\)',
            remove_uuid_default,
            sql,
            flags=re.IGNORECASE
        )

        return sql

    def _convert_alter_tables(self, sql: str) -> str:
        """Convert ALTER TABLE statements"""
        # Most ALTER TABLE syntax is compatible, just need type conversions
        # Those will be handled by _apply_type_mappings
        return sql

    def _convert_indexes(self, sql: str) -> str:
        """Convert CREATE INDEX statements, warn about GIN indexes"""
        # Pattern for GIN indexes
        gin_pattern = r'CREATE\s+INDEX\s+(\w+)\s+ON\s+(\w+)\s+USING\s+GIN\s*\(([^)]+)\)'

        def convert_gin(match):
            index_name = match.group(1)
            table_name = match.group(2)
            columns = match.group(3)

            self.result.warnings.append(
                f"GIN index '{index_name}' on {table_name}({columns}) converted to regular index. "
                f"Full-text search functionality will be lost. Consider using FTS5 extension."
            )

            # Convert to regular index
            return f'CREATE INDEX {index_name} ON {table_name} ({columns})'

        return re.sub(gin_pattern, convert_gin, sql, flags=re.IGNORECASE)

    def _convert_triggers(self, sql: str) -> str:
        """Convert trigger calls to SQLite trigger syntax"""
        # Remove diesel_manage_updated_at calls and convert to SQLite triggers
        pattern = r"SELECT\s+diesel_manage_updated_at\s*\(\s*['\"](\w+)['\"]\s*\)\s*;"

        def replace_with_trigger(match):
            table_name = match.group(1)
            self.result.changes.append(f"Converted diesel_manage_updated_at for table '{table_name}' to SQLite trigger")

            trigger = f"""
-- SQLite trigger for updating timestamps on {table_name}
CREATE TRIGGER IF NOT EXISTS update_{table_name}_timestamp
AFTER UPDATE ON {table_name}
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE {table_name} SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;"""
            return trigger

        return re.sub(pattern, replace_with_trigger, sql, flags=re.IGNORECASE)

    def _convert_defaults(self, sql: str) -> str:
        """Convert DEFAULT value syntax"""
        # Convert DEFAULT NOW() to DEFAULT CURRENT_TIMESTAMP
        sql = re.sub(
            r'\bDEFAULT\s+NOW\s*\(\s*\)',
            'DEFAULT CURRENT_TIMESTAMP',
            sql,
            flags=re.IGNORECASE
        )

        return sql

    def _apply_type_mappings(self, sql: str) -> str:
        """Apply all type mappings"""
        for pg_type, sqlite_type in self.TYPE_MAPPINGS.items():
            sql = re.sub(pg_type, sqlite_type, sql, flags=re.IGNORECASE)

        return sql

def convert_migration_file(input_path: Path, output_path: Path) -> ConversionResult:
    """Convert a single migration file (up.sql or down.sql)"""
    converter = MigrationConverter()

    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            sql = f.read()

        # Add header comment
        header = f"""-- SQLite Migration (Converted from PostgreSQL)
-- Original: {input_path.name}
-- Conversion date: {__import__('datetime').datetime.now().isoformat()}
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

"""

        converted = converter.convert(sql)

        # Write output
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write(converted)

        converter.result.changes.append(f"✓ Converted: {input_path.name} → {output_path.name}")

    except Exception as e:
        converter.result.errors.append(f"Failed to convert {input_path}: {str(e)}")

    return converter.result

def main():
    parser = argparse.ArgumentParser(
        description='Convert PostgreSQL migrations to SQLite format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument('--all', action='store_true',
                        help='Convert all migrations')
    parser.add_argument('--core', action='store_true',
                        help='Convert core MVP migrations only')
    parser.add_argument('--migration', type=str,
                        help='Convert specific migration by name')
    parser.add_argument('--input', type=str, default='backend/migrations',
                        help='Input migrations directory (default: backend/migrations)')
    parser.add_argument('--output', type=str, default='backend/migrations_sqlite',
                        help='Output migrations directory (default: backend/migrations_sqlite)')
    parser.add_argument('--log', type=str, default='conversion_log.txt',
                        help='Conversion log file (default: conversion_log.txt)')

    args = parser.parse_args()

    if not (args.all or args.core or args.migration):
        parser.error('Must specify --all, --core, or --migration <name>')

    input_dir = Path(args.input)
    output_dir = Path(args.output)

    if not input_dir.exists():
        print(f"{Colors.RED}Error: Input directory '{input_dir}' does not exist{Colors.RESET}")
        sys.exit(1)

    # Determine which migrations to convert
    if args.migration:
        migrations = [args.migration]
    elif args.core:
        migrations = MigrationConverter.CORE_MIGRATIONS
    else:  # --all
        migrations = [d.name for d in sorted(input_dir.iterdir()) if d.is_dir()]

    print(f"{Colors.CYAN}PostgreSQL → SQLite Migration Converter{Colors.RESET}")
    print(f"Input:  {input_dir}")
    print(f"Output: {output_dir}")
    print(f"Migrations to convert: {len(migrations)}")
    print()

    total_result = ConversionResult()
    converted_count = 0

    for migration_name in migrations:
        migration_dir = input_dir / migration_name

        if not migration_dir.exists():
            print(f"{Colors.YELLOW}Warning: Migration '{migration_name}' not found, skipping{Colors.RESET}")
            continue

        print(f"{Colors.BLUE}Converting:{Colors.RESET} {migration_name}")

        # Convert up.sql
        up_input = migration_dir / 'up.sql'
        up_output = output_dir / migration_name / 'up.sql'

        if up_input.exists():
            result = convert_migration_file(up_input, up_output)
            total_result.warnings.extend(result.warnings)
            total_result.changes.extend(result.changes)
            total_result.errors.extend(result.errors)

        # Convert down.sql
        down_input = migration_dir / 'down.sql'
        down_output = output_dir / migration_name / 'down.sql'

        if down_input.exists():
            result = convert_migration_file(down_input, down_output)
            total_result.warnings.extend(result.warnings)
            total_result.changes.extend(result.changes)
            total_result.errors.extend(result.errors)

        if not total_result.has_errors():
            converted_count += 1
            print(f"  {Colors.GREEN}✓ Success{Colors.RESET}")
        else:
            print(f"  {Colors.RED}✗ Errors occurred{Colors.RESET}")

        print()

    # Write log file
    with open(args.log, 'w', encoding='utf-8') as f:
        f.write("PostgreSQL → SQLite Migration Conversion Log\n")
        f.write("=" * 80 + "\n\n")

        f.write(f"Converted: {converted_count}/{len(migrations)} migrations\n\n")

        f.write("\nCHANGES:\n")
        f.write("-" * 80 + "\n")
        for change in total_result.changes:
            f.write(f"  • {change}\n")

        f.write("\n\nWARNINGS (Manual Review Recommended):\n")
        f.write("-" * 80 + "\n")
        for warning in total_result.warnings:
            f.write(f"  ⚠ {warning}\n")

        if total_result.errors:
            f.write("\n\nERRORS:\n")
            f.write("-" * 80 + "\n")
            for error in total_result.errors:
                f.write(f"  ✗ {error}\n")

    # Print summary
    print()
    print("=" * 80)
    print(f"{Colors.CYAN}CONVERSION SUMMARY{Colors.RESET}")
    print("=" * 80)
    print(f"Migrations converted: {Colors.GREEN}{converted_count}/{len(migrations)}{Colors.RESET}")
    print(f"Changes applied:      {len(total_result.changes)}")
    print(f"Warnings:             {Colors.YELLOW}{len(total_result.warnings)}{Colors.RESET}")
    print(f"Errors:               {Colors.RED if total_result.has_errors() else Colors.GREEN}{len(total_result.errors)}{Colors.RESET}")
    print()
    print(f"Detailed log written to: {args.log}")
    print()

    if total_result.warnings:
        print(f"{Colors.YELLOW}⚠ Review warnings in {args.log} before using migrations{Colors.RESET}")

    if total_result.has_errors():
        print(f"{Colors.RED}✗ Errors occurred - check {args.log}{Colors.RESET}")
        sys.exit(1)
    else:
        print(f"{Colors.GREEN}✓ Conversion completed successfully{Colors.RESET}")

if __name__ == '__main__':
    main()
