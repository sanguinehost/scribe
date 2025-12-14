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

@dataclass
class ColumnDefinition:
    """Represents a column in a table schema"""
    name: str
    data_type: str
    not_null: bool = False
    primary_key: bool = False
    default: str = None
    references: str = None  # "table_name(column_name)"

    def to_sql(self) -> str:
        """Generate SQL column definition"""
        parts = [self.name, self.data_type]

        if self.primary_key:
            if self.data_type == 'INTEGER':
                parts.append('PRIMARY KEY AUTOINCREMENT')
            else:
                parts.append('PRIMARY KEY')

        if self.not_null and not self.primary_key:
            parts.append('NOT NULL')

        if self.default:
            parts.append(f'DEFAULT {self.default}')

        if self.references:
            parts.append(f'REFERENCES {self.references}')

        return ' '.join(parts)

@dataclass
class TableSchema:
    """Represents a table's schema state"""
    name: str
    columns: List[ColumnDefinition] = field(default_factory=list)
    indexes: List[str] = field(default_factory=list)
    triggers: List[str] = field(default_factory=list)

    def get_column(self, name: str) -> ColumnDefinition:
        """Get column by name"""
        for col in self.columns:
            if col.name == name:
                return col
        return None

    def to_create_table_sql(self) -> str:
        """Generate CREATE TABLE SQL"""
        col_defs = [f'    {col.to_sql()}' for col in self.columns]
        return f"CREATE TABLE {self.name} (\n" + ',\n'.join(col_defs) + "\n)"

class MigrationStateTracker:
    """Tracks cumulative schema changes across migrations for intelligent conversion"""

    def __init__(self):
        self.tables = {}  # table_name -> TableSchema

    def parse_create_table(self, sql: str) -> None:
        """Parse CREATE TABLE statement and store initial state"""
        # Extract table name
        match = re.search(r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\(', sql, re.IGNORECASE)
        if not match:
            return

        table_name = match.group(1)

        # Extract column definitions (simplified parser)
        # This is a basic implementation - could be enhanced
        table_body = sql[match.end():sql.rfind(')')]

        columns = []
        for line in table_body.split(','):
            line = line.strip()
            if not line or line.startswith('--') or line.upper().startswith('CONSTRAINT'):
                continue

            # Parse column definition
            parts = line.split()
            if len(parts) >= 2:
                col_name = parts[0]
                col_type = parts[1]

                col = ColumnDefinition(
                    name=col_name,
                    data_type=col_type,
                    not_null='NOT NULL' in line.upper(),
                    primary_key='PRIMARY KEY' in line.upper(),
                    default=self._extract_default(line),
                    references=self._extract_references(line)
                )
                columns.append(col)

        self.tables[table_name] = TableSchema(name=table_name, columns=columns)

    def _extract_default(self, line: str) -> str:
        """Extract DEFAULT value from column definition"""
        match = re.search(r'DEFAULT\s+([^,\s]+)', line, re.IGNORECASE)
        return match.group(1) if match else None

    def _extract_references(self, line: str) -> str:
        """Extract REFERENCES clause from column definition"""
        match = re.search(r'REFERENCES\s+(\w+\([^)]+\))', line, re.IGNORECASE)
        return match.group(1) if match else None

    def apply_alter_column(self, table_name: str, column_name: str, operation: str, value: str = None) -> None:
        """Apply ALTER COLUMN operation to tracked state"""
        if table_name not in self.tables:
            return

        table = self.tables[table_name]
        col = table.get_column(column_name)

        if not col:
            return

        if operation == 'drop_not_null':
            col.not_null = False
        elif operation == 'set_not_null':
            col.not_null = True
        elif operation == 'set_type':
            col.data_type = value
        elif operation == 'set_default':
            col.default = value
        elif operation == 'drop_default':
            col.default = None

    def generate_table_recreation_sql(self, table_name: str) -> str:
        """Generate SQLite table recreation SQL with current tracked state"""
        if table_name not in self.tables:
            return f"-- ERROR: Table '{table_name}' not found in state tracker"

        table = self.tables[table_name]

        sql = f"""-- SQLite: Recreate table '{table_name}' to apply ALTER COLUMN changes
BEGIN TRANSACTION;

{table.to_create_table_sql().replace(table_name, f'{table_name}_new')}

-- Copy data
INSERT INTO {table_name}_new SELECT * FROM {table_name};

-- Drop old table
DROP TABLE {table_name};

-- Rename new table
ALTER TABLE {table_name}_new RENAME TO {table_name};

"""

        # Add indexes
        if table.indexes:
            sql += "-- Recreate indexes\n"
            for index_sql in table.indexes:
                sql += f"{index_sql};\n"
            sql += "\n"

        # Add triggers
        if table.triggers:
            sql += "-- Recreate triggers\n"
            for trigger_sql in table.triggers:
                sql += f"{trigger_sql};\n"
            sql += "\n"

        sql += "COMMIT;\n"

        return sql

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

    # Core migrations needed for full desktop frontend functionality
    # Includes: MVP core (30) + frontend features (26) + usage analytics (5) + recent features (6) = 62 total
    CORE_MIGRATIONS = [
        # Original core MVP migrations (30)
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
        # Essential frontend features (26)
        '2025-04-30-024952_add_history_management_to_chat_sessions',
        '2025-05-04-095859_add_model_name_to_chat_sessions',
        '2025-05-07-023752_add_gemini_options',
        '2025-05-10-100000_add_frontend_tables',
        '2025-05-10-100001_rename_tables',
        '2025-05-10-100002_add_columns_to_chat_tables',
        '2025-05-15-094128_add_token_counts_to_chat_messages',
        '2025-05-20-132227_add_unique_constraint_to_chat_character_overrides',
        '2025-05-30-142900_update_chat_settings_columns',
        '2025-06-04-030028_add_raw_prompt_fields_to_chat_messages',
        '2025-06-06-053628_create_user_settings_table',
        '2025-06-06-142918_add_avatar_data_to_character_assets',
        '2025-06-08-121354_add_sillytavern_v3_fields',
        '2025-06-10-093153_create_email_verification_tokens',
        '2025-06-25-082539_add_typing_speed_to_user_settings',
        '2025-08-09-083724_simplify_chronicle_events',
        '2025-08-10-091221_add_agent_context_analysis',
        '2025-08-10-104056_add_agent_mode_to_chat_sessions',
        '2025-08-11-082250_add_message_id_to_agent_context_analysis',
        '2025-08-11-093707_make_message_id_required_in_agent_context_analysis',
        '2025-08-11-120125_add_assistant_message_id_to_agent_context_analysis',
        '2025-08-11-131951_add_status_to_agent_context_analysis',
        '2025-08-11-135458_add_status_to_chat_messages',
        '2025-08-14-091942_fix_chronicle_events_cascade',
        '2025-08-22-072410_fix_agent_context_analysis_cascade',
        '2025-08-24-115200_add_local_llm_preferences_to_user_settings',
        # Usage analytics (5) - token tracking without billing
        '2025-09-04-073423_add_token_tracking_to_users',
        '2025-09-04-073438_add_token_tracking_to_chat_sessions',
        '2025-09-04-073452_create_usage_tracking_table',
        '2025-10-07-234639_add_total_credits_used_to_chat_sessions',
        '2025-10-08-012616_add_credits_used_to_chat_messages',
        # Recent frontend features (6)
        '2025-08-25-102506_add_model_provider_to_chat_sessions',
        '2025-09-05-062626_add_variant_metadata_to_messages',
        '2025-09-06-203551_add_prompt_template_to_chat_sessions',
        '2025-10-13-195748_fix_agent_analysis_unique_constraint',
        '2025-10-15-054608_add_template_preferences',
        '2025-10-16-173133_add_session_narrative_overrides',
    ]

    def __init__(self):
        self.result = ConversionResult()
        self.state_tracker = MigrationStateTracker()

    def convert(self, sql: str) -> str:
        """Main conversion method - applies all transformations"""
        # First pass: Track CREATE TABLE statements for state
        self._track_create_tables(sql)

        sql = self._remove_extensions(sql)
        sql = self._remove_enum_types(sql)
        sql = self._remove_functions(sql)
        sql = self._convert_create_tables(sql)
        sql = self._convert_alter_tables(sql)  # Now uses state tracker
        sql = self._convert_indexes(sql)
        sql = self._convert_triggers(sql)
        sql = self._convert_defaults(sql)
        sql = self._apply_type_mappings(sql)

        return sql

    def _track_create_tables(self, sql: str) -> None:
        """First pass: Track all CREATE TABLE statements in state tracker"""
        # Find all CREATE TABLE statements
        pattern = r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\([^;]+\);'
        matches = re.finditer(pattern, sql, re.IGNORECASE | re.DOTALL)

        for match in matches:
            table_sql = match.group(0)
            self.state_tracker.parse_create_table(table_sql)

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
        """Convert ALTER TABLE statements using state tracker for intelligent recreation"""
        from collections import defaultdict

        # Track which tables need recreation
        tables_to_recreate = set()
        alter_operations = defaultdict(list)

        # Pattern 1: ALTER COLUMN ... DROP NOT NULL
        pattern_drop_not_null = r'ALTER\s+TABLE\s+(\w+)\s+ALTER\s+COLUMN\s+(\w+)\s+DROP\s+NOT\s+NULL\s*;'

        for match in re.finditer(pattern_drop_not_null, sql, re.IGNORECASE):
            table_name = match.group(1)
            column_name = match.group(2)

            # Update state tracker
            self.state_tracker.apply_alter_column(table_name, column_name, 'drop_not_null')
            tables_to_recreate.add(table_name)
            alter_operations[table_name].append(f"DROP NOT NULL on {column_name}")

            self.result.changes.append(
                f"Table '{table_name}': Will recreate to make '{column_name}' nullable"
            )

        # Pattern 2: ALTER COLUMN ... SET NOT NULL
        pattern_set_not_null = r'ALTER\s+TABLE\s+(\w+)\s+ALTER\s+COLUMN\s+(\w+)\s+SET\s+NOT\s+NULL\s*;'

        for match in re.finditer(pattern_set_not_null, sql, re.IGNORECASE):
            table_name = match.group(1)
            column_name = match.group(2)

            # Update state tracker
            self.state_tracker.apply_alter_column(table_name, column_name, 'set_not_null')
            tables_to_recreate.add(table_name)
            alter_operations[table_name].append(f"SET NOT NULL on {column_name}")

            self.result.changes.append(
                f"Table '{table_name}': Will recreate to make '{column_name}' NOT NULL"
            )

        # Pattern 3: ALTER COLUMN ... SET DATA TYPE
        pattern_set_type = r'ALTER\s+TABLE\s+(\w+)\s+ALTER\s+COLUMN\s+(\w+)\s+(?:SET\s+DATA\s+)?TYPE\s+([^;]+);'

        for match in re.finditer(pattern_set_type, sql, re.IGNORECASE):
            table_name = match.group(1)
            column_name = match.group(2)
            new_type = match.group(3).strip()

            # Update state tracker
            self.state_tracker.apply_alter_column(table_name, column_name, 'set_type', new_type)
            tables_to_recreate.add(table_name)
            alter_operations[table_name].append(f"TYPE {new_type} on {column_name}")

            self.result.changes.append(
                f"Table '{table_name}': Will recreate to change '{column_name}' type to {new_type}"
            )

        # Pattern 4: ALTER COLUMN ... SET DEFAULT
        pattern_set_default = r'ALTER\s+TABLE\s+(\w+)\s+ALTER\s+COLUMN\s+(\w+)\s+SET\s+DEFAULT\s+([^;]+);'

        for match in re.finditer(pattern_set_default, sql, re.IGNORECASE):
            table_name = match.group(1)
            column_name = match.group(2)
            default_value = match.group(3).strip()

            # Update state tracker
            self.state_tracker.apply_alter_column(table_name, column_name, 'set_default', default_value)
            tables_to_recreate.add(table_name)
            alter_operations[table_name].append(f"SET DEFAULT {default_value} on {column_name}")

            self.result.changes.append(
                f"Table '{table_name}': Will recreate to set default {default_value} on '{column_name}'"
            )

        # Pattern 5: ALTER COLUMN ... DROP DEFAULT
        pattern_drop_default = r'ALTER\s+TABLE\s+(\w+)\s+ALTER\s+COLUMN\s+(\w+)\s+DROP\s+DEFAULT\s*;'

        for match in re.finditer(pattern_drop_default, sql, re.IGNORECASE):
            table_name = match.group(1)
            column_name = match.group(2)

            # Update state tracker
            self.state_tracker.apply_alter_column(table_name, column_name, 'drop_default')
            tables_to_recreate.add(table_name)
            alter_operations[table_name].append(f"DROP DEFAULT on {column_name}")

            self.result.changes.append(
                f"Table '{table_name}': Will recreate to remove default from '{column_name}'"
            )

        # Now generate table recreation SQL for each affected table
        for table_name in tables_to_recreate:
            operations_list = ', '.join(alter_operations[table_name])
            self.result.changes.append(
                f"Generating table recreation SQL for '{table_name}' ({operations_list})"
            )

            # Generate recreation SQL
            recreation_sql = self.state_tracker.generate_table_recreation_sql(table_name)

            # Find where to insert the recreation SQL
            # We'll replace all ALTER COLUMN statements for this table with the recreation
            patterns_for_table = [
                r'ALTER\s+TABLE\s+' + table_name + r'\s+ALTER\s+COLUMN\s+\w+\s+(?:DROP|SET)\s+(?:NOT\s+)?(?:NULL|DEFAULT|DATA\s+TYPE)[^;]*;'
            ]

            # Replace first occurrence with recreation SQL, rest with empty string
            first_replaced = False
            for pattern in patterns_for_table:
                def replacer(match):
                    nonlocal first_replaced
                    if not first_replaced:
                        first_replaced = True
                        return recreation_sql
                    else:
                        return ''  # Remove subsequent ALTER COLUMN for same table

                sql = re.sub(pattern, replacer, sql, flags=re.IGNORECASE)

        # Remove any remaining ALTER COLUMN statements (ones we couldn't track)
        remaining_alters = re.findall(r'ALTER\s+TABLE\s+\w+\s+ALTER\s+COLUMN[^;]*;', sql, re.IGNORECASE)
        if remaining_alters:
            for alter in remaining_alters[:3]:  # Show first 3
                self.result.warnings.append(f"Unhandled ALTER COLUMN: {alter[:80]}...")

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
