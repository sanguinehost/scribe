#!/usr/bin/env python3
"""
Comprehensive SQLite migration fixer.

Fixes all PostgreSQL-specific syntax issues in SQLite migrations in a single pass:
- ALTER COLUMN TYPE (not supported)
- ALTER COLUMN SET/DROP NOT NULL (not supported - defer to fix_nullable_columns.py)
- Multi-column ALTER TABLE with commas (must split)
- DROP COLUMN CASCADE (not supported)
- Multi-column DROP COLUMN (must split)
- DROP COLUMN IF EXISTS (not supported)
- IF NOT EXISTS in ALTER TABLE ADD COLUMN
- ALTER TABLE IF EXISTS
- DROP TRIGGER ON table_name syntax
- EXECUTE PROCEDURE in triggers
- gen_random_uuid() defaults
- ALTER TABLE ADD CONSTRAINT
- DROP CONSTRAINT IF EXISTS (not supported)
- Incomplete function comments
- COMMENT ON statements (not supported)
- DO $$ blocks (PostgreSQL-specific)
- UPDATE...FROM syntax (use subqueries)
- GIN indexes (PostgreSQL-specific, use B-tree)
- ALTER TYPE for enums (not supported)
- Unnamed CREATE INDEX (must provide name)
- DEFERRABLE on UNIQUE constraints (only for FK)
- Indexes on columns before DROP COLUMN (must drop first)
"""

import argparse
import re
from pathlib import Path
from typing import Tuple


def fix_migration(content: str) -> Tuple[str, dict]:
    """Apply all SQLite compatibility fixes to migration content.

    Returns: (fixed_content, stats_dict)
    """
    stats = {
        'alter_column_type': 0,
        'alter_column_not_null': 0,
        'multi_column_alter': 0,
        'drop_column_cascade': 0,
        'multi_column_drop': 0,
        'drop_column_if_exists': 0,
        'if_not_exists': 0,
        'alter_table_if_exists': 0,
        'drop_trigger': 0,
        'execute_procedure': 0,
        'gen_random_uuid': 0,
        'add_constraint': 0,
        'drop_constraint': 0,
        'incomplete_comments': 0,
        'comment_on': 0,
        'do_blocks': 0,
        'update_from': 0,
        'gin_indexes': 0,
        'alter_type': 0,
        'unnamed_index': 0,
        'deferrable_unique': 0,
        'drop_index_before_column': 0,
        'type_casts': 0,
        'now_function': 0,
        'trailing_comma_alter': 0,
        'create_function': 0,
        'drop_function': 0,
        'interval_syntax': 0,
    }

    # 1. Fix incomplete function comments
    lines = content.split('\n')
    new_lines = []
    in_function_comment = False
    trigger_depth = 0

    for line in lines:
        stripped = line.strip()

        # Track trigger depth
        if 'CREATE TRIGGER' in line:
            trigger_depth += 1
        elif stripped.startswith('END;') and trigger_depth > 0:
            trigger_depth -= 1

        # Track if we're in a function comment block
        if stripped.startswith('-- CREATE') and 'FUNCTION' in stripped:
            in_function_comment = True
        elif stripped and not stripped.startswith('--'):
            if trigger_depth == 0:
                in_function_comment = False

        # Fix uncommented function syntax ONLY if in function block AND NOT in trigger
        if in_function_comment and trigger_depth == 0:
            if (stripped.startswith(('RETURNS', 'BEGIN', 'END', 'IF', 'THEN',
                                    'ELSE', 'EXEC', 'NEW', 'OLD', 'END IF', 'RETURN'))
                and not stripped.startswith('--')):
                line = '-- ' + line
                stats['incomplete_comments'] += 1

        new_lines.append(line)

    content = '\n'.join(new_lines)

    # 2. Fix ALTER TABLE IF EXISTS
    pattern = re.compile(r'(ALTER\s+TABLE\s+)IF\s+EXISTS\s+', re.IGNORECASE | re.MULTILINE)
    content, count = pattern.subn(r'\1', content)
    stats['alter_table_if_exists'] += count

    # 3. Fix IF NOT EXISTS in ADD COLUMN
    pattern = re.compile(
        r'(ALTER\s+TABLE\s+\w+\s+ADD\s+COLUMN\s+)IF\s+NOT\s+EXISTS\s+',
        re.IGNORECASE | re.MULTILINE
    )
    content, count = pattern.subn(r'\1', content)
    stats['if_not_exists'] += count

    # 4. Fix DROP TRIGGER ON table_name
    pattern = re.compile(
        r'^(?!--)(.*)DROP\s+TRIGGER\s+IF\s+EXISTS\s+(\w+)\s+ON\s+(\w+);',
        re.IGNORECASE | re.MULTILINE
    )
    def drop_trigger_replacement(match):
        stats['drop_trigger'] += 1
        prefix = match.group(1)
        trigger_name = match.group(2)
        return f'{prefix}DROP TRIGGER IF EXISTS {trigger_name};'
    content = pattern.sub(drop_trigger_replacement, content)

    # 5. Fix EXECUTE PROCEDURE triggers
    pattern = re.compile(
        r'CREATE\s+TRIGGER\s+(\w+)\s+'
        r'(BEFORE|AFTER)\s+(UPDATE|INSERT|DELETE)\s+ON\s+(\w+)\s+'
        r'FOR\s+EACH\s+ROW\s+'
        r'EXECUTE\s+PROCEDURE\s+(\w+)\(\);',
        re.IGNORECASE | re.MULTILINE | re.DOTALL
    )
    def execute_procedure_replacement(match):
        stats['execute_procedure'] += 1
        trigger_name = match.group(1)
        timing = match.group(2).upper()
        event = match.group(3).upper()
        table_name = match.group(4)
        return f'''CREATE TRIGGER {trigger_name}
{timing} {event} ON {table_name}
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE {table_name} SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;'''
    content = pattern.sub(execute_procedure_replacement, content)

    # 6. Fix gen_random_uuid() defaults
    pattern = re.compile(
        r'(\s+\w+\s+\w+(?:\s+PRIMARY\s+KEY)?)\s+DEFAULT\s+gen_random_uuid\(\)',
        re.IGNORECASE
    )
    content, count = pattern.subn(r'\1', content)
    stats['gen_random_uuid'] += count

    # 7. Comment out ALTER COLUMN TYPE statements
    lines = content.split('\n')
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if 'ALTER COLUMN' in stripped.upper() and 'TYPE' in stripped.upper():
            if not stripped.startswith('--'):
                new_lines.append('-- ' + line + ' -- SQLite does not support ALTER COLUMN TYPE')
                stats['alter_column_type'] += 1
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)
    content = '\n'.join(new_lines)

    # 8. Split multi-column ALTER TABLE statements
    lines = content.split('\n')
    new_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if stripped.upper().startswith('ALTER TABLE'):
            table_match = re.match(r'ALTER\s+TABLE\s+(\w+)', stripped, re.IGNORECASE)
            if table_match:
                table_name = table_match.group(1)
                j = i + 1
                add_columns = []

                # Collect all ADD COLUMN lines
                while j < len(lines):
                    next_line = lines[j]
                    next_stripped = next_line.strip()

                    if not next_stripped or next_stripped.startswith('--'):
                        if next_stripped:
                            new_lines.append(next_line)
                        j += 1
                        continue

                    if 'ADD COLUMN' in next_stripped.upper():
                        clean_line = next_stripped
                        # Remove inline comment
                        if '--' in clean_line:
                            clean_line = clean_line.split('--')[0].strip()
                        # Remove trailing comma or semicolon
                        clean_line = clean_line.rstrip(',;').strip()
                        add_columns.append(clean_line)
                        j += 1

                        if next_stripped.rstrip().endswith(';'):
                            break
                    else:
                        break

                # Split into separate ALTER TABLE statements
                if len(add_columns) > 1:
                    for add_col in add_columns:
                        new_lines.append(f"ALTER TABLE {table_name} {add_col};")
                        stats['multi_column_alter'] += 1
                    i = j + 1
                    continue
                elif len(add_columns) == 1:
                    new_lines.append(f"ALTER TABLE {table_name} {add_columns[0]};")
                    i = j + 1
                    continue

        new_lines.append(line)
        i += 1

    content = '\n'.join(new_lines)

    # 9. Comment out ALTER TABLE ADD CONSTRAINT (for UNIQUE and FK)
    # This is more complex - we'll detect and comment out entire ADD CONSTRAINT blocks
    lines = content.split('\n')
    new_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Check for ADD CONSTRAINT
        if 'ADD CONSTRAINT' in stripped.upper() and not stripped.startswith('--'):
            # Comment out this line and any continuation
            new_lines.append('-- ' + line + ' -- SQLite: Use CREATE INDEX or application-level enforcement')
            stats['add_constraint'] += 1

            # Check if there are continuation lines (FOREIGN KEY, REFERENCES, etc.)
            j = i + 1
            while j < len(lines) and not lines[j].strip().endswith(';'):
                if lines[j].strip() and not lines[j].strip().startswith('--'):
                    new_lines.append('-- ' + lines[j])
                else:
                    new_lines.append(lines[j])
                j += 1
            # Add the final line with semicolon
            if j < len(lines) and lines[j].strip().endswith(';'):
                if not lines[j].strip().startswith('--'):
                    new_lines.append('-- ' + lines[j])
                else:
                    new_lines.append(lines[j])
                i = j + 1
            else:
                i = j
            continue

        new_lines.append(line)
        i += 1

    content = '\n'.join(new_lines)

    # 10. Fix ALTER COLUMN SET/DROP NOT NULL (defer to fix_nullable_columns.py)
    lines = content.split('\n')
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if ('ALTER COLUMN' in stripped.upper() and
            ('SET NOT NULL' in stripped.upper() or 'DROP NOT NULL' in stripped.upper())):
            if not stripped.startswith('--'):
                new_lines.append('-- ' + line + ' -- SQLite Note: Making column NOT NULL/nullable requires table recreation - defer to fix_nullable_columns.py')
                stats['alter_column_not_null'] += 1
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)
    content = '\n'.join(new_lines)

    # 11. Fix DROP COLUMN CASCADE
    pattern = re.compile(
        r'(ALTER\s+TABLE\s+\w+\s+DROP\s+COLUMN\s+\w+)\s+CASCADE',
        re.IGNORECASE
    )
    content, count = pattern.subn(r'\1', content)
    stats['drop_column_cascade'] += count

    # 12. Split multi-column DROP COLUMN statements
    lines = content.split('\n')
    new_lines = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Check for ALTER TABLE with multiple DROP COLUMN
        if 'ALTER TABLE' in stripped.upper() and 'DROP COLUMN' in stripped.upper():
            table_match = re.match(r'ALTER\s+TABLE\s+(\w+)', stripped, re.IGNORECASE)
            if table_match and ',' in stripped:
                table_name = table_match.group(1)
                # Extract column names
                drop_pattern = re.compile(r'DROP\s+COLUMN\s+(\w+)', re.IGNORECASE)
                columns = drop_pattern.findall(stripped)
                if len(columns) > 1:
                    for col in columns:
                        new_lines.append(f"ALTER TABLE {table_name} DROP COLUMN {col};")
                        stats['multi_column_drop'] += 1
                    i += 1
                    continue

        new_lines.append(line)
        i += 1
    content = '\n'.join(new_lines)

    # 13. Fix DROP COLUMN IF EXISTS
    pattern = re.compile(
        r'(ALTER\s+TABLE\s+\w+\s+DROP\s+COLUMN\s+)IF\s+EXISTS\s+',
        re.IGNORECASE
    )
    content, count = pattern.subn(r'\1', content)
    stats['drop_column_if_exists'] += count

    # 14. Fix DROP CONSTRAINT IF EXISTS
    pattern = re.compile(
        r'ALTER\s+TABLE\s+\w+\s+DROP\s+CONSTRAINT\s+IF\s+EXISTS\s+\w+;',
        re.IGNORECASE
    )
    def drop_constraint_replacement(match):
        stats['drop_constraint'] += 1
        return '-- ' + match.group(0) + ' -- SQLite Note: SQLite doesn\'t support DROP CONSTRAINT'
    content = pattern.sub(drop_constraint_replacement, content)

    # 15. Fix COMMENT ON statements
    lines = content.split('\n')
    new_lines = []
    in_comment_on = False
    for line in lines:
        stripped = line.strip()

        # Start of COMMENT ON block
        if stripped.upper().startswith('--') and 'COMMENT ON' in stripped.upper():
            in_comment_on = True
            new_lines.append(line)
            new_lines.append('-- SQLite Note: SQLite doesn\'t support COMMENT ON syntax, comments are stored as schema documentation')
            continue

        # Inside COMMENT ON block - ensure everything is commented
        if in_comment_on:
            if stripped.startswith("'") and stripped.endswith("';"):
                if not stripped.startswith('--'):
                    new_lines.append('-- ' + line)
                    stats['comment_on'] += 1
                else:
                    new_lines.append(line)
                in_comment_on = False
                continue

        new_lines.append(line)
    content = '\n'.join(new_lines)

    # 16. Fix DO $$ blocks
    lines = content.split('\n')
    new_lines = []
    in_do_block = False
    do_block_start = -1

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Start of DO block
        if stripped.upper().startswith('DO') and '$$' in stripped:
            in_do_block = True
            do_block_start = i
            new_lines.append('-- ' + line + ' -- SQLite Note: SQLite doesn\'t support DO blocks or information_schema for idempotent migrations')
            stats['do_blocks'] += 1
            continue

        # Inside DO block - comment everything
        if in_do_block:
            if '$$' in stripped and 'END' in stripped.upper():
                new_lines.append('-- ' + line)
                in_do_block = False
            elif not stripped.startswith('--'):
                new_lines.append('-- ' + line)
            else:
                new_lines.append(line)
            continue

        new_lines.append(line)
    content = '\n'.join(new_lines)

    # 17. Fix UPDATE...FROM syntax
    pattern = re.compile(
        r'UPDATE\s+(\w+)\s+SET\s+(\w+)\s*=\s*(\w+)\.(\w+)\s+FROM\s+(\w+)\s+WHERE',
        re.IGNORECASE | re.MULTILINE
    )
    def update_from_replacement(match):
        stats['update_from'] += 1
        target_table = match.group(1)
        set_column = match.group(2)
        source_table_alias = match.group(3)
        source_column = match.group(4)
        source_table = match.group(5)
        # Note: This is a simplified replacement, may need manual adjustment
        return f'''UPDATE {target_table}
SET {set_column} = (
    SELECT {source_column}
    FROM {source_table}
    WHERE'''
    content = pattern.sub(update_from_replacement, content)

    # 18. Fix GIN indexes (remove USING GIN)
    pattern = re.compile(
        r'(CREATE\s+INDEX\s+[^;]+?)\s+USING\s+GIN\s+',
        re.IGNORECASE | re.DOTALL
    )
    content, count = pattern.subn(r'\1 ', content)
    stats['gin_indexes'] += count

    # 19. Fix ALTER TYPE for enums
    lines = content.split('\n')
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if 'ALTER TYPE' in stripped.upper() and 'ADD VALUE' in stripped.upper():
            if not stripped.startswith('--'):
                new_lines.append('-- ' + line + ' -- SQLite Note: SQLite doesn\'t have enum types, uses TEXT CHECK constraints instead')
                stats['alter_type'] += 1
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)
    content = '\n'.join(new_lines)

    # 20. Fix unnamed CREATE INDEX (add name based on table and column)
    pattern = re.compile(
        r'CREATE\s+INDEX\s+ON\s+(\w+)\s*\((\w+)\)',
        re.IGNORECASE
    )
    def unnamed_index_replacement(match):
        stats['unnamed_index'] += 1
        table_name = match.group(1)
        column_name = match.group(2)
        index_name = f'idx_{table_name}_{column_name}'
        return f'CREATE INDEX {index_name} ON {table_name}({column_name})'
    content = pattern.sub(unnamed_index_replacement, content)

    # 21. Fix DEFERRABLE on UNIQUE constraints
    pattern = re.compile(
        r'(UNIQUE\s*\([^)]+\))\s+DEFERRABLE\s+INITIALLY\s+DEFERRED',
        re.IGNORECASE
    )
    content, count = pattern.subn(r'\1', content)
    stats['deferrable_unique'] += count

    # 22. Add DROP INDEX before DROP COLUMN warnings
    # This is detection only - manual intervention required
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if 'DROP COLUMN' in line.upper() and not line.strip().startswith('--'):
            # Check if there might be indexes on this column
            col_match = re.search(r'DROP\s+COLUMN\s+(\w+)', line, re.IGNORECASE)
            if col_match:
                column_name = col_match.group(1)
                # Look for indexes that might reference this column
                for j, prev_line in enumerate(lines[max(0, i-50):i]):
                    if 'CREATE INDEX' in prev_line.upper() and column_name in prev_line:
                        stats['drop_index_before_column'] += 1
                        break

    # 23. Fix PostgreSQL type casts (::TEXT, ::JSONB, etc)
    # SQLite doesn't use :: for casting
    pattern = re.compile(r'::(TEXT|JSONB|INTEGER|BOOLEAN|TIMESTAMP)', re.IGNORECASE)
    content, count = pattern.subn('', content)
    stats['type_casts'] += count

    # 24. Replace NOW() with CURRENT_TIMESTAMP
    # PostgreSQL's NOW() function doesn't exist in SQLite
    pattern = re.compile(r'\bNOW\(\)', re.IGNORECASE)
    content, count = pattern.subn('CURRENT_TIMESTAMP', content)
    stats['now_function'] += count

    # 25. Fix trailing comma in ALTER TABLE ADD COLUMN
    # SQLite doesn't allow trailing commas before semicolons in single-column ADD
    pattern = re.compile(
        r'(ALTER\s+TABLE\s+\w+\s+ADD\s+COLUMN\s+\w+\s+[^;,]+),\s*--',
        re.IGNORECASE
    )
    content, count = pattern.subn(r'\1; --', content)
    stats['trailing_comma_alter'] += count

    # 26. Comment out CREATE OR REPLACE FUNCTION statements
    # SQLite doesn't support PostgreSQL functions
    lines = content.split('\n')
    new_lines = []
    for line in lines:
        if 'CREATE OR REPLACE FUNCTION' in line.upper() and not line.strip().startswith('--'):
            new_lines.append('-- ' + line + ' -- SQLite Note: PostgreSQL functions not supported')
            stats['create_function'] += 1
        else:
            new_lines.append(line)
    content = '\n'.join(new_lines)

    # 27. Comment out DROP FUNCTION statements
    # If the CREATE was commented out, the DROP should be too
    lines = content.split('\n')
    new_lines = []
    for line in lines:
        if 'DROP FUNCTION' in line.upper() and not line.strip().startswith('--'):
            new_lines.append('-- ' + line + ' -- SQLite Note: Function was never created')
            stats['drop_function'] += 1
        else:
            new_lines.append(line)
    content = '\n'.join(new_lines)

    # 28. Fix PostgreSQL INTERVAL syntax to SQLite datetime() function
    # Convert: column + INTERVAL '365 days' -> datetime(column, '+365 days')
    # Convert: column - INTERVAL '30 days' -> datetime(column, '-30 days')
    pattern = re.compile(
        r'(\w+)\s*([+-])\s*INTERVAL\s+\'([+-]?\d+\s+\w+)\'',
        re.IGNORECASE
    )
    def interval_replacement(match):
        stats['interval_syntax'] += 1
        column = match.group(1)
        operator = match.group(2)
        interval = match.group(3)
        # Ensure the interval has the correct sign
        if not interval.startswith('+') and not interval.startswith('-'):
            interval = operator + interval
        return f'datetime({column}, \'{interval}\')'
    content = pattern.sub(interval_replacement, content)

    return content, stats


def process_migration_file(file_path: Path, dry_run: bool = False) -> dict:
    """Process a single migration file.

    Returns: stats dictionary
    """
    content = file_path.read_text()
    fixed_content, stats = fix_migration(content)

    total_fixes = sum(stats.values())

    if total_fixes > 0:
        print(f"  {file_path.parent.name}/up.sql: {total_fixes} fixes applied")
        for fix_type, count in stats.items():
            if count > 0:
                print(f"    - {fix_type}: {count}")

        if not dry_run:
            file_path.write_text(fixed_content)

    return stats


def main():
    parser = argparse.ArgumentParser(
        description='Comprehensive SQLite migration fixer - handles all PostgreSQL incompatibilities'
    )
    parser.add_argument('--migration-dir', type=str, default='migrations_sqlite',
                        help='Path to migrations directory')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would be fixed without making changes')

    args = parser.parse_args()

    migration_dir = Path(args.migration_dir)
    if not migration_dir.exists():
        print(f"Error: Migration directory '{migration_dir}' not found")
        return 1

    print(f"Processing migrations in {migration_dir}...")
    if args.dry_run:
        print("[DRY RUN] No changes will be made\n")

    total_stats = {
        'alter_column_type': 0,
        'alter_column_not_null': 0,
        'multi_column_alter': 0,
        'drop_column_cascade': 0,
        'multi_column_drop': 0,
        'drop_column_if_exists': 0,
        'if_not_exists': 0,
        'alter_table_if_exists': 0,
        'drop_trigger': 0,
        'execute_procedure': 0,
        'gen_random_uuid': 0,
        'add_constraint': 0,
        'drop_constraint': 0,
        'incomplete_comments': 0,
        'comment_on': 0,
        'do_blocks': 0,
        'update_from': 0,
        'gin_indexes': 0,
        'alter_type': 0,
        'unnamed_index': 0,
        'deferrable_unique': 0,
        'drop_index_before_column': 0,
        'type_casts': 0,
        'now_function': 0,
        'trailing_comma_alter': 0,
        'create_function': 0,
        'drop_function': 0,
        'interval_syntax': 0,
    }
    total_files = 0

    # Process all up.sql files
    for up_file in sorted(migration_dir.glob('*/up.sql')):
        stats = process_migration_file(up_file, args.dry_run)
        if sum(stats.values()) > 0:
            total_files += 1
            for key in total_stats:
                total_stats[key] += stats[key]

    print(f"\n✓ Processed {total_files} files")
    print("\nTotal fixes by type:")
    for fix_type, count in total_stats.items():
        if count > 0:
            print(f"  {fix_type}: {count}")
    print(f"\nGrand total: {sum(total_stats.values())} fixes")

    return 0


if __name__ == '__main__':
    exit(main())
