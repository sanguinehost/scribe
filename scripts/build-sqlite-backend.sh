#!/bin/bash
# SQLite Backend Build Script - ALL-IN-ONE
#
# This is the ONLY script you need to rebuild the SQLite backend from scratch.
# All fixes are embedded - no external Python scripts.
#
# Usage:
#   ./scripts/build-sqlite-backend.sh           # Full rebuild
#   ./scripts/build-sqlite-backend.sh --schema  # Only regenerate schema

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

DB_PATH="$PROJECT_ROOT/data/scribe.db"
SCHEMA_PATH="$PROJECT_ROOT/backend/src/schema.rs"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}SQLite Backend Build Script${NC}"
echo -e "${BLUE}========================================${NC}"
echo

# Parse arguments
SCHEMA_ONLY=false
if [ "$1" == "--schema" ]; then
    SCHEMA_ONLY=true
fi

# ============================================================================
# STEP 1: Run migrations (unless --schema flag)
# ============================================================================
if [ "$SCHEMA_ONLY" = false ]; then
    echo -e "${YELLOW}[1/5] Running migrations...${NC}"
    diesel migration run --database-url="sqlite://$DB_PATH"
    echo -e "${GREEN}✓ Migrations complete${NC}"
    echo
fi

# ============================================================================
# STEP 2: Generate schema.rs with diesel
# ============================================================================
echo -e "${YELLOW}[2/5] Generating schema.rs...${NC}"
diesel print-schema --database-url="sqlite://$DB_PATH" > "$SCHEMA_PATH"
echo -e "${GREEN}✓ Schema generated${NC}"
echo

# ============================================================================
# STEP 3: Fix schema.rs (inline sed replacements)
# ============================================================================
echo -e "${YELLOW}[3/5] Fixing schema.rs (nullable IDs, Float→Double)...${NC}"

# Fix nullable primary keys (Nullable<Text> → Text)
PRIMARY_KEY_FIXES=(
    "agent_context_analysis:id"
    "characters:id"
    "character_assets:id"
    "character_card_tags:id"
    "character_lorebook_associations:id"
    "character_tags:id"
    "chat_lorebook_associations:id"
    "chat_messages:id"
    "chat_sessions:id"
    "credit_transactions:id"
    "documents:id"
    "group_chats:id"
    "group_chat_participants:id"
    "inference_templates:id"
    "lorebook_categories:id"
    "lorebook_entries:id"
    "lorebooks:id"
    "plan_features:id"
    "subscriptions:id"
    "subscription_cancellation_flow_state:id"
    "template_preferences:id"
    "transactions:id"
    "user_assets:id"
    "user_credits:id"
    "user_personas:id"
    "user_settings:id"
    "users:id"
    "chronicles:id"
)

for entry in "${PRIMARY_KEY_FIXES[@]}"; do
    TABLE="${entry%%:*}"
    COLUMN="${entry##*:}"
    sed -i "/${TABLE} (${COLUMN})/,/}/ s/${COLUMN} -> Nullable<Text>/${COLUMN} -> Text/" "$SCHEMA_PATH"
done

# Fix Float → Double for decimal columns
DECIMAL_FIXES=(
    "chat_messages:actual_cost"
    "chat_messages:modified_cost"
    "chat_messages:actual_charge"
    "chat_sessions:total_actual_cost"
    "chat_sessions:total_modified_cost"
    "chat_sessions:total_actual_charge"
)

for entry in "${DECIMAL_FIXES[@]}"; do
    TABLE="${entry%%:*}"
    COLUMN="${entry##*:}"
    sed -i "/${TABLE}/,/}/ s/${COLUMN} -> Float/${COLUMN} -> Double/" "$SCHEMA_PATH"
done

echo -e "${GREEN}✓ Fixed $(echo ${#PRIMARY_KEY_FIXES[@]}) nullable primary keys${NC}"
echo -e "${GREEN}✓ Fixed $(echo ${#DECIMAL_FIXES[@]}) Float→Double columns${NC}"
echo

# ============================================================================
# STEP 4: Fix model files (Vec<u8> → DbBlob)
# ============================================================================
echo -e "${YELLOW}[4/5] Fixing model files (Vec<u8> → DbBlob)...${NC}"

MODEL_FILES=(
    "backend/src/models_sqlite/character_card.rs"
    "backend/src/models_sqlite/chats.rs"
    "backend/src/models_sqlite/character_assets.rs"
    "backend/src/models/characters.rs"
)

total_replacements=0

for file in "${MODEL_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        continue
    fi

    # Ensure DbBlob import exists
    if ! grep -q "use crate::db::DbBlob" "$file"; then
        # Add import after other db imports or after prelude
        if grep -q "use crate::db::" "$file"; then
            sed -i "/use crate::db::/a use crate::db::DbBlob;" "$file"
        elif grep -q "use diesel::prelude::" "$file"; then
            sed -i "/use diesel::prelude::/a use crate::db::DbBlob;" "$file"
        fi
    fi

    # Replace Option<Vec<u8>> → Option<DbBlob>
    count1=$(grep -c "pub.*: Option<Vec<u8>>" "$file" 2>/dev/null || true)
    sed -i -E 's/\bpub\s+([a-z_][a-z0-9_]*):\s*Option<Vec<u8>>/pub \1: Option<DbBlob>/g' "$file"

    # Replace Vec<u8> → DbBlob (not in Option)
    count2=$(grep -c "pub.*: Vec<u8>" "$file" 2>/dev/null || true)
    sed -i -E 's/\bpub\s+([a-z_][a-z0-9_]*):\s*Vec<u8>([^>]|$)/pub \1: DbBlob\2/g' "$file"

    file_total=$((count1 + count2))
    if [ $file_total -gt 0 ]; then
        echo -e "  ${file}: ${file_total} replacements"
        total_replacements=$((total_replacements + file_total))
    fi
done

echo -e "${GREEN}✓ Fixed ${total_replacements} Vec<u8> fields${NC}"
echo

# ============================================================================
# STEP 5: Fix Vec<u8> ↔ DbBlob conversions using compiler errors (iterative)
# ============================================================================
echo -e "${YELLOW}[5/5] Fixing Vec<u8> ↔ DbBlob type conversions...${NC}"

# Run fixes iteratively until no more conversions are made
MAX_ITERATIONS=10
iteration=0
while [ $iteration -lt $MAX_ITERATIONS ]; do
    iteration=$((iteration + 1))
    echo -e "  Iteration $iteration/$MAX_ITERATIONS..."

    # Use Python to parse cargo errors and apply precise fixes
    conversions=$(python3 - <<'PYTHON_SCRIPT'
import subprocess
import json
import re
from pathlib import Path

def get_type_errors():
    """Run cargo check with JSON output and extract type mismatch locations."""
    result = subprocess.run(
        ['cargo', 'check', '-p', 'scribe-backend', '--no-default-features',
         '--features', 'desktop', '--message-format=json'],
        capture_output=True,
        text=True,
        cwd='.'
    )

    errors = []
    for line in result.stdout.split('\n'):
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
            if msg.get('reason') == 'compiler-message':
                message = msg.get('message', {})
                if message.get('level') == 'error':
                    code_obj = message.get('code')
                    code = code_obj.get('code', '') if code_obj else ''

                    # Check children for type mismatch info
                    children_text = ' '.join(
                        child.get('message', '')
                        for child in message.get('children', [])
                    )
                    full_text = message.get('message', '') + ' ' + children_text

                    # Only process type mismatch errors involving Vec<u8> or DbBlob
                    if code in ['E0308', 'E0277'] and ('Vec<u8>' in full_text or 'DbBlob' in full_text):
                        spans = message.get('spans', [])
                        if spans:
                            span = spans[0]
                            errors.append({
                                'file': span['file_name'],
                                'line': span['line_start'],
                                'col': span['column_start'],
                                'text': full_text
                            })
        except json.JSONDecodeError:
            continue

    return errors

def fix_line(line: str, error_text: str) -> str:
    """Apply targeted fix based on error type."""

    # Detect direction of conversion needed
    vec_to_blob = 'expected' in error_text and 'DbBlob' in error_text and 'Vec<u8>' in error_text and error_text.index('DbBlob') < error_text.index('Vec<u8>')
    blob_to_vec = 'expected' in error_text and 'Vec<u8>' in error_text and 'DbBlob' in error_text and error_text.index('Vec<u8>') < error_text.index('DbBlob')

    if vec_to_blob:
        # Need to add .into() to convert Vec<u8> -> DbBlob

        # Fix: .to_vec() -> .to_vec().into()
        if '.to_vec()' in line and '.into()' not in line:
            line = re.sub(r'\.to_vec\(\)', r'.to_vec().into()', line)

        # Fix: .into_bytes() -> .into_bytes().into()
        elif '.into_bytes()' in line and '.into()' not in line:
            line = re.sub(r'\.into_bytes\(\)', r'.into_bytes().into()', line)

        # Fix: field = value; (direct assignment)
        elif '=' in line and ';' in line and '.into()' not in line and 'Some(' not in line:
            # Match assignment: var = simple_expr;
            line = re.sub(r'=\s*([a-z_][a-z0-9_]*)\s*;', r'= \1.into();', line)

        # Fix: field: var, (struct field assignment)
        elif ':' in line and ',' in line and '.into()' not in line and 'Some(' not in line:
            # Match field: simple_var,
            line = re.sub(r'(:\s*)([a-z_][a-z0-9_]*)(\s*,)', r'\1\2.into()\3', line)

        # Fix: Some(...) patterns
        elif 'Some(' in line and '.into()' not in line:
            # Fix: Some(expr.into_bytes())
            if '.into_bytes()' in line:
                line = re.sub(r'Some\(([^)]+\.into_bytes\(\))\)', r'Some(\1.into())', line)
            # Fix: Some(vec![...])
            elif 'vec![' in line:
                line = re.sub(r'Some\((vec!\[[^\]]*\])\)', r'Some(\1.into())', line)
            # Fix: Some(variable)
            else:
                line = re.sub(r'Some\(([a-z_][a-z0-9_]*)\)', r'Some(\1.into())', line)

        # Fix: vec![...] not in Some
        elif 'vec![' in line and '.into()' not in line:
            line = re.sub(r'(vec!\[[^\]]*\])([,\s;])', r'\1.into()\2', line)

    elif blob_to_vec:
        # Need to add .to_vec() to convert DbBlob -> Vec<u8>

        # Fix: variable as function arg or in expressions
        if '(' in line and ')' in line and '.to_vec()' not in line:
            # Fix: function(blob_var) -> function(blob_var.to_vec())
            line = re.sub(r'\(([a-z_][a-z0-9_]*)\)([,\s;])', r'(\1.to_vec())\2', line)

        # Fix: field.unwrap() -> field.unwrap().to_vec()
        elif '.unwrap()' in line and '.to_vec()' not in line:
            line = re.sub(r'\.unwrap\(\)', r'.unwrap().to_vec()', line)

        # Fix: Some(blob_var) -> Some(blob_var.to_vec())
        elif 'Some(' in line and '.to_vec()' not in line:
            line = re.sub(r'Some\(([a-z_][a-z0-9_]*)\)', r'Some(\1.to_vec())', line)

        # Fix: field.clone() -> field.clone().to_vec()
        elif '.clone()' in line and '.to_vec()' not in line:
            line = re.sub(r'\.clone\(\)', r'.clone().to_vec()', line)

    return line

def main():
    errors = get_type_errors()

    if not errors:
        print(0)
        return

    # Group errors by file
    files_to_fix = {}
    for error in errors:
        file = error['file']
        if file.startswith('backend/'):
            if file not in files_to_fix:
                files_to_fix[file] = []
            files_to_fix[file].append(error)

    fixed_count = 0
    for file_path, file_errors in files_to_fix.items():
        path = Path(file_path)
        if not path.exists():
            continue

        lines = path.read_text().splitlines(keepends=True)
        modified = False

        # Sort errors by line number descending so we can modify from bottom to top
        # (avoids line number shifts)
        for error in sorted(file_errors, key=lambda e: -e['line']):
            line_idx = error['line'] - 1
            if line_idx >= len(lines):
                continue

            original = lines[line_idx]
            fixed = fix_line(original, error['text'])

            if fixed != original:
                lines[line_idx] = fixed
                modified = True
                fixed_count += 1

        if modified:
            path.write_text(''.join(lines))

    print(fixed_count)

if __name__ == '__main__':
    main()
PYTHON_SCRIPT
)

    if [ "$conversions" = "0" ] || [ -z "$conversions" ]; then
        if [ $iteration = 1 ]; then
            echo -e "${GREEN}  ✓ No type conversions needed${NC}"
        else
            echo -e "${GREEN}  ✓ No more conversions to apply${NC}"
        fi
        break
    else
        echo -e "    Applied $conversions conversions"
    fi
done

if [ $iteration -eq $MAX_ITERATIONS ]; then
    echo -e "${YELLOW}  ⚠ Reached max iterations - some errors may remain${NC}"
fi


echo

# ============================================================================
# DONE
# ============================================================================
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}✓ SQLite backend build complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo
echo "Next steps:"
echo "  cargo check -p scribe-backend --no-default-features --features desktop"
echo "  ./scripts/build-desktop-dev.sh --run"
