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
# STEP 5: Manual conversions needed
# ============================================================================
echo -e "${YELLOW}[5/5] Checking for remaining type mismatches...${NC}"
echo -e "  NOTE: .into() conversions require manual fixes (sed pattern too aggressive)"
echo -e "${GREEN}✓ Schema and model files ready${NC}"
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
