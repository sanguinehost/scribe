#!/bin/bash
# Fix unconverted PostgreSQL triggers in SQLite migrations

# Function to convert a trigger
fix_trigger() {
    local file="$1"
    local table_name="$2"

    # Remove the invalid trigger statement
    sed -i '/^CREATE TRIGGER.*EXECUTE FUNCTION/,/;$/d' "$file"

    # Add the correct SQLite trigger at the end of the file (before any comments at the very end)
    cat >> "$file" <<EOF

-- SQLite trigger for updating timestamps on $table_name
CREATE TRIGGER IF NOT EXISTS update_${table_name}_timestamp
AFTER UPDATE ON $table_name
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE $table_name SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
EOF
}

# Fix each migration
fix_trigger "backend/migrations_sqlite/2025-06-05-123407_create_chat_character_lorebook_overrides/up.sql" "chat_character_lorebook_overrides"
fix_trigger "backend/migrations_sqlite/2025-06-15-151918_create_message_variants_table/up.sql" "message_variants"
fix_trigger "backend/migrations_sqlite/2025-06-03-091600_create_character_lorebooks_table/up.sql" "character_lorebooks"
fix_trigger "backend/migrations_sqlite/2025-10-15-054608_add_template_preferences/up.sql" "template_preferences"
fix_trigger "backend/migrations_sqlite/2025-08-10-091221_add_agent_context_analysis/up.sql" "agent_context_analysis"
fix_trigger "backend/migrations_sqlite/2025-05-19-023621_create_chat_character_overrides/up.sql" "chat_character_overrides"
fix_trigger "backend/migrations_sqlite/2025-06-06-053628_create_user_settings_table/up.sql" "user_settings"

echo "Fixed 7 SQLite triggers"
