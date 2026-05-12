-- This file should undo anything in `up.sql`

-- Drop tables first, respecting foreign key constraints (reverse order of creation)
DROP TABLE IF EXISTS chat_messages;
DROP TABLE IF EXISTS chat_sessions;
DROP TABLE IF EXISTS lorebook_entries;
DROP TABLE IF EXISTS lorebooks;
DROP TABLE IF EXISTS character_assets;
DROP TABLE IF EXISTS characters;
DROP TABLE IF EXISTS users;

-- Drop the enum type after the tables that use it
DROP TYPE IF EXISTS message_type;

-- Drop helper functions
DROP FUNCTION IF EXISTS diesel_set_updated_at();
DROP FUNCTION IF EXISTS diesel_manage_updated_at(_tbl regclass);

-- Drop the extension if it's safe to do so (might be used by other things)
-- Consider commenting this out if unsure
-- DROP EXTENSION IF EXISTS "uuid-ossp";
