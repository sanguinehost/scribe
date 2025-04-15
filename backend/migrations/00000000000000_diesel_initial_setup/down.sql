-- This file was automatically created by Diesel to setup helper functions
-- and other internal bookkeeping. This file is safe to edit, any future
-- changes will be added to existing projects as new migrations.

-- Drop tables in reverse order of creation due to foreign keys
DROP TABLE IF EXISTS chat_messages;
DROP TABLE IF EXISTS chat_sessions;
DROP TABLE IF EXISTS lorebook_entries;
DROP TABLE IF EXISTS lorebooks;
DROP TABLE IF EXISTS character_assets;
DROP TABLE IF EXISTS characters;
DROP TABLE IF EXISTS users;

-- Drop helper functions and types
DROP FUNCTION IF EXISTS diesel_set_updated_at();
DROP FUNCTION IF EXISTS diesel_manage_updated_at(_tbl regclass);
DROP TYPE IF EXISTS message_type;

-- Optionally drop the extension if it's not needed by other parts of the DB
-- DROP EXTENSION IF EXISTS "uuid-ossp";
