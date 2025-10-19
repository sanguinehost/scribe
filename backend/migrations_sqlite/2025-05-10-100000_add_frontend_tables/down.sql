-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.499880
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Drop added columns from chat_messages
ALTER TABLE chat_messages DROP COLUMN IF EXISTS attachments;
ALTER TABLE chat_messages DROP COLUMN IF EXISTS parts;
ALTER TABLE chat_messages DROP COLUMN IF EXISTS role;

-- Drop added columns from chat_sessions
ALTER TABLE chat_sessions DROP COLUMN IF EXISTS visibility;

-- Drop suggestions table
DROP TABLE IF EXISTS suggestions;

-- Drop documents table
DROP TABLE IF EXISTS documents;

-- Drop votes table
DROP TABLE IF EXISTS votes;
