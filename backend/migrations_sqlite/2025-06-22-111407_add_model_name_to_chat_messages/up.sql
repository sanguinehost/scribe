-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.498175
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add model_name column to chat_messages table to track which model was used for each message
ALTER TABLE chat_messages ADD COLUMN model_name TEXT;

-- Set default model for existing messages (we'll use the session's model as a reasonable default)
-- SQLite Note: Using subquery instead of FROM clause
UPDATE chat_messages
SET model_name = (
    SELECT model_name
    FROM chat_sessions
    WHERE chat_sessions.id = chat_messages.session_id
)
WHERE model_name IS NULL;

-- Make the column NOT NULL after setting defaults
-- SQLite Note: Making model_name NOT NULL requires table recreation - defer to fix_nullable_columns.py
-- ALTER TABLE chat_messages ALTER COLUMN model_name SET NOT NULL;
