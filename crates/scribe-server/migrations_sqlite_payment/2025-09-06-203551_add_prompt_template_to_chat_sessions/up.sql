-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.507744
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add prompt_template_id column to chat_sessions
-- SQLite Note: SQLite doesn't support DO blocks or information_schema for idempotent migrations
-- If column already exists, this migration will fail (migrations should run in order)
ALTER TABLE chat_sessions ADD COLUMN prompt_template_id TEXT DEFAULT 'neutral_roleplay';

-- Make the column non-null after setting default
-- SQLite Note: Making prompt_template_id NOT NULL requires table recreation - defer to fix_nullable_columns.py
-- ALTER TABLE chat_sessions ALTER COLUMN prompt_template_id SET NOT NULL;
