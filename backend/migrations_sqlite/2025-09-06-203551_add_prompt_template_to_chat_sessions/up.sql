-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.507744
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add prompt_template_id column to chat_sessions (idempotent)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'chat_sessions'
        AND column_name = 'prompt_template_id'
    ) THEN
        ALTER TABLE chat_sessions ADD COLUMN prompt_template_id TEXT DEFAULT 'neutral_roleplay';
        -- Make the column non-null after setting default
        ALTER TABLE chat_sessions ALTER COLUMN prompt_template_id SET NOT NULL;
    END IF;
END $$;
