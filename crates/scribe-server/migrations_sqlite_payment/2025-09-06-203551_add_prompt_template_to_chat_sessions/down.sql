-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.507878
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Remove prompt_template_id column from chat_sessions (idempotent)
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'chat_sessions'
        AND column_name = 'prompt_template_id'
    ) THEN
        ALTER TABLE chat_sessions DROP COLUMN prompt_template_id;
    END IF;
END $$;
