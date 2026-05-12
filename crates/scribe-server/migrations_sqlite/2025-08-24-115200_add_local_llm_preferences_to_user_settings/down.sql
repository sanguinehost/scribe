-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.505914
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Rollback local LLM preferences from user_settings table

-- Remove the index first
DROP INDEX IF EXISTS idx_user_settings_preferred_local_model;

-- Remove the added columns in reverse order
ALTER TABLE user_settings DROP COLUMN IF EXISTS local_model_preferences;
ALTER TABLE user_settings DROP COLUMN IF EXISTS local_llm_enabled;
ALTER TABLE user_settings DROP COLUMN IF EXISTS preferred_local_model;
