-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:00:19.546126
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

ALTER TABLE users
DROP CONSTRAINT IF EXISTS fk_default_user_persona,
DROP COLUMN IF EXISTS default_persona_id;
