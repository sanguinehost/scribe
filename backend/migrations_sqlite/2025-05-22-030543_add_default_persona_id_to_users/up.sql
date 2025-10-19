-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:00:19.546049
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

ALTER TABLE users
ADD COLUMN default_persona_id TEXT,
ADD CONSTRAINT fk_default_user_persona
    FOREIGN KEY (default_persona_id)
    REFERENCES user_personas (id)
    ON DELETE SET NULL;
