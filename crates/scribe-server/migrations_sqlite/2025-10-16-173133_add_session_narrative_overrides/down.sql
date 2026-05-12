-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.508845
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Remove session narrative style override fields
DROP INDEX IF EXISTS idx_chat_sessions_with_narrative_override;

ALTER TABLE chat_sessions
DROP COLUMN IF EXISTS narrative_style_override_ciphertext,
DROP COLUMN IF EXISTS narrative_style_override_nonce;
