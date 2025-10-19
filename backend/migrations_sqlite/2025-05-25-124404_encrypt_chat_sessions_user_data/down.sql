-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:00:19.549247
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Revert to plaintext columns (data will be lost)
ALTER TABLE chat_sessions
DROP COLUMN system_prompt_ciphertext,
DROP COLUMN system_prompt_nonce,
DROP COLUMN title_ciphertext,
DROP COLUMN title_nonce,
ADD COLUMN system_prompt TEXT,
ADD COLUMN title TEXT;
