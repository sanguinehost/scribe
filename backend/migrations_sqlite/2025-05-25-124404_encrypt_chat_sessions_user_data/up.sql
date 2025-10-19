-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.495877
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Drop old plaintext columns and add encrypted ones for chat sessions user data
ALTER TABLE chat_sessions
DROP COLUMN system_prompt,
DROP COLUMN title,
ADD COLUMN system_prompt_ciphertext BLOB,
ADD COLUMN system_prompt_nonce BLOB,
ADD COLUMN title_ciphertext BLOB,
ADD COLUMN title_nonce BLOB;
