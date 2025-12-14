-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.495877
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Drop old plaintext columns and add encrypted ones for chat sessions user data
-- SQLite requires separate ALTER TABLE statements for DROP and ADD operations
ALTER TABLE chat_sessions DROP COLUMN system_prompt;
ALTER TABLE chat_sessions DROP COLUMN title;
ALTER TABLE chat_sessions ADD COLUMN system_prompt_ciphertext BLOB;
ALTER TABLE chat_sessions ADD COLUMN system_prompt_nonce BLOB;
ALTER TABLE chat_sessions ADD COLUMN title_ciphertext BLOB;
ALTER TABLE chat_sessions ADD COLUMN title_nonce BLOB;
