-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:00:19.549011
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Your SQL goes here
ALTER TABLE chat_session_lorebooks
ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;
