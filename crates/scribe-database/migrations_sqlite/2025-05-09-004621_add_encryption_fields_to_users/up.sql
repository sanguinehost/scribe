-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.490303
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Your SQL goes here
ALTER TABLE users ADD COLUMN kek_salt TEXT NOT NULL;
ALTER TABLE users ADD COLUMN encrypted_dek BLOB NOT NULL;
ALTER TABLE users ADD COLUMN encrypted_dek_by_recovery BLOB NULL;
ALTER TABLE users ADD COLUMN recovery_kek_salt TEXT NULL;
