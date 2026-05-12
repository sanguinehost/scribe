-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.490381
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- This file should undo anything in `up.sql`
ALTER TABLE users
DROP COLUMN recovery_kek_salt,
DROP COLUMN encrypted_dek_by_recovery,
DROP COLUMN encrypted_dek,
DROP COLUMN kek_salt;
