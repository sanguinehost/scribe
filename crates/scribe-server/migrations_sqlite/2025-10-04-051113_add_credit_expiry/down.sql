-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-20T19:54:56.902985
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Rollback credit expiry functionality
-- Removes expires_at column and associated indexes

DROP INDEX IF EXISTS idx_credit_transactions_user_expiry;
DROP INDEX IF EXISTS idx_credit_transactions_expires_at;

ALTER TABLE credit_transactions DROP COLUMN expires_at;
