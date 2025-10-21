-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-20T19:54:56.902661
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Rollback: Remove version column from user_credits table
-- This reverts the optimistic locking implementation

DROP INDEX IF EXISTS idx_user_credits_version;
ALTER TABLE user_credits DROP COLUMN version;
