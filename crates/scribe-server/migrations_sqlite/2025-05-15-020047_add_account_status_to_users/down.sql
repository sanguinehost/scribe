-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.491860
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Remove TEXT column from users table
ALTER TABLE users DROP COLUMN TEXT;

-- Drop the TEXT enum type
DROP TYPE TEXT;
