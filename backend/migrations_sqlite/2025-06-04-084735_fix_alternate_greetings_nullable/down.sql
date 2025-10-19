-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:00:19.549771
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Revert alternate_greetings column to be non-nullable
-- Note: This will fail if there are NULL values in the column
ALTER TABLE characters ALTER COLUMN alternate_greetings SET NOT NULL;
