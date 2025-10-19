-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.502083
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Drop the new table and its dependencies
DROP TABLE IF EXISTS user_assets;

-- Remove the added fields from character_assets
ALTER TABLE character_assets DROP COLUMN IF EXISTS data;
ALTER TABLE character_assets DROP COLUMN IF EXISTS content_type;
ALTER TABLE character_assets ALTER COLUMN uri SET NOT NULL;
