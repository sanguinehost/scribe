-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.497294
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Drop the message_variants table and related triggers/functions
DROP TRIGGER IF EXISTS update_message_variants_updated_at ON message_variants;
DROP FUNCTION IF EXISTS update_message_variants_updated_at();
DROP TABLE IF EXISTS message_variants;
