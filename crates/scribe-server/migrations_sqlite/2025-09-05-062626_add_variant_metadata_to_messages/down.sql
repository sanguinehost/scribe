-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.507658
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Remove variant tracking metadata from chat_messages table
ALTER TABLE chat_messages DROP COLUMN IF EXISTS variant_count;
ALTER TABLE chat_messages DROP COLUMN IF EXISTS current_variant_index;

-- Remove the index
DROP INDEX IF EXISTS idx_message_variants_parent;
