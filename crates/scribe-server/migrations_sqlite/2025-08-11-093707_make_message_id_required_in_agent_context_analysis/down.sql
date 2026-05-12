-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.504382
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Make message_id nullable again (reverting the change)
ALTER TABLE agent_context_analysis
ALTER COLUMN message_id DROP NOT NULL;
