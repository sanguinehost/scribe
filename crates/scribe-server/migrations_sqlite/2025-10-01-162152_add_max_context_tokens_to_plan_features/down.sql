-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-20T19:54:56.901505
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Remove max_context_tokens column from plan_features table

ALTER TABLE plan_features DROP COLUMN max_context_tokens;
