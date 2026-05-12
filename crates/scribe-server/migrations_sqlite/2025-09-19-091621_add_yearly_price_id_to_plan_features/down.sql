-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-20T19:54:56.897185
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Remove yearly price ID column from plan_features table
ALTER TABLE plan_features
DROP COLUMN paddle_price_id_yearly;
