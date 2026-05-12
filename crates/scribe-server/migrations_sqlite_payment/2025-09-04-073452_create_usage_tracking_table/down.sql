-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.506786
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Drop usage_tracking table and all related indexes
DROP TABLE IF EXISTS usage_tracking;
