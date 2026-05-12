-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-20T19:54:56.902371
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Revert webhook_events table
DROP TABLE IF EXISTS webhook_events;
