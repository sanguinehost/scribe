-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-20T19:54:56.901266
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Remove the unique constraint for active subscriptions per user

DROP INDEX idx_subscriptions_unique_active_user;
