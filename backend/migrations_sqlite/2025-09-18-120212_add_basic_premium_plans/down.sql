-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-20T19:54:56.896522
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Remove basic and premium plan types
DELETE FROM plan_features WHERE plan_type IN ('basic', 'premium');
