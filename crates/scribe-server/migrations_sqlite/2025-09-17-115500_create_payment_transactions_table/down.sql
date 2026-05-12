-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-20T19:54:56.894372
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Drop payment transactions table and indexes
DROP TABLE IF EXISTS payment_transactions CASCADE;
