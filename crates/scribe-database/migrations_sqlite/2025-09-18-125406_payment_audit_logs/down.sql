-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-20T19:54:56.896982
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Drop payment audit logs table
DROP TABLE IF EXISTS payment_audit_logs;
