-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.491533
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- This file should undo anything in `up.sql`

ALTER TABLE users
DROP COLUMN IF EXISTS dek_nonce,
DROP COLUMN IF EXISTS recovery_dek_nonce;
