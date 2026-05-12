-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.498487
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Rollback encryption of chronicle event summaries

ALTER TABLE chronicle_events
DROP COLUMN summary_encrypted,
DROP COLUMN summary_nonce;
