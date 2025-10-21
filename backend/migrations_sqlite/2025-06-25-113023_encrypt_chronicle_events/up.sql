-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.498370
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Encrypt chronicle event summaries to comply with encryption-at-rest architecture

-- Add encrypted summary fields
ALTER TABLE chronicle_events ADD COLUMN summary_encrypted BLOB;
ALTER TABLE chronicle_events ADD COLUMN summary_nonce BLOB;
-- Note: The existing 'summary' column will be kept temporarily for data migration
-- We will populate the encrypted fields in a follow-up data migration script
-- then drop the old column in a subsequent migration
