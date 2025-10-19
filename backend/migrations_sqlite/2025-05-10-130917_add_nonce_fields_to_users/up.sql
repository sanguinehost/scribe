-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:00:19.544772
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Your SQL goes here
ALTER TABLE users
ADD COLUMN dek_nonce BLOB NOT NULL DEFAULT '\x',
ADD COLUMN recovery_dek_nonce BLOB;
