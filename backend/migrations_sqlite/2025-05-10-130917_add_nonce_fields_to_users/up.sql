-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.491468
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Your SQL goes here
ALTER TABLE users ADD COLUMN dek_nonce BLOB NOT NULL DEFAULT '\x';
ALTER TABLE users ADD COLUMN recovery_dek_nonce BLOB;
