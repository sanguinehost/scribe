-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:00:19.543521
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Your SQL goes here
ALTER TABLE users
ADD COLUMN email VARCHAR NOT NULL UNIQUE;
