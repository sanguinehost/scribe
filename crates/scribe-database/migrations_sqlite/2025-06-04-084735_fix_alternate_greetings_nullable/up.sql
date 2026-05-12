-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.496431
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Fix alternate_greetings column to be nullable to match Rust model
-- SQLite Note: Column is already nullable in the SQLite schema, no action needed
-- ALTER TABLE characters ALTER COLUMN alternate_greetings DROP NOT NULL;
