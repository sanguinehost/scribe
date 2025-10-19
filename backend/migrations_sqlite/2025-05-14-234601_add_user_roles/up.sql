-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:00:19.544911
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Create the TEXT enum type
-- CREATE TYPE TEXT -- Removed: SQLite uses TEXT for enums

-- Add role column to users table with 'User' as the default
ALTER TABLE users
ADD COLUMN role TEXT NOT NULL DEFAULT 'User';
