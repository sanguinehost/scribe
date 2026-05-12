-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.491770
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Create account_status enum type
-- CREATE TYPE account_status AS ENUM ('active', 'locked'); -- Removed: SQLite uses TEXT for enums

-- Add account_status column to users table with default 'active'
ALTER TABLE users ADD COLUMN account_status TEXT NOT NULL DEFAULT 'active';
