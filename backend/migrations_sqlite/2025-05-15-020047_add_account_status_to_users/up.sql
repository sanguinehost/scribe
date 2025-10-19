-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.491770
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Create TEXT enum type
-- CREATE TYPE TEXT -- Removed: SQLite uses TEXT for enums

-- Add TEXT column to users table with default 'active'
ALTER TABLE users ADD COLUMN TEXT TEXT NOT NULL DEFAULT 'active';
