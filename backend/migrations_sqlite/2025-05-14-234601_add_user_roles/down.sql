-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:00:19.545001
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- This file undoes what's in `up.sql`

-- Drop the role column from users
ALTER TABLE users
DROP COLUMN IF EXISTS role;

-- Drop the TEXT enum type
DROP TYPE IF EXISTS TEXT;
