-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.490185
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Your SQL goes here
-- SQLite limitation: ALTER TABLE ADD COLUMN cannot add UNIQUE or NOT NULL (without DEFAULT)
-- Add column as nullable, then create unique index separately
ALTER TABLE users ADD COLUMN email TEXT NULL;

-- Create unique index to enforce uniqueness (equivalent to UNIQUE constraint)
CREATE UNIQUE INDEX idx_users_email_unique ON users(email);
