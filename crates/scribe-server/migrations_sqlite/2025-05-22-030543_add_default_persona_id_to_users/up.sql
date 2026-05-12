-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.492745
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add default_persona_id column to users table
ALTER TABLE users ADD COLUMN default_persona_id TEXT;

-- SQLite doesn't support ALTER TABLE ADD CONSTRAINT for foreign keys
-- Foreign key relationship is documented here but enforced at application level
-- References: user_personas(id) ON DELETE SET NULL

-- Add index for performance
CREATE INDEX idx_users_default_persona_id ON users(default_persona_id);
