-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.502514
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- SQLite Note: SQLite doesn't have enum types, uses TEXT CHECK constraints instead
-- ALTER TYPE account_status ADD VALUE 'pending';

-- Create the email_verification_tokens table
CREATE TABLE email_verification_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Add an index on the user_id for quick lookups
CREATE INDEX idx_email_verification_tokens_user_id ON email_verification_tokens (user_id);
