-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T10:57:37.955782
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NO... -- Removed: SQLite does not support PL/pgSQL

-- Your SQL goes here
CREATE TABLE sessions (
    id TEXT PRIMARY KEY NOT NULL,        -- Session ID provided by axum-session
    expires DATETIME,                 -- Expiry DATETIME (optional)
    session TEXT NOT NULL                -- Serialized session data
);

-- Optional: Index for faster session lookups
CREATE INDEX idx_sessions_id ON sessions (id);

-- Optional: Index for cleaning up expired sessions (if needed)
-- CREATE INDEX idx_sessions_expires ON sessions (expires);
