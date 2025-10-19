-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.499564
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add votes table if it doesn't exist
CREATE TABLE IF NOT EXISTS votes (
    chat_id TEXT NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
    message_id TEXT NOT NULL REFERENCES chat_messages(id) ON DELETE CASCADE,
    is_upvoted BOOLEAN NOT NULL,
    PRIMARY KEY (chat_id, message_id)
);

-- Add documents table
CREATE TABLE IF NOT EXISTS documents (
    id TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    title TEXT NOT NULL,
    content TEXT,
    kind VARCHAR NOT NULL DEFAULT 'text',
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (id, created_at)
);

-- Add suggestions table
CREATE TABLE IF NOT EXISTS suggestions (
    id TEXT NOT NULL PRIMARY KEY,
    document_id TEXT NOT NULL,
    document_created_at DATETIME NOT NULL,
    original_text TEXT NOT NULL,
    suggested_text TEXT NOT NULL,
    description TEXT,
    is_resolved BOOLEAN NOT NULL DEFAULT FALSE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (document_id, document_created_at) REFERENCES documents(id, created_at) ON DELETE CASCADE
);

-- Add some new columns to existing tables
ALTER TABLE chat_sessions ADD COLUMN IF NOT EXISTS visibility TEXT DEFAULT 'private';
ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS role TEXT;
ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS parts TEXT;
ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS attachments TEXT;
