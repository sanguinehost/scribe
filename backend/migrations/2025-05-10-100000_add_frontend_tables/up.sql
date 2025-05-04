-- Add votes table if it doesn't exist
CREATE TABLE IF NOT EXISTS votes (
    chat_id UUID NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
    message_id UUID NOT NULL REFERENCES chat_messages(id) ON DELETE CASCADE,
    is_upvoted BOOLEAN NOT NULL,
    PRIMARY KEY (chat_id, message_id)
);

-- Add documents table
CREATE TABLE IF NOT EXISTS documents (
    id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    title TEXT NOT NULL,
    content TEXT,
    kind VARCHAR NOT NULL DEFAULT 'text',
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (id, created_at)
);

-- Add suggestions table
CREATE TABLE IF NOT EXISTS suggestions (
    id UUID NOT NULL PRIMARY KEY,
    document_id UUID NOT NULL,
    document_created_at TIMESTAMPTZ NOT NULL,
    original_text TEXT NOT NULL,
    suggested_text TEXT NOT NULL,
    description TEXT,
    is_resolved BOOLEAN NOT NULL DEFAULT FALSE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (document_id, document_created_at) REFERENCES documents(id, created_at) ON DELETE CASCADE
);

-- Add some new columns to existing tables
ALTER TABLE chat_sessions ADD COLUMN IF NOT EXISTS visibility VARCHAR(50) DEFAULT 'private';
ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS role VARCHAR(50);
ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS parts JSONB;
ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS attachments JSONB; 