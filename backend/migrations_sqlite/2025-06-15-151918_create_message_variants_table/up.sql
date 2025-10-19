-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:00:19.550248
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Create message_variants table to store alternative responses for assistant messages
CREATE TABLE message_variants (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_message_id TEXT NOT NULL REFERENCES chat_messages(id) ON DELETE CASCADE,
    variant_index INTEGER NOT NULL, -- 0 = original, 1 = first variant, etc.
    content BLOB NOT NULL, -- Encrypted content
    content_nonce BLOB, -- Nonce for encryption
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Ensure unique variant indexes per parent message
    UNIQUE(parent_message_id, variant_index)
);

-- Index for performance when fetching variants for a message
CREATE INDEX idx_message_variants_parent_message_id ON message_variants(parent_message_id);

-- Index for ordering variants
CREATE INDEX idx_message_variants_parent_variant ON message_variants(parent_message_id, variant_index);

-- Trigger to auto-update the updated_at DATETIME
CREATE OR REPLACE FUNCTION update_message_variants_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_message_variants_updated_at
    BEFORE UPDATE ON message_variants
    FOR EACH ROW
    EXECUTE FUNCTION update_message_variants_updated_at();
