-- Create message_variants table to store alternative responses for assistant messages
CREATE TABLE message_variants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_message_id UUID NOT NULL REFERENCES chat_messages(id) ON DELETE CASCADE,
    variant_index INTEGER NOT NULL, -- 0 = original, 1 = first variant, etc.
    content BYTEA NOT NULL, -- Encrypted content
    content_nonce BYTEA, -- Nonce for encryption
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Ensure unique variant indexes per parent message
    UNIQUE(parent_message_id, variant_index)
);

-- Index for performance when fetching variants for a message
CREATE INDEX idx_message_variants_parent_message_id ON message_variants(parent_message_id);

-- Index for ordering variants
CREATE INDEX idx_message_variants_parent_variant ON message_variants(parent_message_id, variant_index);

-- Trigger to auto-update the updated_at timestamp
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
