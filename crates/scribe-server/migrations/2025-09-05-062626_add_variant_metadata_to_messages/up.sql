-- Add variant tracking metadata to chat_messages table
ALTER TABLE chat_messages ADD COLUMN variant_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE chat_messages ADD COLUMN current_variant_index INTEGER NOT NULL DEFAULT 0;

-- Add index for faster variant queries
CREATE INDEX IF NOT EXISTS idx_message_variants_parent ON message_variants(parent_message_id);

-- Migrate existing data: set variant_count for messages that have variants
UPDATE chat_messages
SET variant_count = (
    SELECT COUNT(*)
    FROM message_variants
    WHERE message_variants.parent_message_id = chat_messages.id
)
WHERE EXISTS (
    SELECT 1
    FROM message_variants
    WHERE message_variants.parent_message_id = chat_messages.id
);
