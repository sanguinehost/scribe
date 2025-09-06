-- Remove variant tracking metadata from chat_messages table
ALTER TABLE chat_messages DROP COLUMN IF EXISTS variant_count;
ALTER TABLE chat_messages DROP COLUMN IF EXISTS current_variant_index;

-- Remove the index
DROP INDEX IF EXISTS idx_message_variants_parent;
