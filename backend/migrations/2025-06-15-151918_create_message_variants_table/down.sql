-- Drop the message_variants table and related triggers/functions
DROP TRIGGER IF EXISTS update_message_variants_updated_at ON message_variants;
DROP FUNCTION IF EXISTS update_message_variants_updated_at();
DROP TABLE IF EXISTS message_variants;
