ALTER TABLE chat_messages
DROP COLUMN IF EXISTS reasoning_content,
DROP COLUMN IF EXISTS reasoning_content_nonce;

ALTER TABLE message_variants
DROP COLUMN IF EXISTS reasoning_content,
DROP COLUMN IF EXISTS reasoning_content_nonce;
