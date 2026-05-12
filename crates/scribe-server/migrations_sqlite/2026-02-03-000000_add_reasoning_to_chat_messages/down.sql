ALTER TABLE chat_messages
DROP COLUMN reasoning_content;
ALTER TABLE chat_messages
DROP COLUMN reasoning_content_nonce;

ALTER TABLE message_variants
DROP COLUMN reasoning_content;
ALTER TABLE message_variants
DROP COLUMN reasoning_content_nonce;
