ALTER TABLE chat_messages
ADD COLUMN reasoning_content BLOB;
ALTER TABLE chat_messages
ADD COLUMN reasoning_content_nonce BLOB;

ALTER TABLE message_variants
ADD COLUMN reasoning_content BLOB;
ALTER TABLE message_variants
ADD COLUMN reasoning_content_nonce BLOB;
