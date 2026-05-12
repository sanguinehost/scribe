ALTER TABLE chat_messages
ADD COLUMN reasoning_content BYTEA,
ADD COLUMN reasoning_content_nonce BYTEA;

ALTER TABLE message_variants
ADD COLUMN reasoning_content BYTEA,
ADD COLUMN reasoning_content_nonce BYTEA;
