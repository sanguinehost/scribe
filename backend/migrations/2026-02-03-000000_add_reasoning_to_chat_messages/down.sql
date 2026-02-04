ALTER TABLE chat_messages
DROP COLUMN IF EXISTS reasoning_content,
DROP COLUMN IF EXISTS reasoning_content_nonce;
