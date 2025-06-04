-- Remove raw prompt debugging fields

DROP INDEX IF EXISTS idx_chat_messages_raw_prompt_exists;

ALTER TABLE chat_messages 
DROP COLUMN IF EXISTS raw_prompt_ciphertext,
DROP COLUMN IF EXISTS raw_prompt_nonce;