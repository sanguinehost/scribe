-- Rollback: Remove raw_prompt fields from message_variants table

ALTER TABLE message_variants DROP COLUMN raw_prompt_ciphertext;
ALTER TABLE message_variants DROP COLUMN raw_prompt_nonce;
