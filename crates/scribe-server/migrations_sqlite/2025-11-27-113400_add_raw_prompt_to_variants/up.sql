-- Add raw_prompt_ciphertext and raw_prompt_nonce to message_variants table
-- These fields store the encrypted raw prompt that was sent to the AI when generating this variant

ALTER TABLE message_variants ADD COLUMN raw_prompt_ciphertext BLOB;
ALTER TABLE message_variants ADD COLUMN raw_prompt_nonce BLOB;
