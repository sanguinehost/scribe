-- Drop old plaintext columns and add encrypted ones for chat sessions user data
ALTER TABLE chat_sessions 
DROP COLUMN system_prompt,
DROP COLUMN title,
ADD COLUMN system_prompt_ciphertext BYTEA,
ADD COLUMN system_prompt_nonce BYTEA,
ADD COLUMN title_ciphertext BYTEA,
ADD COLUMN title_nonce BYTEA;