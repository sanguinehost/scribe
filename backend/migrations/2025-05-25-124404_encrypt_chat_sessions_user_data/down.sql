-- Revert to plaintext columns (data will be lost)
ALTER TABLE chat_sessions 
DROP COLUMN system_prompt_ciphertext,
DROP COLUMN system_prompt_nonce,
DROP COLUMN title_ciphertext,
DROP COLUMN title_nonce,
ADD COLUMN system_prompt TEXT,
ADD COLUMN title VARCHAR(255);