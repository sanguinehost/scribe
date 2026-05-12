-- Add SillyTavern v3 fields to characters table
ALTER TABLE characters ADD COLUMN fav BOOLEAN;
ALTER TABLE characters ADD COLUMN world TEXT;
ALTER TABLE characters ADD COLUMN creator_comment BYTEA;
ALTER TABLE characters ADD COLUMN creator_comment_nonce BYTEA;
ALTER TABLE characters ADD COLUMN depth_prompt BYTEA;
ALTER TABLE characters ADD COLUMN depth_prompt_depth INTEGER;
ALTER TABLE characters ADD COLUMN depth_prompt_role VARCHAR(255);
ALTER TABLE characters ADD COLUMN talkativeness NUMERIC;
ALTER TABLE characters ADD COLUMN depth_prompt_ciphertext BYTEA;
ALTER TABLE characters ADD COLUMN depth_prompt_nonce BYTEA;
ALTER TABLE characters ADD COLUMN world_ciphertext BYTEA;
ALTER TABLE characters ADD COLUMN world_nonce BYTEA;
