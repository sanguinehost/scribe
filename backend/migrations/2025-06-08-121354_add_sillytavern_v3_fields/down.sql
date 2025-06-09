-- Drop the SillyTavern v3 fields (in reverse order of creation)
ALTER TABLE characters DROP COLUMN IF EXISTS world_nonce;
ALTER TABLE characters DROP COLUMN IF EXISTS world_ciphertext;
ALTER TABLE characters DROP COLUMN IF EXISTS depth_prompt_nonce;
ALTER TABLE characters DROP COLUMN IF EXISTS depth_prompt_ciphertext;
ALTER TABLE characters DROP COLUMN IF EXISTS talkativeness;
ALTER TABLE characters DROP COLUMN IF EXISTS depth_prompt_role;
ALTER TABLE characters DROP COLUMN IF EXISTS depth_prompt_depth;
ALTER TABLE characters DROP COLUMN IF EXISTS depth_prompt;
ALTER TABLE characters DROP COLUMN IF EXISTS creator_comment_nonce;
ALTER TABLE characters DROP COLUMN IF EXISTS creator_comment;
ALTER TABLE characters DROP COLUMN IF EXISTS world;
ALTER TABLE characters DROP COLUMN IF EXISTS fav;
