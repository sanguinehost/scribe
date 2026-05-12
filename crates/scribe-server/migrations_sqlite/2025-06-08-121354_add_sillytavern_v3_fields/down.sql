-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.502339
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

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
