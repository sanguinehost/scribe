-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.502178
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add SillyTavern v3 fields to characters table
ALTER TABLE characters ADD COLUMN fav BOOLEAN;
ALTER TABLE characters ADD COLUMN world TEXT;
ALTER TABLE characters ADD COLUMN creator_comment BLOB;
ALTER TABLE characters ADD COLUMN creator_comment_nonce BLOB;
ALTER TABLE characters ADD COLUMN depth_prompt BLOB;
ALTER TABLE characters ADD COLUMN depth_prompt_depth INTEGER;
ALTER TABLE characters ADD COLUMN depth_prompt_role TEXT;
ALTER TABLE characters ADD COLUMN talkativeness NUMERIC;
ALTER TABLE characters ADD COLUMN depth_prompt_ciphertext BLOB;
ALTER TABLE characters ADD COLUMN depth_prompt_nonce BLOB;
ALTER TABLE characters ADD COLUMN world_ciphertext BLOB;
ALTER TABLE characters ADD COLUMN world_nonce BLOB;
