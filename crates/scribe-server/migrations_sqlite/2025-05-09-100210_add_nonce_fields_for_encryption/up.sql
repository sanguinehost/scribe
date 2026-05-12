-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.490718
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Your SQL goes here

-- Add nonce columns to the characters table
-- SQLite Type Affinity Note:
-- SQLite doesn't support ALTER COLUMN TYPE, but this is often not needed because:
-- 1. SQLite uses dynamic typing (type affinity)
-- 2. TEXT columns can store BLOB data and vice versa
-- 3. Type constraints are recommendations, not strict requirements


ALTER TABLE characters ADD COLUMN description_nonce BLOB NULL;
ALTER TABLE characters ADD COLUMN personality_nonce BLOB NULL;
ALTER TABLE characters ADD COLUMN scenario_nonce BLOB NULL;
ALTER TABLE characters ADD COLUMN first_mes_nonce BLOB NULL;
ALTER TABLE characters ADD COLUMN mes_example_nonce BLOB NULL;
ALTER TABLE characters ADD COLUMN creator_notes_nonce BLOB NULL;
ALTER TABLE characters ADD COLUMN system_prompt_nonce BLOB NULL;
ALTER TABLE characters ADD COLUMN persona_nonce BLOB NULL;
ALTER TABLE characters ADD COLUMN world_scenario_nonce BLOB NULL;
ALTER TABLE characters ADD COLUMN greeting_nonce BLOB NULL;
ALTER TABLE characters ADD COLUMN definition_nonce BLOB NULL;
ALTER TABLE characters ADD COLUMN example_dialogue_nonce BLOB NULL;
ALTER TABLE characters ADD COLUMN model_prompt_nonce BLOB NULL;
ALTER TABLE characters ADD COLUMN user_persona_nonce BLOB NULL;
ALTER TABLE characters ADD COLUMN post_history_instructions_nonce BLOB NULL;
-- Change ONLY the remaining TEXT fields (and post_history_instructions) to BLOB
-- Fields like description, personality, etc., are assumed to be handled by a previous migration.
-- SQLite does not support ALTER COLUMN TYPE - these fields remain as TEXT due to type affinity
-- The following PostgreSQL operations are not needed in SQLite:
-- ALTER TABLE characters
--     ALTER COLUMN creator_notes TYPE BLOB USING NULL,
--     ALTER COLUMN system_prompt TYPE BLOB USING NULL,
--     ALTER COLUMN persona TYPE BLOB USING NULL,
--     ALTER COLUMN world_scenario TYPE BLOB USING NULL,
--     ALTER COLUMN greeting TYPE BLOB USING NULL,
--     ALTER COLUMN definition TYPE BLOB USING NULL,
--     ALTER COLUMN example_dialogue TYPE BLOB USING NULL,
--     ALTER COLUMN model_prompt TYPE BLOB USING NULL,
--     ALTER COLUMN user_persona TYPE BLOB USING NULL,
--     ALTER COLUMN post_history_instructions TYPE BLOB USING NULL;

-- Add nonce column to the chat_messages table
-- content column is assumed to be BLOB from a previous migration.
ALTER TABLE chat_messages ADD COLUMN content_nonce BLOB NULL;
