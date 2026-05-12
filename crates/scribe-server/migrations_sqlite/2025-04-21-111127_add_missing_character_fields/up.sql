-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.488932
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add missing columns to the characters table to match models/characters.rs
-- SQLite requires separate ALTER TABLE statements for each column

ALTER TABLE characters ADD COLUMN persona TEXT NULL;
ALTER TABLE characters ADD COLUMN world_scenario TEXT NULL;
ALTER TABLE characters ADD COLUMN avatar TEXT NULL;
ALTER TABLE characters ADD COLUMN chat TEXT NULL;
ALTER TABLE characters ADD COLUMN greeting TEXT NULL;
ALTER TABLE characters ADD COLUMN definition TEXT NULL;
ALTER TABLE characters ADD COLUMN default_voice TEXT NULL;
ALTER TABLE characters ADD COLUMN extensions TEXT NULL;
ALTER TABLE characters ADD COLUMN data_id INTEGER NULL;
-- alternate_greetings is already present in initial migration
ALTER TABLE characters ADD COLUMN category TEXT NULL;
ALTER TABLE characters ADD COLUMN definition_visibility TEXT NULL;
ALTER TABLE characters ADD COLUMN depth INTEGER NULL;
ALTER TABLE characters ADD COLUMN example_dialogue TEXT NULL;
ALTER TABLE characters ADD COLUMN favorite BOOLEAN NULL;
ALTER TABLE characters ADD COLUMN first_message_visibility TEXT NULL;
ALTER TABLE characters ADD COLUMN height NUMERIC NULL;
ALTER TABLE characters ADD COLUMN last_activity DATETIME NULL;
ALTER TABLE characters ADD COLUMN migrated_from TEXT NULL;
ALTER TABLE characters ADD COLUMN model_prompt TEXT NULL;
ALTER TABLE characters ADD COLUMN model_prompt_visibility TEXT NULL;
ALTER TABLE characters ADD COLUMN model_temperature NUMERIC NULL;
ALTER TABLE characters ADD COLUMN num_interactions INTEGER NULL;
ALTER TABLE characters ADD COLUMN permanence NUMERIC NULL;
ALTER TABLE characters ADD COLUMN persona_visibility TEXT NULL;
ALTER TABLE characters ADD COLUMN revision INTEGER NULL;
ALTER TABLE characters ADD COLUMN sharing_visibility TEXT NULL;
ALTER TABLE characters ADD COLUMN status TEXT NULL;
ALTER TABLE characters ADD COLUMN system_prompt_visibility TEXT NULL;
ALTER TABLE characters ADD COLUMN system_tags TEXT NULL;
ALTER TABLE characters ADD COLUMN token_budget INTEGER NULL;
ALTER TABLE characters ADD COLUMN usage_hints TEXT NULL;
ALTER TABLE characters ADD COLUMN user_persona TEXT NULL;
ALTER TABLE characters ADD COLUMN user_persona_visibility TEXT NULL;
ALTER TABLE characters ADD COLUMN visibility TEXT NULL;
ALTER TABLE characters ADD COLUMN weight NUMERIC NULL;
ALTER TABLE characters ADD COLUMN world_scenario_visibility TEXT NULL;
-- creator_notes_multilingual is already present in initial migration
