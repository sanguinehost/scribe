-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.488932
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add missing columns to the characters table to match models/characters.rs

ALTER TABLE characters
    ADD COLUMN persona TEXT NULL,
    ADD COLUMN world_scenario TEXT NULL,
    ADD COLUMN avatar TEXT NULL,
    ADD COLUMN chat TEXT NULL,
    ADD COLUMN greeting TEXT NULL,
    ADD COLUMN definition TEXT NULL,
    ADD COLUMN default_voice TEXT NULL,
    ADD COLUMN extensions TEXT NULL,
    ADD COLUMN data_id INTEGER NULL,
    -- alternate_greetings is already present in initial migration
    ADD COLUMN category TEXT NULL,
    ADD COLUMN definition_visibility TEXT NULL,
    ADD COLUMN depth INTEGER NULL,
    ADD COLUMN example_dialogue TEXT NULL,
    ADD COLUMN favorite BOOLEAN NULL,
    ADD COLUMN first_message_visibility TEXT NULL,
    ADD COLUMN height NUMERIC NULL,
    ADD COLUMN last_activity DATETIME NULL,
    ADD COLUMN migrated_from TEXT NULL,
    ADD COLUMN model_prompt TEXT NULL,
    ADD COLUMN model_prompt_visibility TEXT NULL,
    ADD COLUMN model_temperature NUMERIC NULL,
    ADD COLUMN num_interactions INTEGER NULL,
    ADD COLUMN permanence NUMERIC NULL,
    ADD COLUMN persona_visibility TEXT NULL,
    ADD COLUMN revision INTEGER NULL,
    ADD COLUMN sharing_visibility TEXT NULL,
    ADD COLUMN status TEXT NULL,
    ADD COLUMN system_prompt_visibility TEXT NULL,
    ADD COLUMN system_tags TEXT NULL,
    ADD COLUMN token_budget INTEGER NULL,
    ADD COLUMN usage_hints TEXT NULL,
    ADD COLUMN user_persona TEXT NULL,
    ADD COLUMN user_persona_visibility TEXT NULL,
    ADD COLUMN visibility TEXT NULL,
    ADD COLUMN weight NUMERIC NULL,
    ADD COLUMN world_scenario_visibility TEXT NULL;
    -- creator_notes_multilingual is already present in initial migration
