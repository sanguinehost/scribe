-- Your SQL goes here

-- Add nonce columns to the characters table
ALTER TABLE characters
    ADD COLUMN description_nonce BYTEA NULL,
    ADD COLUMN personality_nonce BYTEA NULL,
    ADD COLUMN scenario_nonce BYTEA NULL,
    ADD COLUMN first_mes_nonce BYTEA NULL,
    ADD COLUMN mes_example_nonce BYTEA NULL,
    ADD COLUMN creator_notes_nonce BYTEA NULL,
    ADD COLUMN system_prompt_nonce BYTEA NULL,
    ADD COLUMN persona_nonce BYTEA NULL,
    ADD COLUMN world_scenario_nonce BYTEA NULL,
    ADD COLUMN greeting_nonce BYTEA NULL,
    ADD COLUMN definition_nonce BYTEA NULL,
    ADD COLUMN example_dialogue_nonce BYTEA NULL,
    ADD COLUMN model_prompt_nonce BYTEA NULL,
    ADD COLUMN user_persona_nonce BYTEA NULL,
    ADD COLUMN post_history_instructions_nonce BYTEA NULL;

-- Change ONLY the remaining TEXT fields (and post_history_instructions) to BYTEA
-- Fields like description, personality, etc., are assumed to be handled by a previous migration.
ALTER TABLE characters
    ALTER COLUMN creator_notes TYPE BYTEA USING NULL, -- Data loss if not handled, assuming new/empty or manual conversion
    ALTER COLUMN system_prompt TYPE BYTEA USING NULL,
    ALTER COLUMN persona TYPE BYTEA USING NULL,
    ALTER COLUMN world_scenario TYPE BYTEA USING NULL,
    ALTER COLUMN greeting TYPE BYTEA USING NULL,
    ALTER COLUMN definition TYPE BYTEA USING NULL,
    ALTER COLUMN example_dialogue TYPE BYTEA USING NULL,
    ALTER COLUMN model_prompt TYPE BYTEA USING NULL,
    ALTER COLUMN user_persona TYPE BYTEA USING NULL,
    ALTER COLUMN post_history_instructions TYPE BYTEA USING NULL;

-- Add nonce column to the chat_messages table
-- content column is assumed to be BYTEA from a previous migration.
ALTER TABLE chat_messages
    ADD COLUMN content_nonce BYTEA NULL;
