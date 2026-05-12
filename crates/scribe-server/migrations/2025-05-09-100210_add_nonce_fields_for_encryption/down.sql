-- This file should undo anything in `up.sql`

-- Remove nonce columns from the characters table
ALTER TABLE characters
    DROP COLUMN IF EXISTS description_nonce,
    DROP COLUMN IF EXISTS personality_nonce,
    DROP COLUMN IF EXISTS scenario_nonce,
    DROP COLUMN IF EXISTS first_mes_nonce,
    DROP COLUMN IF EXISTS mes_example_nonce,
    DROP COLUMN IF EXISTS creator_notes_nonce,
    DROP COLUMN IF EXISTS system_prompt_nonce,
    DROP COLUMN IF EXISTS persona_nonce,
    DROP COLUMN IF EXISTS world_scenario_nonce,
    DROP COLUMN IF EXISTS greeting_nonce,
    DROP COLUMN IF EXISTS definition_nonce,
    DROP COLUMN IF EXISTS example_dialogue_nonce,
    DROP COLUMN IF EXISTS model_prompt_nonce,
    DROP COLUMN IF EXISTS user_persona_nonce,
    DROP COLUMN IF EXISTS post_history_instructions_nonce;

-- Change relevant BYTEA fields back to TEXT for characters table
-- Note: This is potentially lossy if BYTEA data is not valid UTF-8
-- Fields like description, personality, etc., are assumed to be handled by a later migration's down.sql.
ALTER TABLE characters
    ALTER COLUMN creator_notes TYPE TEXT USING NULL,
    ALTER COLUMN system_prompt TYPE TEXT USING NULL,
    ALTER COLUMN persona TYPE TEXT USING NULL,
    ALTER COLUMN world_scenario TYPE TEXT USING NULL,
    ALTER COLUMN greeting TYPE TEXT USING NULL,
    ALTER COLUMN definition TYPE TEXT USING NULL,
    ALTER COLUMN example_dialogue TYPE TEXT USING NULL,
    ALTER COLUMN model_prompt TYPE TEXT USING NULL,
    ALTER COLUMN user_persona TYPE TEXT USING NULL,
    ALTER COLUMN post_history_instructions TYPE TEXT USING NULL;

-- Remove nonce column from the chat_messages table
ALTER TABLE chat_messages
    DROP COLUMN IF EXISTS content_nonce;
