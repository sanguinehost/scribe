-- Fix type inconsistencies in chat_sessions
ALTER TABLE chat_sessions ALTER COLUMN total_prompt_tokens TYPE BIGINT;
ALTER TABLE chat_sessions ALTER COLUMN total_completion_tokens TYPE BIGINT;
ALTER TABLE chat_sessions ALTER COLUMN game_state TYPE JSONB USING game_state::JSONB;

-- Fix type inconsistencies in chat_messages
ALTER TABLE chat_messages ALTER COLUMN prompt_tokens TYPE BIGINT;
ALTER TABLE chat_messages ALTER COLUMN completion_tokens TYPE BIGINT;

-- Fix type inconsistencies in message_variants
ALTER TABLE message_variants ALTER COLUMN game_state TYPE JSONB USING game_state::JSONB;
