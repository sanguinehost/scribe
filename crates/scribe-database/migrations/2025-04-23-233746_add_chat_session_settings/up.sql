-- Add columns for chat generation settings to the chat_sessions table

ALTER TABLE chat_sessions
    ADD COLUMN frequency_penalty NUMERIC NULL, -- Controls penalty for frequent tokens
    ADD COLUMN presence_penalty NUMERIC NULL,  -- Controls penalty for new tokens
    ADD COLUMN top_k INTEGER NULL,             -- Limits sampling to top K tokens
    ADD COLUMN top_p NUMERIC NULL,             -- Limits sampling via nucleus sampling
    ADD COLUMN repetition_penalty NUMERIC NULL, -- Penalizes repeating tokens
    ADD COLUMN min_p NUMERIC NULL,             -- Minimum probability for nucleus sampling
    ADD COLUMN top_a NUMERIC NULL,             -- Limits sampling via top-A sampling
    ADD COLUMN seed INTEGER NULL,              -- Seed for deterministic generation (-1 for random)
    ADD COLUMN logit_bias JSONB NULL;          -- JSON object for token biasing
