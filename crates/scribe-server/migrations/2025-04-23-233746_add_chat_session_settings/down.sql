-- Revert the changes from the corresponding up.sql file
-- Drop the columns added for chat generation settings

ALTER TABLE chat_sessions
    DROP COLUMN IF EXISTS frequency_penalty,
    DROP COLUMN IF EXISTS presence_penalty,
    DROP COLUMN IF EXISTS top_k,
    DROP COLUMN IF EXISTS top_p,
    DROP COLUMN IF EXISTS repetition_penalty,
    DROP COLUMN IF EXISTS min_p,
    DROP COLUMN IF EXISTS top_a,
    DROP COLUMN IF EXISTS seed,
    DROP COLUMN IF EXISTS logit_bias;
