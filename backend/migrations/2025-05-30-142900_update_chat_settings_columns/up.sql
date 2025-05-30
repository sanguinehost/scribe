ALTER TABLE chat_sessions
ADD COLUMN IF NOT EXISTS repetition_penalty NUMERIC NULL,
ADD COLUMN IF NOT EXISTS min_p NUMERIC NULL,
ADD COLUMN IF NOT EXISTS top_a NUMERIC NULL,
ADD COLUMN IF NOT EXISTS logit_bias JSONB NULL;

-- Ensure stop_sequences is TEXT[] NULL if it wasn't already,
-- or if it was a different type.
ALTER TABLE chat_sessions
DROP COLUMN IF EXISTS stop_sequences; -- Drop first to avoid type conflicts if it exists with a different type

ALTER TABLE chat_sessions
ADD COLUMN stop_sequences TEXT[] NULL;