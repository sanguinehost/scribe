ALTER TABLE chat_sessions
ADD COLUMN repetition_penalty NUMERIC,
ADD COLUMN min_p NUMERIC,
ADD COLUMN top_a NUMERIC,
ADD COLUMN logit_bias JSONB;

ALTER TABLE chat_sessions
DROP COLUMN IF EXISTS stop_sequences;