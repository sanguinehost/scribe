ALTER TABLE chat_messages
ADD COLUMN prompt_tokens INTEGER,
ADD COLUMN completion_tokens INTEGER;
