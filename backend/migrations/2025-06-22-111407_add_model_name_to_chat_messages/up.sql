-- Add model_name column to chat_messages table to track which model was used for each message
ALTER TABLE chat_messages ADD COLUMN model_name VARCHAR(255);

-- Set default model for existing messages (we'll use the session's model as a reasonable default)
UPDATE chat_messages 
SET model_name = cs.model_name 
FROM chat_sessions cs 
WHERE chat_messages.session_id = cs.id 
AND chat_messages.model_name IS NULL;

-- Make the column NOT NULL after setting defaults
ALTER TABLE chat_messages ALTER COLUMN model_name SET NOT NULL;
