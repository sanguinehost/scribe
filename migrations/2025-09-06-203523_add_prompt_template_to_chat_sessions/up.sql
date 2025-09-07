-- Add prompt_template_id column to chat_sessions
ALTER TABLE chat_sessions ADD COLUMN prompt_template_id VARCHAR(50) DEFAULT 'neutral_roleplay';

-- Make the column non-null after setting default
ALTER TABLE chat_sessions ALTER COLUMN prompt_template_id SET NOT NULL;