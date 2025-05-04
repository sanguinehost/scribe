-- Drop added columns from chat_messages
ALTER TABLE IF EXISTS chat_messages DROP COLUMN IF EXISTS attachments;
ALTER TABLE IF EXISTS chat_messages DROP COLUMN IF EXISTS parts;
ALTER TABLE IF EXISTS chat_messages DROP COLUMN IF EXISTS role;

-- Drop added columns from chat_sessions
ALTER TABLE IF EXISTS chat_sessions DROP COLUMN IF EXISTS visibility; 