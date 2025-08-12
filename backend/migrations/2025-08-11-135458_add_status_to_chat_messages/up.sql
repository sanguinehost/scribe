-- Add status tracking fields to chat_messages table
ALTER TABLE chat_messages 
ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'completed',
ADD COLUMN error_message TEXT,
ADD COLUMN superseded_at TIMESTAMPTZ;

-- Add index for efficient querying of active messages
CREATE INDEX idx_chat_messages_status ON chat_messages(session_id, status) WHERE superseded_at IS NULL;