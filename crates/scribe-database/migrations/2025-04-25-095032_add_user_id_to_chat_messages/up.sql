-- Your SQL goes here

-- Add user_id column to chat_messages, making it non-nullable
ALTER TABLE chat_messages
ADD COLUMN user_id UUID NOT NULL;

-- Add a foreign key constraint to link user_id to the users table
ALTER TABLE chat_messages
ADD CONSTRAINT fk_chat_messages_user
FOREIGN KEY (user_id)
REFERENCES users(id)
ON DELETE CASCADE; -- Or ON DELETE SET NULL / RESTRICT depending on desired behavior

-- Optional: Add an index for performance if frequently querying by user_id
CREATE INDEX idx_chat_messages_user_id ON chat_messages(user_id);
