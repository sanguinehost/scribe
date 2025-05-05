-- Your SQL goes here

-- Add model_name column to chat_sessions table
ALTER TABLE chat_sessions
ADD COLUMN model_name VARCHAR(100) NOT NULL DEFAULT 'gemini-2.5-pro-preview-03-25';
