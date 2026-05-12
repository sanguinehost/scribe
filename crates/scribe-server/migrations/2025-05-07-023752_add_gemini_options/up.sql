-- Your SQL goes here

-- Add Gemini-specific fields to chat_sessions
ALTER TABLE chat_sessions
ADD COLUMN gemini_thinking_budget INTEGER,
ADD COLUMN gemini_enable_code_execution BOOLEAN;
