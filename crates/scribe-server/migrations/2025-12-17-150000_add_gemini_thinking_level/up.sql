-- Add gemini_thinking_level to chat_sessions and user_settings
ALTER TABLE chat_sessions ADD COLUMN gemini_thinking_level TEXT DEFAULT NULL;
ALTER TABLE user_settings ADD COLUMN default_gemini_thinking_level TEXT DEFAULT NULL;
