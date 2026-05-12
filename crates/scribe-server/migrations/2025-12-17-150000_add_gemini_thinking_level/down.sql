-- Remove gemini_thinking_level from chat_sessions and user_settings
ALTER TABLE chat_sessions DROP COLUMN gemini_thinking_level;
ALTER TABLE user_settings DROP COLUMN default_gemini_thinking_level;
