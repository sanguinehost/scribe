-- Rename columns in chat_sessions
ALTER TABLE chat_sessions RENAME COLUMN gemini_thinking_budget TO thinking_budget;
ALTER TABLE chat_sessions RENAME COLUMN gemini_thinking_level TO thinking_level;
ALTER TABLE chat_sessions RENAME COLUMN gemini_enable_code_execution TO enable_code_execution;

-- Rename columns in user_settings
ALTER TABLE user_settings RENAME COLUMN default_gemini_thinking_budget TO default_thinking_budget;
ALTER TABLE user_settings RENAME COLUMN default_gemini_thinking_level TO default_thinking_level;
ALTER TABLE user_settings RENAME COLUMN default_gemini_enable_code_execution TO default_enable_code_execution;
