-- Revert renaming columns in user_settings
ALTER TABLE user_settings RENAME COLUMN default_thinking_budget TO default_gemini_thinking_budget;
ALTER TABLE user_settings RENAME COLUMN default_thinking_level TO default_gemini_thinking_level;
ALTER TABLE user_settings RENAME COLUMN default_enable_code_execution TO default_gemini_enable_code_execution;

-- Revert renaming columns in chat_sessions
ALTER TABLE chat_sessions RENAME COLUMN thinking_budget TO gemini_thinking_budget;
ALTER TABLE chat_sessions RENAME COLUMN thinking_level TO gemini_thinking_level;
ALTER TABLE chat_sessions RENAME COLUMN enable_code_execution TO gemini_enable_code_execution;
