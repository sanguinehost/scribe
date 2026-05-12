-- Add RAG limits to chat_sessions and user_settings
ALTER TABLE chat_sessions ADD COLUMN rag_chronicles_limit INTEGER DEFAULT NULL;
ALTER TABLE chat_sessions ADD COLUMN rag_lorebooks_limit INTEGER DEFAULT NULL;
ALTER TABLE chat_sessions ADD COLUMN rag_older_chat_limit INTEGER DEFAULT NULL;

ALTER TABLE user_settings ADD COLUMN default_rag_chronicles_limit INTEGER DEFAULT NULL;
ALTER TABLE user_settings ADD COLUMN default_rag_lorebooks_limit INTEGER DEFAULT NULL;
ALTER TABLE user_settings ADD COLUMN default_rag_older_chat_limit INTEGER DEFAULT NULL;
