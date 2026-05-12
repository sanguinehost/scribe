-- Remove RAG limits from chat_sessions and user_settings
ALTER TABLE chat_sessions DROP COLUMN rag_chronicles_limit;
ALTER TABLE chat_sessions DROP COLUMN rag_lorebooks_limit;
ALTER TABLE chat_sessions DROP COLUMN rag_older_chat_limit;

ALTER TABLE user_settings DROP COLUMN default_rag_chronicles_limit;
ALTER TABLE user_settings DROP COLUMN default_rag_older_chat_limit;
ALTER TABLE user_settings DROP COLUMN default_rag_lorebooks_limit;
