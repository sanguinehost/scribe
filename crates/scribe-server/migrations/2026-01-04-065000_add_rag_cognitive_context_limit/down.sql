-- Remove rag_cognitive_context_limit column from chat_sessions table
ALTER TABLE chat_sessions DROP COLUMN rag_cognitive_context_limit;
