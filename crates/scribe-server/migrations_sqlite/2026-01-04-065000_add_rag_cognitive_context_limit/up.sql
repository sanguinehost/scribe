-- Add rag_cognitive_context_limit column to chat_sessions table
ALTER TABLE chat_sessions ADD COLUMN rag_cognitive_context_limit INTEGER DEFAULT NULL;
