-- Remove rag_cognitive_context_limit column from chat_sessions table
-- Note: SQLite does not support DROP COLUMN directly in older versions
-- This is a best-effort down migration for SQLite 3.35.0+
ALTER TABLE chat_sessions DROP COLUMN rag_cognitive_context_limit;
