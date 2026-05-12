-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.505623
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Revert the foreign key constraint back to no CASCADE
-- This undoes the cascade deletion fix

-- Drop the constraint with CASCADE
ALTER TABLE agent_context_analysis
DROP CONSTRAINT IF EXISTS agent_context_analysis_assistant_message_id_fkey;

-- Re-add the original constraint without CASCADE
ALTER TABLE agent_context_analysis
ADD CONSTRAINT agent_context_analysis_assistant_message_id_fkey
FOREIGN KEY (assistant_message_id) REFERENCES chat_messages(id);
