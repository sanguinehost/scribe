-- First, delete any orphaned analyses without message_id (these are invalid data)
DELETE FROM agent_context_analysis WHERE message_id IS NULL;

-- Now make message_id NOT NULL
ALTER TABLE agent_context_analysis
ALTER COLUMN message_id SET NOT NULL;