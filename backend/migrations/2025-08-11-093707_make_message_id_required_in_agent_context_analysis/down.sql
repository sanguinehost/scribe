-- Make message_id nullable again (reverting the change)
ALTER TABLE agent_context_analysis
ALTER COLUMN message_id DROP NOT NULL;