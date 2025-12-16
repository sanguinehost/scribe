-- Add game_state to message_variants to store state snapshots per variant
ALTER TABLE message_variants ADD COLUMN game_state TEXT DEFAULT NULL;
