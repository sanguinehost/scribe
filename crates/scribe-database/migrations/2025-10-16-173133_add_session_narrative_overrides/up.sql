-- Add session-level narrative style override fields to chat_sessions
-- These allow temporary preference changes for individual conversations
-- Following the existing encryption pattern for session-specific user content
ALTER TABLE chat_sessions
ADD COLUMN narrative_style_override_ciphertext BYTEA,
ADD COLUMN narrative_style_override_nonce BYTEA;

-- Add index for sessions with overrides (for potential future analytics)
CREATE INDEX idx_chat_sessions_with_narrative_override
ON chat_sessions(id)
WHERE narrative_style_override_ciphertext IS NOT NULL;
