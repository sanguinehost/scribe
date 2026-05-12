-- Remove session narrative style override fields
DROP INDEX IF EXISTS idx_chat_sessions_with_narrative_override;

ALTER TABLE chat_sessions
DROP COLUMN IF EXISTS narrative_style_override_ciphertext,
DROP COLUMN IF EXISTS narrative_style_override_nonce;
