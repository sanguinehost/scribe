-- Encrypt chronicle event summaries to comply with encryption-at-rest architecture

-- Add encrypted summary fields
ALTER TABLE chronicle_events 
ADD COLUMN summary_encrypted BYTEA,
ADD COLUMN summary_nonce BYTEA;

-- Note: The existing 'summary' column will be kept temporarily for data migration
-- We will populate the encrypted fields in a follow-up data migration script
-- then drop the old column in a subsequent migration