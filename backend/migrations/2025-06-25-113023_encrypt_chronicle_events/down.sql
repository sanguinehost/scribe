-- Rollback encryption of chronicle event summaries

ALTER TABLE chronicle_events 
DROP COLUMN summary_encrypted,
DROP COLUMN summary_nonce;