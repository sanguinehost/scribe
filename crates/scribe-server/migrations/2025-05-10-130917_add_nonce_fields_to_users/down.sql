-- This file should undo anything in `up.sql`

ALTER TABLE users
DROP COLUMN IF EXISTS dek_nonce,
DROP COLUMN IF EXISTS recovery_dek_nonce;
