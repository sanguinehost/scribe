-- This file should undo anything in `up.sql`
ALTER TABLE users
DROP COLUMN recovery_kek_salt,
DROP COLUMN encrypted_dek_by_recovery,
DROP COLUMN encrypted_dek,
DROP COLUMN kek_salt;
