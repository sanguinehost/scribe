-- Your SQL goes here
ALTER TABLE users
ADD COLUMN kek_salt VARCHAR(128) NOT NULL,
ADD COLUMN encrypted_dek BYTEA NOT NULL,
ADD COLUMN encrypted_dek_by_recovery BYTEA NULL,
ADD COLUMN recovery_kek_salt TEXT NULL;