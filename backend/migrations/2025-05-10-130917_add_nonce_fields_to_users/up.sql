-- Your SQL goes here
ALTER TABLE users
ADD COLUMN dek_nonce BYTEA NOT NULL DEFAULT '\x',
ADD COLUMN recovery_dek_nonce BYTEA;
