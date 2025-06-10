-- This file should undo the changes made in up.sql

-- Drop the email_verification_tokens table and its index
DROP TABLE IF EXISTS email_verification_tokens;

-- Revert the default account status on the users table
ALTER TABLE users ALTER COLUMN account_status SET DEFAULT 'active';

-- Note: Removing a value from an ENUM in PostgreSQL is not straightforward
-- and can be risky if data using that enum value exists.
-- The standard safe approach involves creating a new enum, migrating data,
-- dropping the old enum, and renaming the new one.
-- For the purpose of this migration's `down` script, we will assume that
-- no users are left in the 'pending' state before this is run.

-- 1. Alter the table to use TEXT temporarily
ALTER TABLE users ALTER COLUMN account_status TYPE TEXT;

-- 2. Drop the old enum
DROP TYPE account_status;

-- 3. Create the enum without 'pending'
CREATE TYPE account_status AS ENUM ('active', 'locked');

-- 4. Convert the column back to the new enum type, setting a default
ALTER TABLE users ALTER COLUMN account_status TYPE account_status USING account_status::account_status;
ALTER TABLE users ALTER COLUMN account_status SET DEFAULT 'active';
