-- Remove account_status column from users table
ALTER TABLE users DROP COLUMN account_status;

-- Drop the account_status enum type
DROP TYPE account_status;