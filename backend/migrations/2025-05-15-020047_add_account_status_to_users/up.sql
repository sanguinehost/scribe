-- Create account_status enum type
CREATE TYPE account_status AS ENUM ('active', 'locked');

-- Add account_status column to users table with default 'active'
ALTER TABLE users ADD COLUMN account_status account_status NOT NULL DEFAULT 'active';