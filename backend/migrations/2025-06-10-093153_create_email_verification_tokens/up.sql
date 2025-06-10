-- Add 'pending' to the account_status enum
-- This is run in a separate transaction from the table creation below,
-- which is why this is safe.
ALTER TYPE account_status ADD VALUE 'pending';

-- Create the email_verification_tokens table
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Add an index on the user_id for quick lookups
CREATE INDEX ON email_verification_tokens (user_id);
