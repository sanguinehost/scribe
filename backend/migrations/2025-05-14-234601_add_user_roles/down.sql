-- This file undoes what's in `up.sql`

-- Drop the role column from users
ALTER TABLE users
DROP COLUMN IF EXISTS role;

-- Drop the user_role enum type
DROP TYPE IF EXISTS user_role;