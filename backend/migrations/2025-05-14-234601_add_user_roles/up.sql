-- Create the user_role enum type
CREATE TYPE user_role AS ENUM ('User', 'Moderator', 'Administrator');

-- Add role column to users table with 'User' as the default
ALTER TABLE users
ADD COLUMN role user_role NOT NULL DEFAULT 'User';