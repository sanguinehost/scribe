-- Fix alternate_greetings column to be nullable to match Rust model
ALTER TABLE characters ALTER COLUMN alternate_greetings DROP NOT NULL;