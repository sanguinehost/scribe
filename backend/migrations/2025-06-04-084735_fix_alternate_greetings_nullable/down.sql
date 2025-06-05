-- Revert alternate_greetings column to be non-nullable
-- Note: This will fail if there are NULL values in the column
ALTER TABLE characters ALTER COLUMN alternate_greetings SET NOT NULL;