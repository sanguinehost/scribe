-- SQLite doesn't support DROP COLUMN easily without recreating the entire table
-- To avoid data loss during development, this is a no-op migration
-- If you need to rollback, you would need to:
-- 1. Create a new table without these columns
-- 2. Copy all data from the old table
-- 3. Drop the old table
-- 4. Rename the new table

-- For now, leaving as no-op to preserve data
