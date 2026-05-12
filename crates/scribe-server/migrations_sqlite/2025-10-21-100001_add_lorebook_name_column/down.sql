-- Rollback: Remove name column from lorebook_entries

-- SQLite limitation: Cannot drop columns in SQLite < 3.35.0
-- For down migration, would need to recreate table without this column
SELECT 'SQLite does not support DROP COLUMN. Manual migration required.' AS warning;

-- ALTER TABLE lorebook_entries DROP COLUMN name;
