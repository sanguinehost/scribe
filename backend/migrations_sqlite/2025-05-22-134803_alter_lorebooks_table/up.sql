-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql - Major schema change for lorebooks table
--
-- IMPORTANT: SQLite doesn't support complex ALTER TABLE operations
-- This migration uses the table recreation pattern:
-- 1. Create new table with desired schema
-- 2. Copy compatible data
-- 3. Drop old table
-- 4. Rename new table
-- ================================================================

-- Create new lorebooks table with updated schema
CREATE TABLE lorebooks_new (
    id TEXT PRIMARY KEY,  -- Changed from INTEGER to TEXT (UUID)
    user_id TEXT NOT NULL,  -- NEW: Owner of the lorebook (FK to users, enforced at app level)
    name TEXT NOT NULL,  -- Changed from nullable to NOT NULL
    description TEXT,  -- Remains nullable
    source_format TEXT NOT NULL,  -- NEW: Format of imported lorebook
    is_public BOOLEAN NOT NULL DEFAULT false,  -- NEW: Visibility flag
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create index for user_id lookups
CREATE INDEX idx_lorebooks_new_user_id ON lorebooks_new(user_id);

-- Copy compatible data from old table
-- NOTE: This migration cannot preserve existing data because:
-- 1. Primary key type changed (INTEGER -> TEXT/UUID)
-- 2. New NOT NULL columns (user_id, source_format) have no source data
-- 3. Structural changes are too significant
-- If there is existing data, it must be migrated manually or re-imported
INSERT INTO lorebooks_new (id, user_id, name, description, source_format, is_public, created_at, updated_at)
SELECT
    CAST(id AS TEXT) as id,  -- Convert INTEGER id to TEXT
    'default-user-id' as user_id,  -- Placeholder - must be updated manually
    COALESCE(name, 'Unnamed Lorebook') as name,  -- Ensure NOT NULL
    description,
    'legacy' as source_format,  -- Mark as legacy imports
    false as is_public,
    created_at,
    updated_at
FROM lorebooks
WHERE name IS NOT NULL;  -- Only migrate lorebooks with names

-- Drop old table
DROP TABLE lorebooks;

-- Rename new table to original name
ALTER TABLE lorebooks_new RENAME TO lorebooks;

-- Recreate trigger for updated_at
CREATE TRIGGER set_updated_at
BEFORE UPDATE ON lorebooks
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE lorebooks SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
