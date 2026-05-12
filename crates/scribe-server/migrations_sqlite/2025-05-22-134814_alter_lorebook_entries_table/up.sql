-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql - Major schema change for lorebook_entries table
--
-- IMPORTANT: SQLite doesn't support complex ALTER TABLE operations
-- This migration uses the table recreation pattern:
-- 1. Create new table with desired schema
-- 2. Copy compatible data (with placeholder encrypted values)
-- 3. Drop old table
-- 4. Rename new table
-- ================================================================

-- Create new lorebook_entries table with updated schema
CREATE TABLE lorebook_entries_new (
    id TEXT PRIMARY KEY,  -- Changed from INTEGER to TEXT (UUID)
    lorebook_id TEXT NOT NULL,  -- Changed from INTEGER to TEXT (UUID), FK to lorebooks
    user_id TEXT NOT NULL,  -- NEW: Owner of the lorebook entry (FK to users, enforced at app level)
    original_sillytavern_uid INTEGER,  -- NEW: Original SillyTavern entry ID (nullable)
    entry_title_ciphertext BLOB NOT NULL,  -- NEW: Encrypted title (replaces 'name')
    entry_title_nonce BLOB NOT NULL,  -- NEW: Nonce for title encryption
    keys_text_ciphertext BLOB NOT NULL,  -- NEW: Encrypted keywords (replaces 'keys')
    keys_text_nonce BLOB NOT NULL,  -- NEW: Nonce for keywords encryption
    content_ciphertext BLOB NOT NULL,  -- NEW: Encrypted content (replaces old 'content' TEXT)
    content_nonce BLOB NOT NULL,  -- NEW: Nonce for content encryption
    comment_ciphertext BLOB,  -- NEW: Encrypted comment (replaces old 'comment' TEXT, nullable)
    comment_nonce BLOB,  -- NEW: Nonce for comment encryption (nullable)
    is_enabled BOOLEAN NOT NULL DEFAULT true,  -- Renamed from 'enabled'
    is_constant BOOLEAN NOT NULL DEFAULT false,  -- Renamed from 'constant'
    insertion_order INTEGER NOT NULL DEFAULT 100,  -- Kept with new default
    placement_hint TEXT,  -- NEW: Placement hint (replaces 'position', nullable)
    sillytavern_metadata_ciphertext BLOB,  -- NEW: Encrypted SillyTavern metadata (nullable)
    sillytavern_metadata_nonce BLOB,  -- NEW: Nonce for metadata encryption (nullable)
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create index for lorebook_id lookups
CREATE INDEX idx_lorebook_entries_new_lorebook_id ON lorebook_entries_new(lorebook_id);

-- Create index for user_id lookups
CREATE INDEX idx_lorebook_entries_new_user_id ON lorebook_entries_new(user_id);

-- Copy compatible data from old table
-- NOTE: This migration cannot preserve existing data because:
-- 1. Primary key type changed (INTEGER -> TEXT/UUID)
-- 2. Foreign key type changed (INTEGER -> TEXT/UUID)
-- 3. New encrypted columns require encryption keys
-- 4. New NOT NULL columns (user_id, ciphertext/nonce pairs) have no source data
-- If there is existing data, it must be migrated manually or re-imported
INSERT INTO lorebook_entries_new (
    id,
    lorebook_id,
    user_id,
    original_sillytavern_uid,
    entry_title_ciphertext,
    entry_title_nonce,
    keys_text_ciphertext,
    keys_text_nonce,
    content_ciphertext,
    content_nonce,
    comment_ciphertext,
    comment_nonce,
    is_enabled,
    is_constant,
    insertion_order,
    placement_hint,
    sillytavern_metadata_ciphertext,
    sillytavern_metadata_nonce,
    created_at,
    updated_at
)
SELECT
    CAST(id AS TEXT) as id,  -- Convert INTEGER id to TEXT
    CAST(lorebook_id AS TEXT) as lorebook_id,  -- Convert INTEGER FK to TEXT
    'default-user-id' as user_id,  -- Placeholder - must be updated manually
    CASE WHEN entry_id IS NOT NULL THEN CAST(entry_id AS INTEGER) ELSE NULL END as original_sillytavern_uid,
    X'00' as entry_title_ciphertext,  -- Placeholder encrypted data
    X'00' as entry_title_nonce,  -- Placeholder nonce
    X'00' as keys_text_ciphertext,  -- Placeholder encrypted keywords
    X'00' as keys_text_nonce,  -- Placeholder nonce
    X'00' as content_ciphertext,  -- Placeholder encrypted content
    X'00' as content_nonce,  -- Placeholder nonce
    CASE WHEN comment IS NOT NULL THEN X'00' ELSE NULL END as comment_ciphertext,  -- Placeholder if comment existed
    CASE WHEN comment IS NOT NULL THEN X'00' ELSE NULL END as comment_nonce,  -- Placeholder if comment existed
    enabled as is_enabled,
    COALESCE(constant, false) as is_constant,
    insertion_order,
    position as placement_hint,  -- Rename position to placement_hint
    NULL as sillytavern_metadata_ciphertext,
    NULL as sillytavern_metadata_nonce,
    created_at,
    updated_at
FROM lorebook_entries;

-- Drop old table
DROP TABLE lorebook_entries;

-- Rename new table to original name
ALTER TABLE lorebook_entries_new RENAME TO lorebook_entries;

-- Recreate trigger for updated_at
DROP TRIGGER IF EXISTS set_updated_at;
CREATE TRIGGER set_updated_at
BEFORE UPDATE ON lorebook_entries
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at OR NEW.updated_at IS NULL
BEGIN
    UPDATE lorebook_entries SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
