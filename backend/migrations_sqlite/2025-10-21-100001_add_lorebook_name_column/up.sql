-- SQLite Migration: Add name column to lorebook_entries
-- Aligns with PostgreSQL schema (VARCHAR(255) NULLABLE)
-- Purpose: Support legacy SillyTavern entry names for compatibility

ALTER TABLE lorebook_entries ADD COLUMN name TEXT;

-- Note: Column is nullable to match PostgreSQL schema
-- Most entries use entry_title_ciphertext as the primary title field
-- This 'name' field exists for backwards compatibility
