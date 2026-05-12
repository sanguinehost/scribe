-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.497383
--
-- IMPORTANT: This migration ONLY adds chat_mode column
-- Making character_id nullable is handled by a separate migration
-- ================================================================

-- Add chat_mode column to chat_sessions table
-- Default to 'Character' to maintain compatibility with existing sessions
ALTER TABLE chat_sessions
ADD COLUMN chat_mode VARCHAR NOT NULL DEFAULT 'Character';
