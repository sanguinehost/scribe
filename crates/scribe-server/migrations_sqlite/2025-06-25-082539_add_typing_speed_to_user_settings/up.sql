-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.502940
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Add typing_speed column to user_settings table
ALTER TABLE user_settings ADD COLUMN typing_speed INTEGER;
