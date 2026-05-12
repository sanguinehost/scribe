-- SQLite Migration (Converted from PostgreSQL)
-- Original: down.sql
-- Conversion date: 2025-10-19T11:15:25.503000
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Remove typing_speed column from user_settings table
ALTER TABLE user_settings DROP COLUMN typing_speed;
