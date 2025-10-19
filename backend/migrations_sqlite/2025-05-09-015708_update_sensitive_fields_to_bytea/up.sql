-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.490458
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Alter chat_messages table
ALTER TABLE chat_messages
ALTER COLUMN content TYPE BLOB USING content::BLOB;

-- Alter characters table
ALTER TABLE characters
ALTER COLUMN description TYPE BLOB USING description::BLOB,
ALTER COLUMN personality TYPE BLOB USING personality::BLOB,
ALTER COLUMN scenario TYPE BLOB USING scenario::BLOB,
ALTER COLUMN first_mes TYPE BLOB USING first_mes::BLOB,
ALTER COLUMN mes_example TYPE BLOB USING mes_example::BLOB;
