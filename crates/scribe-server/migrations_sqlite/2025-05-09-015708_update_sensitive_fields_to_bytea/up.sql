-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.490458
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- SQLite doesn't support ALTER COLUMN TYPE
-- However, SQLite is type-agnostic: TEXT columns can store BLOB data and vice versa
-- The existing TEXT columns will work fine for storing encrypted binary data
-- No schema changes needed for SQLite

-- Original PostgreSQL migration changed these columns from TEXT to BYTEA (BLOB):
-- - chat_messages.content
-- - characters.description, personality, scenario, first_mes, mes_example
-- In SQLite, these remain declared as TEXT but can store binary data without issues
