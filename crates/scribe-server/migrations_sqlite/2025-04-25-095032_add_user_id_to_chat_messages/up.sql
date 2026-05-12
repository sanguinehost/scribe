-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.489943
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Your SQL goes here

-- Add user_id column to chat_messages
-- Note: SQLite doesn't support adding NOT NULL columns to existing tables with data
-- Making it nullable for now; actual constraint enforcement at application level
ALTER TABLE chat_messages ADD COLUMN user_id TEXT NULL;

-- SQLite doesn't support ALTER TABLE ADD CONSTRAINT for foreign keys
-- Foreign key constraints can only be added at table creation time
-- The relationship is documented here but enforced at application level

-- Add an index for performance when querying by user_id
CREATE INDEX idx_chat_messages_user_id ON chat_messages(user_id);
