-- SQLite Migration: Add Cost Tracking Fields
-- Converted from PostgreSQL migration: 2025-10-13-192830_add_proper_cost_tracking_fields
-- Purpose: Track API costs for desktop users, enable sync with cloud platform
--
-- Note: SQLite uses REAL for decimal numbers (stored as 8-byte IEEE floating point)
-- This provides ~15 digits of precision, sufficient for dollar amounts

-- Add cost tracking fields to chat_messages
ALTER TABLE chat_messages ADD COLUMN actual_cost REAL NOT NULL DEFAULT 0;
ALTER TABLE chat_messages ADD COLUMN modified_cost REAL NOT NULL DEFAULT 0;
ALTER TABLE chat_messages ADD COLUMN credit_cost INTEGER NOT NULL DEFAULT 0;
ALTER TABLE chat_messages ADD COLUMN actual_charge REAL NOT NULL DEFAULT 0;

-- Add cumulative cost tracking fields to chat_sessions
ALTER TABLE chat_sessions ADD COLUMN total_actual_cost REAL NOT NULL DEFAULT 0;
ALTER TABLE chat_sessions ADD COLUMN total_modified_cost REAL NOT NULL DEFAULT 0;
ALTER TABLE chat_sessions ADD COLUMN total_credit_cost INTEGER NOT NULL DEFAULT 0;
ALTER TABLE chat_sessions ADD COLUMN total_actual_charge REAL NOT NULL DEFAULT 0;

-- Create indexes for cost-based queries
CREATE INDEX idx_chat_messages_actual_cost ON chat_messages(session_id, actual_cost) WHERE actual_cost > 0;
CREATE INDEX idx_chat_messages_credit_cost ON chat_messages(session_id, credit_cost) WHERE credit_cost > 0;
