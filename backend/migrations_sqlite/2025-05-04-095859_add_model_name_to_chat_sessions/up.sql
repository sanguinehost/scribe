-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:15:25.499264
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Your SQL goes here

-- Add model_name column to chat_sessions table
ALTER TABLE chat_sessions
ADD COLUMN model_name TEXT NOT NULL DEFAULT 'gemini-2.5-pro';
