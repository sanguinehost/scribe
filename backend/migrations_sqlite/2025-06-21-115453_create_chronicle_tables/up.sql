-- SQLite Migration (Converted from PostgreSQL)
-- Original: up.sql
-- Conversion date: 2025-10-19T11:00:19.550852
--
-- IMPORTANT: Review warnings below and verify functionality
-- ================================================================

-- Create Chronicle tables and add player_chronicle_id to chat_sessions
-- Based on Chronicle Implementation Plan

-- Create player_chronicles table
CREATE TABLE player_chronicles (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create chronicle_events table
CREATE TABLE chronicle_events (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid(),
    chronicle_id TEXT NOT NULL REFERENCES player_chronicles(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    summary TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'USER_ADDED',
    event_data TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Add player_chronicle_id to chat_sessions table
ALTER TABLE chat_sessions
ADD COLUMN player_chronicle_id TEXT REFERENCES player_chronicles(id) ON DELETE SET NULL;

-- Create indexes for performance
CREATE INDEX idx_player_chronicles_user_id ON player_chronicles(user_id);
CREATE INDEX idx_chronicle_events_chronicle_id ON chronicle_events(chronicle_id);
CREATE INDEX idx_chronicle_events_user_id ON chronicle_events(user_id);
CREATE INDEX idx_chronicle_events_event_type ON chronicle_events(event_type);
CREATE INDEX idx_chronicle_events_source ON chronicle_events(source);
CREATE INDEX idx_chronicle_events_created_at ON chronicle_events(created_at);
CREATE INDEX idx_chat_sessions_player_chronicle_id ON chat_sessions(player_chronicle_id);

-- Create partial index for chronicle events with event_data
CREATE INDEX idx_chronicle_events_event_data_gin ON chronicle_events (event_data)
WHERE event_data IS NOT NULL;
