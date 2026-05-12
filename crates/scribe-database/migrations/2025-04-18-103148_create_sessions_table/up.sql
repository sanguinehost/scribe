CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Your SQL goes here
CREATE TABLE sessions (
    id TEXT PRIMARY KEY NOT NULL,        -- Session ID provided by axum-session
    expires TIMESTAMPTZ,                 -- Expiry timestamp (optional)
    session TEXT NOT NULL                -- Serialized session data
);

-- Optional: Index for faster session lookups
CREATE INDEX idx_sessions_id ON sessions (id);

-- Optional: Index for cleaning up expired sessions (if needed)
-- CREATE INDEX idx_sessions_expires ON sessions (expires);
