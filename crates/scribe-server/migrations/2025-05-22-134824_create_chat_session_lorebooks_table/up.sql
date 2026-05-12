-- Ensure uuid-ossp extension is available, though it should be from previous migrations.
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE chat_session_lorebooks (
    chat_session_id UUID NOT NULL,
    lorebook_id UUID NOT NULL,
    user_id UUID NOT NULL,
    PRIMARY KEY (chat_session_id, lorebook_id),
    CONSTRAINT fk_csl_chat_session FOREIGN KEY (chat_session_id) REFERENCES chat_sessions(id) ON DELETE CASCADE,
    CONSTRAINT fk_csl_lorebook FOREIGN KEY (lorebook_id) REFERENCES lorebooks(id) ON DELETE CASCADE,
    CONSTRAINT fk_csl_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Add indexes for faster lookups, especially if querying by user_id or lorebook_id individually.
CREATE INDEX idx_csl_user_id ON chat_session_lorebooks (user_id);
CREATE INDEX idx_csl_lorebook_id ON chat_session_lorebooks (lorebook_id);
-- The primary key already covers (chat_session_id, lorebook_id) and (chat_session_id) lookups.
