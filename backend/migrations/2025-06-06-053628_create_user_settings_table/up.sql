-- Create user_settings table for storing per-user default settings
CREATE TABLE user_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Generation Settings (nullable - fall back to system defaults if not set)
    default_model_name VARCHAR(100),
    default_temperature DECIMAL(3,2),
    default_max_output_tokens INTEGER,
    default_frequency_penalty DECIMAL(3,2),
    default_presence_penalty DECIMAL(3,2),
    default_top_p DECIMAL(4,3),
    default_top_k INTEGER,
    default_seed INTEGER,
    
    -- Gemini-Specific Settings
    default_gemini_thinking_budget INTEGER,
    default_gemini_enable_code_execution BOOLEAN,
    
    -- Context Management Settings
    default_context_total_token_limit INTEGER,
    default_context_recent_history_budget INTEGER,
    default_context_rag_budget INTEGER,
    
    -- Application Preferences
    auto_save_chats BOOLEAN DEFAULT true,
    theme VARCHAR(20) DEFAULT 'system',
    notifications_enabled BOOLEAN DEFAULT true,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Ensure one settings record per user
    UNIQUE(user_id)
);

-- Create index for faster lookups
CREATE INDEX idx_user_settings_user_id ON user_settings(user_id);

-- Create trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_user_settings_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_user_settings_updated_at
    BEFORE UPDATE ON user_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_user_settings_updated_at();