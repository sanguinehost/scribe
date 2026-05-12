-- Your SQL goes here
ALTER TABLE chat_sessions
ADD COLUMN active_custom_persona_id UUID REFERENCES user_personas(id) ON DELETE SET NULL,
ADD COLUMN active_impersonated_character_id UUID REFERENCES characters(id) ON DELETE SET NULL,
ADD CONSTRAINT only_one_active_persona CHECK (active_custom_persona_id IS NULL OR active_impersonated_character_id IS NULL);
