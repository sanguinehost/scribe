ALTER TABLE users
ADD COLUMN default_persona_id UUID,
ADD CONSTRAINT fk_default_user_persona
    FOREIGN KEY (default_persona_id)
    REFERENCES user_personas (id)
    ON DELETE SET NULL;
