-- Alter chat_messages table
ALTER TABLE chat_messages
ALTER COLUMN content TYPE TEXT USING encode(content, 'escape');

-- Alter characters table
ALTER TABLE characters
ALTER COLUMN description TYPE TEXT USING encode(description, 'escape'),
ALTER COLUMN personality TYPE TEXT USING encode(personality, 'escape'),
ALTER COLUMN scenario TYPE TEXT USING encode(scenario, 'escape'),
ALTER COLUMN first_mes TYPE TEXT USING encode(first_mes, 'escape'),
ALTER COLUMN mes_example TYPE TEXT USING encode(mes_example, 'escape');
