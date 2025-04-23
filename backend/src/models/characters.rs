// backend/src/models/characters.rs
#![allow(dead_code)] // Allow dead code for fields not yet actively used
// use crate::schema::characters; // Removed unused import
// use crate::schema::users; // Removed unused import
use chrono::{DateTime, Utc}; // Removed unused NaiveDateTime
use diesel::prelude::*;
// use chrono::{DateTime, Utc, NaiveDateTime};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;
use crate::services::character_parser::ParsedCharacterCard;
use diesel_json::Json; // Import Json wrapper
use bigdecimal::BigDecimal;
use crate::schema::characters;
use crate::models::users::User; // Added import
// use crate::models::character_card::{CharacterCardV3, CharacterCardDataV3}; // Import the actual structs

#[derive(
    Queryable, Selectable, Insertable, AsChangeset, Serialize, Deserialize, Debug, Clone, PartialEq,
)]
#[diesel(table_name = crate::schema::characters)]
#[diesel(check_for_backend(diesel::pg::Pg))] 
pub struct Character {
    #[diesel(deserialize_as = Uuid)]
    pub id: Uuid, // PK
    #[diesel(deserialize_as = Uuid)]
    pub user_id: Uuid, // FK to users table
    pub name: String,
    pub description: Option<String>,
    pub persona: Option<String>,
    pub world_scenario: Option<String>,
    pub system_prompt: Option<String>,
    pub post_history_instructions: Option<String>,
    pub creator_notes: Option<String>,
    pub personality: Option<String>,
    pub scenario: Option<String>,
    pub first_mes: Option<String>,
    pub mes_example: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub creator: Option<String>,
    pub character_version: Option<String>,
    pub tags: Option<Vec<Option<String>>>,
    pub avatar: Option<String>, // file name or identifier for the avatar image
    pub chat: Option<String>,   // identifier for associated chat history?
    pub greeting: Option<String>,
    pub definition: Option<String>,
    pub default_voice: Option<String>,
    pub extensions: Option<Json<JsonValue>>, // Use Json wrapper for JSONB
    pub data_id: Option<i32>,
    pub alternate_greetings: Option<Vec<Option<String>>>,
    pub category: Option<String>,
    pub definition_visibility: Option<String>,
    pub depth: Option<i32>,
    pub example_dialogue: Option<String>,
    pub favorite: Option<bool>,
    pub first_message_visibility: Option<String>,
    pub height: Option<BigDecimal>,
    pub last_activity: Option<DateTime<Utc>>,
    pub migrated_from: Option<String>,
    pub model_prompt: Option<String>,
    pub model_prompt_visibility: Option<String>,
    pub model_temperature: Option<BigDecimal>,
    pub num_interactions: Option<i64>,
    pub permanence: Option<BigDecimal>,
    pub persona_visibility: Option<String>,
    pub revision: Option<i32>,
    pub sharing_visibility: Option<String>,
    pub status: Option<String>,
    pub system_prompt_visibility: Option<String>,
    pub system_tags: Option<Vec<Option<String>>>,
    pub token_budget: Option<i32>,
    pub usage_hints: Option<Json<JsonValue>>, // Use Json wrapper for JSONB
    pub user_persona: Option<String>,
    pub user_persona_visibility: Option<String>,
    pub visibility: Option<String>,
    pub weight: Option<BigDecimal>,
    pub world_scenario_visibility: Option<String>,
    pub creator_notes_multilingual: Option<Json<JsonValue>>, // Use Json wrapper for JSONB
}

// Represents fields that can be updated from a parsed card
// Using Option<&'a str> allows updating only provided fields
// without allocating new Strings.
#[derive(Debug, Default, AsChangeset)]
#[diesel(table_name = crate::schema::characters)]
pub struct UpdatableCharacter<'a> {
    pub spec: Option<&'a str>,
    pub spec_version: Option<&'a str>,
    pub name: Option<&'a str>,
    pub description: Option<&'a str>,
    pub personality: Option<&'a str>,
    pub first_mes: Option<&'a str>,
    pub mes_example: Option<&'a str>,
    pub scenario: Option<&'a str>,
    pub system_prompt: Option<&'a str>,
    pub creator_notes: Option<&'a str>,
    // Use Vec<&'a str> for slices of strings
    pub tags: Option<Vec<&'a str>>,
    pub creator: Option<&'a str>,
    pub character_version: Option<&'a str>,
    pub alternate_greetings: Option<Vec<&'a str>>,
    // JSON needs separate handling, maybe Option<&'a Value>?
    // pub metadata_json: Option<&'a Value>, // Correct type?
    // Map other DB fields if needed
}

impl<'a> From<&'a ParsedCharacterCard> for UpdatableCharacter<'a> {
    fn from(parsed_card: &'a ParsedCharacterCard) -> Self {
        match parsed_card {
            ParsedCharacterCard::V3(card_v3) => {
                // Corrected map_string helper
                let map_string = |s: &'a String| -> Option<&'a str> {
                    if s.is_empty() { None } else { Some(s.as_str()) }
                };
                // Corrected map_vec helper
                let map_vec = |v: &'a Vec<String>| -> Option<Vec<&'a str>> {
                    let mapped: Vec<&'a str> = v.iter()
                                                .filter(|s| !s.is_empty())
                                                .map(|s| s.as_str()) // Use as_str()
                                                .collect(); // Compiler should infer Vec<&str>
                    if mapped.is_empty() { None } else { Some(mapped) }
                };

                Self {
                    spec: Some(&card_v3.spec),
                    spec_version: Some(&card_v3.spec_version),
                    name: card_v3.data.name.as_deref(), // Correct: Option<String> -> Option<&str>
                    description: map_string(&card_v3.data.description),
                    personality: map_string(&card_v3.data.personality),
                    first_mes: map_string(&card_v3.data.first_mes),
                    mes_example: map_string(&card_v3.data.mes_example),
                    scenario: map_string(&card_v3.data.scenario),
                    system_prompt: map_string(&card_v3.data.system_prompt),
                    // metadata_json: None,
                    creator_notes: map_string(&card_v3.data.creator_notes),
                    tags: map_vec(&card_v3.data.tags),
                    creator: map_string(&card_v3.data.creator),
                    character_version: map_string(&card_v3.data.character_version),
                    alternate_greetings: map_vec(&card_v3.data.alternate_greetings),
                }
            }
            ParsedCharacterCard::V2Fallback(data_v2) => {
                let map_string = |s: &'a String| -> Option<&'a str> {
                     if s.is_empty() { None } else { Some(s.as_str()) }
                 };
                let map_vec = |v: &'a Vec<String>| -> Option<Vec<&'a str>> {
                      let mapped: Vec<&'a str> = v.iter()
                                                  .filter(|s| !s.is_empty())
                                                  .map(|s| s.as_str()) // Use as_str()
                                                  .collect();
                      if mapped.is_empty() { None } else { Some(mapped) }
                  };

                 Self {
                    spec: None,
                    spec_version: None,
                    name: data_v2.name.as_deref(), // Correct: Option<String> -> Option<&str>
                    description: map_string(&data_v2.description),
                    personality: map_string(&data_v2.personality),
                    first_mes: map_string(&data_v2.first_mes),
                    mes_example: map_string(&data_v2.mes_example),
                    scenario: map_string(&data_v2.scenario),
                    system_prompt: map_string(&data_v2.system_prompt),
                    // metadata_json: None,
                    creator_notes: map_string(&data_v2.creator_notes),
                    tags: map_vec(&data_v2.tags),
                    creator: map_string(&data_v2.creator),
                    character_version: map_string(&data_v2.character_version),
                    alternate_greetings: map_vec(&data_v2.alternate_greetings),
                 }
            }
        }
    }
}

// Represents the core metadata of a character, stored in the DB
#[derive(Queryable, Selectable, Identifiable, Associations, Serialize, Deserialize, Debug, Clone)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(table_name = characters)]
pub struct CharacterMetadata {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub first_mes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    // Add other V2/V3 fields needed for listing/selection if necessary
    // pub persona: Option<String>,
    // pub greeting: Option<String>,
    // pub example_dialogue: Option<String>,
    // ... other fields extracted from the card
}

// Structure for inserting a new character metadata record
#[derive(Insertable)]
#[diesel(table_name = characters)]
pub struct NewCharacterMetadata<'a> {
    pub user_id: Uuid,
    pub name: &'a str,
    pub description: Option<&'a str>,
    // Add other required fields that come directly from the parsed card
    // e.g., pub persona: Option<&'a str>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::character_card::{CharacterCardV3, CharacterCardDataV3}; // Import the actual structs
    use crate::services::character_parser::ParsedCharacterCard; // Import the enum
    use serde_json;
    use uuid::Uuid;
    use chrono::Utc;

    // Helper function to create a dummy V3 card
    fn create_dummy_v3_card() -> ParsedCharacterCard {
        ParsedCharacterCard::V3(CharacterCardV3 {
            spec: "chara_card_v3_spec".to_string(),
            spec_version: "1.0.0".to_string(),
            data: CharacterCardDataV3 {
                name: Some("Test V3 Name".to_string()),
                description: "V3 Description".to_string(),
                personality: "".to_string(), // Empty string
                first_mes: "V3 First Message".to_string(),
                mes_example: "V3 Example".to_string(),
                scenario: "".to_string(),
                system_prompt: "V3 System".to_string(),
                creator_notes: "V3 Creator Notes".to_string(),
                tags: vec!["tag1".to_string(), "".to_string(), "tag3".to_string()], // Include empty tag
                creator: "V3 Creator".to_string(),
                character_version: "v1.2".to_string(),
                alternate_greetings: vec!["Hi".to_string(), "Hello".to_string()],
                // Explicitly add missing fields with default values
                post_history_instructions: Default::default(),
                character_book: None,
                assets: None,
                nickname: None,
                creator_notes_multilingual: None,
                source: None,
                group_only_greetings: Default::default(),
                creation_date: None,
                modification_date: None,
                extensions: Default::default(), // Keep extensions
            },
        })
    }

    // Helper function to create a dummy V2 card
     fn create_dummy_v2_card() -> ParsedCharacterCard {
        ParsedCharacterCard::V2Fallback(CharacterCardDataV3 { // V2 uses the V3 data struct as fallback
            name: Some("Test V2 Name".to_string()),
            description: "V2 Description".to_string(),
            personality: "V2 Personality".to_string(),
            first_mes: "".to_string(), // Empty string
            mes_example: "V2 Example".to_string(),
            scenario: "V2 Scenario".to_string(),
            system_prompt: "".to_string(),
            creator_notes: "V2 Creator Notes".to_string(),
            tags: vec!["v2tag1".to_string()],
            creator: "V2 Creator".to_string(),
            character_version: "v1.1".to_string(),
            alternate_greetings: vec![], // Empty vec
            // Fields specific to V2 or common fields used as fallback
            // These fields aren't part of CharacterCardDataV3 struct, so remove them or handle differently if needed
            // greeting: Some("V2 Greeting".to_string()),
            // avatar: Some("v2_avatar.png".to_string()),
            // chat: None,
            // ... other V2 fields if they exist in the struct
            ..Default::default() // Use default for remaining fields in CharacterCardDataV3
        })
    }

    #[test]
    fn test_updatable_character_from_v3_card() {
        let v3_card = create_dummy_v3_card();
        let updatable = UpdatableCharacter::from(&v3_card);

        assert_eq!(updatable.spec, Some("chara_card_v3_spec"));
        assert_eq!(updatable.spec_version, Some("1.0.0"));
        assert_eq!(updatable.name, Some("Test V3 Name"));
        assert_eq!(updatable.description, Some("V3 Description"));
        assert_eq!(updatable.personality, None); // Empty string maps to None
        assert_eq!(updatable.first_mes, Some("V3 First Message"));
        assert_eq!(updatable.mes_example, Some("V3 Example"));
        assert_eq!(updatable.scenario, None); // Empty string maps to None
        assert_eq!(updatable.system_prompt, Some("V3 System"));
        assert_eq!(updatable.creator_notes, Some("V3 Creator Notes"));
        assert_eq!(updatable.tags, Some(vec!["tag1", "tag3"])); // Empty tag is filtered out
        assert_eq!(updatable.creator, Some("V3 Creator"));
        assert_eq!(updatable.character_version, Some("v1.2"));
        assert_eq!(updatable.alternate_greetings, Some(vec!["Hi", "Hello"]));
    }

    #[test]
    fn test_updatable_character_from_v2_card() {
        let v2_card = create_dummy_v2_card();
        let updatable = UpdatableCharacter::from(&v2_card);

        assert_eq!(updatable.spec, None); // No spec in V2
        assert_eq!(updatable.spec_version, None); // No spec_version in V2
        assert_eq!(updatable.name, Some("Test V2 Name"));
        assert_eq!(updatable.description, Some("V2 Description"));
        assert_eq!(updatable.personality, Some("V2 Personality"));
        assert_eq!(updatable.first_mes, None); // Empty string maps to None
        assert_eq!(updatable.mes_example, Some("V2 Example"));
        assert_eq!(updatable.scenario, Some("V2 Scenario"));
        assert_eq!(updatable.system_prompt, None); // Empty string maps to None
        assert_eq!(updatable.creator_notes, Some("V2 Creator Notes"));
        assert_eq!(updatable.tags, Some(vec!["v2tag1"]));
        assert_eq!(updatable.creator, Some("V2 Creator"));
        assert_eq!(updatable.character_version, Some("v1.1"));
        assert_eq!(updatable.alternate_greetings, None); // Empty vec maps to None
    }

    #[test]
    fn test_character_metadata_serde() {
        let dt = Utc::now();
        let uuid = Uuid::new_v4();
        let user_uuid = Uuid::new_v4();

        let metadata = CharacterMetadata {
            id: uuid,
            user_id: user_uuid,
            name: "Test Character".to_string(),
            description: Some("A test description".to_string()),
            first_mes: None,
            created_at: dt,
            updated_at: dt,
        };

        // Serialize
        let json_string = serde_json::to_string(&metadata).expect("Serialization failed");
        println!("Serialized JSON: {}", json_string); // Optional: print for debugging

        // Deserialize
        let deserialized_metadata: CharacterMetadata = serde_json::from_str(&json_string).expect("Deserialization failed");

        // Assert equality (Direct comparison should work due to Clone, PartialEq)
        assert_eq!(metadata.id, deserialized_metadata.id);
        assert_eq!(metadata.user_id, deserialized_metadata.user_id);
        assert_eq!(metadata.name, deserialized_metadata.name);
        assert_eq!(metadata.description, deserialized_metadata.description);
        assert_eq!(metadata.first_mes, deserialized_metadata.first_mes);
        // Note: Comparing DateTime<Utc> directly might be flaky due to precision differences
        // after serialization/deserialization. Comparing timestamps is safer.
        assert_eq!(metadata.created_at.timestamp_millis(), deserialized_metadata.created_at.timestamp_millis());
        assert_eq!(metadata.updated_at.timestamp_millis(), deserialized_metadata.updated_at.timestamp_millis());
    }
} 