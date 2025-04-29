// backend/src/models/characters.rs
#![allow(dead_code)] // Allow dead code for fields not yet actively used
use std::str::FromStr; // <-- ADD THIS LINE
use serde_json::json; // <-- ADD THIS LINE
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use crate::models::users::User;
use crate::schema::characters;
use crate::services::character_parser::ParsedCharacterCard;
use bigdecimal::BigDecimal;
use diesel_json::Json; // Import Json wrapper
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid; // Added import

#[derive(
    Queryable, Selectable, Insertable, AsChangeset, Serialize, Deserialize, Debug, Clone, PartialEq,
)]
#[diesel(table_name = crate::schema::characters)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Character {
    pub id: Uuid,                             // PK
    pub user_id: Uuid,                        // FK to users table
    pub spec: String,
    pub spec_version: String,
    pub name: String,
    pub description: Option<String>,
    pub personality: Option<String>,          // Moved to match schema order
    pub scenario: Option<String>,             // Moved to match schema order
    pub first_mes: Option<String>,            // Moved to match schema order
    pub mes_example: Option<String>,          // Moved to match schema order
    pub creator_notes: Option<String>,        // Moved to match schema order
    pub system_prompt: Option<String>,        // Moved to match schema order
    pub post_history_instructions: Option<String>, // Moved to match schema order
    pub tags: Option<Vec<Option<String>>>,    // Moved to match schema order
    pub creator: Option<String>,              // Moved to match schema order
    pub character_version: Option<String>,    // Moved to match schema order
    pub alternate_greetings: Option<Vec<Option<String>>>, // Moved to match schema order
    pub nickname: Option<String>,             // Added missing field
    pub creator_notes_multilingual: Option<Json<JsonValue>>, // Moved to match schema order
    pub source: Option<Vec<Option<String>>>, // Added missing field
    pub group_only_greetings: Option<Vec<Option<String>>>, // Added missing field
    pub creation_date: Option<DateTime<Utc>>, // Added missing field
    pub modification_date: Option<DateTime<Utc>>, // Added missing field
    pub created_at: DateTime<Utc>,            // Moved to match schema order
    pub updated_at: DateTime<Utc>,            // Moved to match schema order
    pub persona: Option<String>,              // Moved to match schema order
    pub world_scenario: Option<String>,       // Moved to match schema order
    pub avatar: Option<String>,               // Moved to match schema order
    pub chat: Option<String>,                 // Moved to match schema order
    pub greeting: Option<String>,             // Moved to match schema order
    pub definition: Option<String>,           // Moved to match schema order
    pub default_voice: Option<String>,        // Moved to match schema order
    pub extensions: Option<Json<JsonValue>>,  // Moved to match schema order
    pub data_id: Option<i32>,                 // Moved to match schema order
    pub category: Option<String>,             // Moved to match schema order
    pub definition_visibility: Option<String>, // Moved to match schema order
    pub depth: Option<i32>,                   // Moved to match schema order
    pub example_dialogue: Option<String>,     // Moved to match schema order
    pub favorite: Option<bool>,               // Moved to match schema order
    pub first_message_visibility: Option<String>, // Moved to match schema order
    pub height: Option<BigDecimal>,           // Moved to match schema order
    pub last_activity: Option<DateTime<Utc>>, // Moved to match schema order
    pub migrated_from: Option<String>,        // Moved to match schema order
    pub model_prompt: Option<String>,         // Moved to match schema order
    pub model_prompt_visibility: Option<String>, // Moved to match schema order
    pub model_temperature: Option<BigDecimal>, // Moved to match schema order
    pub num_interactions: Option<i64>,        // Moved to match schema order
    pub permanence: Option<BigDecimal>,       // Moved to match schema order
    pub persona_visibility: Option<String>,   // Moved to match schema order
    pub revision: Option<i32>,                // Moved to match schema order
    pub sharing_visibility: Option<String>,   // Moved to match schema order
    pub status: Option<String>,               // Moved to match schema order
    pub system_prompt_visibility: Option<String>, // Moved to match schema order
    pub system_tags: Option<Vec<Option<String>>>, // Moved to match schema order
    pub token_budget: Option<i32>,            // Moved to match schema order
    pub usage_hints: Option<Json<JsonValue>>, // Moved to match schema order
    pub user_persona: Option<String>,         // Moved to match schema order
    pub user_persona_visibility: Option<String>, // Moved to match schema order
    pub visibility: Option<String>,           // Moved to match schema order
    pub weight: Option<BigDecimal>,           // Moved to match schema order
    pub world_scenario_visibility: Option<String>, // Moved to match schema order
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
                    let mapped: Vec<&'a str> = v
                        .iter()
                        .filter(|s| !s.is_empty())
                        .map(|s| s.as_str()) // Use as_str()
                        .collect(); // Compiler should infer Vec<&str>
                    if mapped.is_empty() {
                        None
                    } else {
                        Some(mapped)
                    }
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
                    let mapped: Vec<&'a str> = v
                        .iter()
                        .filter(|s| !s.is_empty())
                        .map(|s| s.as_str()) // Use as_str()
                        .collect();
                    if mapped.is_empty() {
                        None
                    } else {
                        Some(mapped)
                    }
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
#[derive(
    Queryable, Selectable, Identifiable, Associations, Serialize, Deserialize, Debug, Clone,
)]
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

// Helper function to create a dummy Character instance
    fn create_dummy_character() -> Character {
        let now = Utc::now();
        let user_uuid = Uuid::new_v4();
        Character {
            id: Uuid::new_v4(),
            user_id: user_uuid,
            spec: "spec_v1".to_string(),
            spec_version: "1.0".to_string(),
            name: "Dummy Character".to_string(),
            description: Some("A character for testing".to_string()),
            personality: Some("Test personality".to_string()),
            scenario: Some("Test scenario".to_string()),
            first_mes: Some("Hello there!".to_string()),
            mes_example: Some("An example message.".to_string()),
            creator_notes: Some("Notes from creator.".to_string()),
            system_prompt: Some("System prompt here.".to_string()),
            post_history_instructions: Some("Instructions.".to_string()),
            tags: Some(vec![Some("tag1".to_string()), Some("tag2".to_string())]),
            creator: Some("Test Creator".to_string()),
            character_version: Some("v1.0".to_string()),
            alternate_greetings: Some(vec![Some("Hi".to_string()), Some("Hey".to_string())]),
            nickname: Some("Dummy".to_string()),
            creator_notes_multilingual: Some(Json(json!({"en": "English notes"}))),
            source: Some(vec![Some("Source A".to_string())]),
            group_only_greetings: Some(vec![Some("Group greeting".to_string())]),
            creation_date: Some(now),
            modification_date: Some(now),
            created_at: now,
            updated_at: now,
            persona: Some("Test Persona".to_string()),
            world_scenario: Some("Test World".to_string()),
            avatar: Some("avatar.png".to_string()),
            chat: Some("chat_id".to_string()),
            greeting: Some("General Kenobi!".to_string()),
            definition: Some("Definition text".to_string()),
            default_voice: Some("voice_id".to_string()),
            extensions: Some(Json(json!({"custom_field": "value"}))),
            data_id: Some(123),
            category: Some("Test Category".to_string()),
            definition_visibility: Some("public".to_string()),
            depth: Some(5),
            example_dialogue: Some("Dialogue example.".to_string()),
            favorite: Some(true),
            first_message_visibility: Some("private".to_string()),
            height: Some(BigDecimal::from(180)),
            last_activity: Some(now),
            migrated_from: Some("old_system".to_string()),
            model_prompt: Some("Model prompt text.".to_string()),
            model_prompt_visibility: Some("public".to_string()),
            model_temperature: Some(BigDecimal::from_str("0.7").unwrap()),
            num_interactions: Some(100),
            permanence: Some(BigDecimal::from_str("0.5").unwrap()),
            persona_visibility: Some("public".to_string()),
            revision: Some(2),
            sharing_visibility: Some("friends".to_string()),
            status: Some("active".to_string()),
            system_prompt_visibility: Some("private".to_string()),
            system_tags: Some(vec![Some("system_tag".to_string())]),
            token_budget: Some(2048),
            usage_hints: Some(Json(json!({"hint": "Use carefully"}))),
            user_persona: Some("User persona text.".to_string()),
            user_persona_visibility: Some("private".to_string()),
            visibility: Some("public".to_string()),
            weight: Some(BigDecimal::from_str("75.5").unwrap()),
            world_scenario_visibility: Some("public".to_string()),
        }
    }

    #[test]
    fn test_character_debug() {
        let character = create_dummy_character();
        // Ensure Debug formatting doesn't panic
        let debug_output = format!("{:?}", character);
        assert!(debug_output.contains("Dummy Character")); // Basic check
        assert!(debug_output.starts_with("Character {"));
        assert!(debug_output.ends_with("}"));
    }

    #[test]
    fn test_character_clone() {
        let character1 = create_dummy_character();
        let character2 = character1.clone();
        // Assert equality using derived PartialEq
        assert_eq!(character1, character2);
        // Optionally, modify one and assert they are no longer equal
        // let mut character3 = character1.clone();
        // character3.name = "Modified Name".to_string();
        // assert_ne!(character1, character3);
    }

mod tests {
    #[allow(unused_imports)] // <-- ADD THIS LINE
    use super::*; // <-- RESTORE THIS LINE
    use crate::models::character_card::{CharacterCardDataV3, CharacterCardV3};
    use crate::services::character_parser::ParsedCharacterCard;

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
        ParsedCharacterCard::V2Fallback(CharacterCardDataV3 {
            // V2 uses the V3 data struct as fallback
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
        let deserialized_metadata: CharacterMetadata =
            serde_json::from_str(&json_string).expect("Deserialization failed");

        // Assert equality (Direct comparison should work due to Clone, PartialEq)
        assert_eq!(metadata.id, deserialized_metadata.id);
        assert_eq!(metadata.user_id, deserialized_metadata.user_id);
        assert_eq!(metadata.name, deserialized_metadata.name);
        assert_eq!(metadata.description, deserialized_metadata.description);
        assert_eq!(metadata.first_mes, deserialized_metadata.first_mes);
        // Note: Comparing DateTime<Utc> directly might be flaky due to precision differences
        // after serialization/deserialization. Comparing timestamps is safer.
        assert_eq!(
            metadata.created_at.timestamp_millis(),
            deserialized_metadata.created_at.timestamp_millis()
        );
        assert_eq!(
            metadata.updated_at.timestamp_millis(),
            deserialized_metadata.updated_at.timestamp_millis()
        );
    }
}
