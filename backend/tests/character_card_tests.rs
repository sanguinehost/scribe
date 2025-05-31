// This file will contain tests for character_card.rs

// Import items from the main library crate
use scribe_backend::models::character_card::{CharacterCardDataV3, CharacterCardV3, NewCharacter};
use scribe_backend::services::character_parser::ParsedCharacterCard;
use serde_json; // Add this if not already implicitly imported by other uses
use uuid::Uuid; // Keep this specific import

#[test]
fn test_deserialize_minimal_v3_card() {
    let json_data = r#"{
        "spec": "chara_card_v3",
        "spec_version": "3.0",
        "data": {
            "name": "Test Character",
            "description": "A test description.",
            "personality": "",
            "scenario": "",
            "first_mes": "Hello!",
            "mes_example": ""
        }
    }"#;

    let card: Result<CharacterCardV3, _> = serde_json::from_str(json_data);
    assert!(
        card.is_ok(),
        "Failed to deserialize minimal card: {:?}",
        card.err()
    );
    let card = card.unwrap();
    assert_eq!(card.spec, "chara_card_v3");
    assert_eq!(card.data.name, Some("Test Character".to_string()));
    assert_eq!(card.data.description, "A test description.");
    assert_eq!(card.data.first_mes, "Hello!");
    assert!(card.data.alternate_greetings.is_empty());
    assert!(card.data.tags.is_empty());
    assert!(card.data.extensions.is_empty());
    assert!(card.data.character_book.is_none());
    assert!(card.data.assets.is_none()); // Should default to None if omitted
}

#[test]
fn test_deserialize_card_with_lorebook() {
    let json_data = r#"{
        "spec": "chara_card_v3",
        "spec_version": "3.0",
        "data": {
            "name": "Lore Keeper",
            "description": "Knows things.",
            "personality": "", "scenario": "", "first_mes": "", "mes_example": "",
            "character_book": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "user_id": "550e8400-e29b-41d4-a716-446655440001",
                "name": "World Facts",
                "description": null,
                "source_format": "sillytavern",
                "is_public": false,
                "created_at": "2025-05-23T00:00:00Z",
                "updated_at": "2025-05-23T00:00:00Z"
            }
        }
    }"#;
    let card: Result<CharacterCardV3, _> = serde_json::from_str(json_data);
    assert!(
        card.is_ok(),
        "Failed to deserialize card with lorebook: {:?}",
        card.err()
    );
    let card = card.unwrap();
    assert!(card.data.character_book.is_some());
    let book = card.data.character_book.unwrap();
    assert_eq!(book.name, "World Facts");
}

#[test]
fn test_deserialize_asset_types() {
    let json_data = r#"{
        "spec": "chara_card_v3",
        "spec_version": "3.0",
        "data": {
            "name": "Asset Tester", "description": "", "personality": "", "scenario": "", "first_mes": "", "mes_example": "",
            "assets": [
                {
                    "type": "icon",
                    "uri": "embeded://assets/icon/images/main_icon.png",
                    "name": "main",
                    "ext": "png"
                },
                {
                    "type": "user_icon",
                    "uri": "ccdefault:",
                    "name": "User",
                    "ext": "png"
                }
            ]
        }
     }"#;
    let card: Result<CharacterCardV3, _> = serde_json::from_str(json_data);
    assert!(
        card.is_ok(),
        "Failed to deserialize card with assets: {:?}",
        card.err()
    );
    let card = card.unwrap();
    assert!(card.data.assets.is_some());
    let assets = card.data.assets.unwrap();
    assert_eq!(assets.len(), 2);
    assert_eq!(assets[0].r#type, "icon");
    assert_eq!(assets[0].uri, "embeded://assets/icon/images/main_icon.png");
    assert_eq!(assets[0].name, "main");
    assert_eq!(assets[0].ext, "png");

    assert_eq!(assets[1].r#type, "user_icon");
    assert_eq!(assets[1].uri, "ccdefault:");
    assert_eq!(assets[1].name, "User");
    assert_eq!(assets[1].ext, "png"); // Spec says ext should be ignored for ccdefault:, but it must be present.
}

#[test]
fn test_default_empty_strings() {
    // Test that fields defaulting to String are empty if omitted, not null/error
    let json_data = r#"{
        "spec": "chara_card_v3",
        "spec_version": "3.0",
        "data": {
            "name": "Minimal"
        }
    }"#;
    let card: Result<CharacterCardV3, _> = serde_json::from_str(json_data);
    assert!(
        card.is_ok(),
        "Failed to deserialize card with missing defaults: {:?}",
        card.err()
    );
    let card = card.unwrap();
    assert_eq!(card.data.name, Some("Minimal".to_string())); // Check Option
    assert_eq!(card.data.description, ""); // Check default
    assert_eq!(card.data.personality, ""); // Check default
    assert_eq!(card.data.scenario, ""); // Check default
    assert_eq!(card.data.first_mes, ""); // Check default
    assert_eq!(card.data.mes_example, ""); // Check default
    assert_eq!(card.data.creator_notes, ""); // Check default
    assert_eq!(card.data.system_prompt, ""); // Check default
    assert_eq!(card.data.post_history_instructions, ""); // Check default
    assert!(card.data.alternate_greetings.is_empty()); // Check default
    assert!(card.data.tags.is_empty()); // Check default
    assert_eq!(card.data.creator, ""); // Check default
    assert_eq!(card.data.character_version, ""); // Check default
    assert!(card.data.extensions.is_empty()); // Check default
}

// --- Tests for NewCharacter::from_parsed_card ---

// Helper function to create a minimal ParsedCharacterCard::V2Fallback
// Need to import ParsedCharacterCard and CharacterCardDataV3 from the parent module if not already done
// Remove these old crate:: imports as they are now handled at the top level
// use crate::models::character_card::CharacterCardDataV3; // Assuming this path is correct
// use crate::services::character_parser::ParsedCharacterCard; // Assuming this path is correct
// use uuid::Uuid; // Need Uuid for user_id

fn create_minimal_v2_fallback(name: &str) -> ParsedCharacterCard {
    ParsedCharacterCard::V2Fallback(CharacterCardDataV3 {
        name: Some(name.to_string()),
        ..Default::default()
    })
}

#[test]
fn test_from_parsed_card_v2_empty_collections() {
    let user_id = Uuid::new_v4();
    let parsed_v2 = create_minimal_v2_fallback("V2 Empty Collections");

    let new_char = NewCharacter::from_parsed_card(&parsed_v2, user_id);

    assert_eq!(new_char.user_id, user_id);
    assert_eq!(new_char.name, "V2 Empty Collections");
    assert_eq!(new_char.spec, "chara_card_v2");
    assert_eq!(new_char.spec_version, "2.0");
    assert!(new_char.tags.is_none()); // Should be None when empty
    assert!(new_char.alternate_greetings.is_none()); // Should be None when empty
    assert!(new_char.description.is_none()); // Default empty string becomes None
}

#[test]
fn test_from_parsed_card_v2_with_collections() {
    let user_id = Uuid::new_v4();
    let data_v2 = CharacterCardDataV3 {
        // Removed mut, not needed
        name: Some("V2 With Collections".to_string()),
        tags: vec!["tag1".to_string(), "tag2".to_string()],
        alternate_greetings: vec!["hi".to_string()],
        description: "A description".to_string(),
        ..Default::default()
    };
    let parsed_v2 = ParsedCharacterCard::V2Fallback(data_v2);

    let new_char = NewCharacter::from_parsed_card(&parsed_v2, user_id);

    assert_eq!(new_char.user_id, user_id);
    assert_eq!(new_char.name, "V2 With Collections");
    assert_eq!(new_char.spec, "chara_card_v2");
    assert_eq!(new_char.spec_version, "2.0");
    assert_eq!(
        new_char.tags,
        Some(vec![Some("tag1".to_string()), Some("tag2".to_string())])
    );
    assert_eq!(
        new_char.alternate_greetings,
        Some(vec![Some("hi".to_string())])
    );
    assert_eq!(
        new_char.description,
        Some("A description".as_bytes().to_vec())
    );
}

// Add a test for V3 conversion as well for completeness
#[test]
fn test_from_parsed_card_v3() {
    let user_id = Uuid::new_v4();
    let data_v3 = CharacterCardDataV3 {
        name: Some("V3 Full".to_string()),
        description: "V3 Desc".to_string(),
        personality: "V3 Personality".to_string(),
        scenario: "V3 Scenario".to_string(),
        first_mes: "V3 First Mes".to_string(),
        mes_example: "V3 Mes Example".to_string(),
        creator_notes: "V3 Creator Notes".to_string(),
        system_prompt: "V3 System Prompt".to_string(),
        post_history_instructions: "V3 Post History".to_string(),
        tags: vec!["v3tag".to_string()],
        alternate_greetings: vec!["v3greet".to_string()],
        creator: "V3 Creator".to_string(),
        character_version: "1.1".to_string(),
        // assets and extensions can be default
        ..Default::default()
    };
    let card_v3 = CharacterCardV3 {
        spec: "chara_card_v3".to_string(),
        spec_version: "3.0".to_string(),
        data: data_v3.clone(), // Clone data_v3 for comparison later
    };
    let parsed_v3 = ParsedCharacterCard::V3(card_v3);

    let new_char = NewCharacter::from_parsed_card(&parsed_v3, user_id);

    assert_eq!(new_char.user_id, user_id);
    assert_eq!(new_char.name, "V3 Full");
    assert_eq!(new_char.spec, "chara_card_v3");
    assert_eq!(new_char.spec_version, "3.0");
    assert_eq!(
        new_char.description,
        Some(data_v3.description.as_bytes().to_vec())
    );
    assert_eq!(
        new_char.personality,
        Some(data_v3.personality.as_bytes().to_vec())
    );
    assert_eq!(
        new_char.scenario,
        Some(data_v3.scenario.as_bytes().to_vec())
    );
    assert_eq!(
        new_char.first_mes,
        Some(data_v3.first_mes.as_bytes().to_vec())
    );
    assert_eq!(
        new_char.mes_example,
        Some(data_v3.mes_example.as_bytes().to_vec())
    );
    assert_eq!(
        new_char.creator_notes,
        Some(data_v3.creator_notes.as_bytes().to_vec())
    );
    assert_eq!(
        new_char.system_prompt,
        Some(data_v3.system_prompt.as_bytes().to_vec())
    );
    assert_eq!(
        new_char.post_history_instructions,
        Some(data_v3.post_history_instructions.as_bytes().to_vec())
    );
    assert_eq!(new_char.tags, Some(vec![Some("v3tag".to_string())]));
    assert_eq!(
        new_char.alternate_greetings,
        Some(vec![Some("v3greet".to_string())])
    );
    assert_eq!(new_char.creator, Some(data_v3.creator));
    assert_eq!(new_char.character_version, Some(data_v3.character_version));
}
