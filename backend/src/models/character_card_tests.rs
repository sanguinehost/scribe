// This file will contain tests for character_card.rs 

use super::*; // Import items from the parent module (character_card.rs)

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
    assert!(card.is_ok(), "Failed to deserialize minimal card: {:?}", card.err());
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
                "name": "World Facts",
                "entries": [
                    {
                        "keys": ["capital", "france"],
                        "content": "The capital of France is Paris.",
                        "enabled": true,
                        "insertion_order": 10,
                        "use_regex": false
                    },
                     {
                        "keys": ["\\d+ ducks"],
                        "content": "That's a lot of ducks!",
                        "enabled": true,
                        "insertion_order": 5,
                        "use_regex": true,
                        "case_sensitive": false,
                        "priority": 100,
                        "id": 12345,
                        "comment": "Reacts to ducks"
                    }
                ]
            }
        }
    }"#;
    let card: Result<CharacterCardV3, _> = serde_json::from_str(json_data);
     assert!(card.is_ok(), "Failed to deserialize card with lorebook: {:?}", card.err());
     let card = card.unwrap();
     assert!(card.data.character_book.is_some());
     let book = card.data.character_book.unwrap();
     assert_eq!(book.name.unwrap(), "World Facts");
     assert_eq!(book.entries.len(), 2);
     assert_eq!(book.entries[0].keys, vec!["capital".to_string(), "france".to_string()]);
     assert_eq!(book.entries[0].content, "The capital of France is Paris.");
     assert!(book.entries[0].enabled);
     assert_eq!(book.entries[0].insertion_order, 10);
     assert!(!book.entries[0].use_regex); // use_regex default is false.

     assert_eq!(book.entries[1].keys, vec![r"\d+ ducks".to_string()]);
     assert!(book.entries[1].use_regex);
     assert_eq!(book.entries[1].case_sensitive, Some(false));
     assert_eq!(book.entries[1].priority, Some(100));
     assert!(book.entries[1].id.is_some());
     assert_eq!(book.entries[1].id.clone().unwrap().as_i64().unwrap(), 12345); // Check ID is number
     assert_eq!(book.entries[1].comment.clone().unwrap(), "Reacts to ducks");
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
     assert!(card.is_ok(), "Failed to deserialize card with assets: {:?}", card.err());
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
    assert!(card.is_ok(), "Failed to deserialize card with missing defaults: {:?}", card.err());
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