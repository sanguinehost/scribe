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

// --- Tests for parse_decorators_from_content ---

#[test]
fn test_parse_decorators_no_decorators() {
    let content = "This is normal content.\nWith multiple lines.";
    let (decorators, processed_content) = parse_decorators_from_content(content);
    assert!(decorators.is_empty());
    assert_eq!(processed_content, content);
}

#[test]
fn test_parse_decorators_simple() {
    let content = "@@role system\n@@position after_desc\nActual content here.";
    let (decorators, processed_content) = parse_decorators_from_content(content);
    assert_eq!(decorators.len(), 2);
    assert_eq!(decorators[0].name, "role");
    assert_eq!(decorators[0].value, Some("system".to_string()));
    assert!(decorators[0].fallbacks.is_empty());
    assert_eq!(decorators[1].name, "position");
    assert_eq!(decorators[1].value, Some("after_desc".to_string()));
    assert!(decorators[1].fallbacks.is_empty());
    assert_eq!(processed_content, "Actual content here.");
}

#[test]
fn test_parse_decorators_no_value() {
    let content = "@@enabled\nContent line.";
    let (decorators, processed_content) = parse_decorators_from_content(content);
    assert_eq!(decorators.len(), 1);
    assert_eq!(decorators[0].name, "enabled");
    assert_eq!(decorators[0].value, None);
    assert!(decorators[0].fallbacks.is_empty());
    assert_eq!(processed_content, "Content line.");
}

#[test]
fn test_parse_decorators_with_fallbacks() {
    let content = "@@name Character Name\n@@@nombre Nombre del Personaje\n@@@nom Nom du Personnage\nDescription starts here.";
    let (decorators, processed_content) = parse_decorators_from_content(content);
    assert_eq!(decorators.len(), 1);
    let main_decorator = &decorators[0];
    assert_eq!(main_decorator.name, "name");
    assert_eq!(main_decorator.value, Some("Character Name".to_string()));
    assert_eq!(main_decorator.fallbacks.len(), 2);
    assert_eq!(main_decorator.fallbacks[0].name, "nombre");
    assert_eq!(main_decorator.fallbacks[0].value, Some("Nombre del Personaje".to_string()));
    assert!(main_decorator.fallbacks[0].fallbacks.is_empty());
    assert_eq!(main_decorator.fallbacks[1].name, "nom");
    assert_eq!(main_decorator.fallbacks[1].value, Some("Nom du Personnage".to_string()));
    assert!(main_decorator.fallbacks[1].fallbacks.is_empty());
    assert_eq!(processed_content, "Description starts here.");
}

#[test]
fn test_parse_decorators_mixed_content() {
    let content = "Line 1\n@@decorator1 value1\nLine 2\n@@decorator2\n@@@fallback2 val_fb\nLine 3";
    let (decorators, processed_content) = parse_decorators_from_content(content);
    assert_eq!(decorators.len(), 2);
    assert_eq!(decorators[0].name, "decorator1");
    assert_eq!(decorators[0].value, Some("value1".to_string()));
    assert!(decorators[0].fallbacks.is_empty());
    assert_eq!(decorators[1].name, "decorator2");
    assert_eq!(decorators[1].value, None);
    assert_eq!(decorators[1].fallbacks.len(), 1);
    assert_eq!(decorators[1].fallbacks[0].name, "fallback2");
    assert_eq!(decorators[1].fallbacks[0].value, Some("val_fb".to_string()));
    assert_eq!(processed_content, "Line 1\nLine 2\nLine 3");
}

#[test]
fn test_parse_decorators_invalid_lines() {
    let content = "Line 1\n@@\n@@@ \n@@ name value\n@@@fallback val\n  @@@ invalid_fallback\nLine 2";
    let (decorators, processed_content) = parse_decorators_from_content(content);
    assert_eq!(decorators.len(), 1); // Only the valid "@@ name value" should be parsed
    assert_eq!(decorators[0].name, "name");
    assert_eq!(decorators[0].value, Some("value".to_string()));
    assert_eq!(decorators[0].fallbacks.len(), 1); // Only the valid "@@@fallback val"
    assert_eq!(decorators[0].fallbacks[0].name, "fallback");
    assert_eq!(decorators[0].fallbacks[0].value, Some("val".to_string()));
    // Invalid lines should be treated as content
    assert_eq!(processed_content, "Line 1\n@@\n@@@ \n  @@@ invalid_fallback\nLine 2");
}

#[test]
fn test_parse_decorators_whitespace_handling() {
    let content = "  @@ spaced_name   spaced value  \n\t@@@ spaced_fallback \t spaced_fb_value \t\nContent";
    let (decorators, processed_content) = parse_decorators_from_content(content);
    assert_eq!(decorators.len(), 1);
    assert_eq!(decorators[0].name, "spaced_name");
    assert_eq!(decorators[0].value, Some("spaced value".to_string()));
    assert_eq!(decorators[0].fallbacks.len(), 1);
    assert_eq!(decorators[0].fallbacks[0].name, "spaced_fallback");
    assert_eq!(decorators[0].fallbacks[0].value, Some("spaced_fb_value".to_string()));
    assert_eq!(processed_content, "Content");
}

#[test]
fn test_parse_decorators_empty_content() {
    let content = "";
    let (decorators, processed_content) = parse_decorators_from_content(content);
    assert!(decorators.is_empty());
    assert_eq!(processed_content, "");
}

#[test]
fn test_parse_decorators_only_decorators() {
    let content = "@@d1 v1\n@@@f1 vf1\n@@d2";
    let (decorators, processed_content) = parse_decorators_from_content(content);
    assert_eq!(decorators.len(), 2);
    assert_eq!(decorators[0].name, "d1");
    assert_eq!(decorators[0].value, Some("v1".to_string()));
    assert_eq!(decorators[0].fallbacks.len(), 1);
    assert_eq!(decorators[1].name, "d2");
    assert_eq!(decorators[1].value, None);
    assert!(decorators[1].fallbacks.is_empty());
    assert_eq!(processed_content, ""); // Content should be empty
}

#[test]
fn test_parse_decorators_fallback_without_main() {
     let content = "Line 1\n@@@fallback value\nLine 2";
     let (decorators, processed_content) = parse_decorators_from_content(content);
     assert!(decorators.is_empty()); // Fallback without main is treated as content
     assert_eq!(processed_content, content);
}

#[test]
fn test_parse_decorators_edge_cases() {
    // Test @@ followed by nothing or whitespace
    let content1 = "@@\nContent";
    let (decorators1, processed_content1) = parse_decorators_from_content(content1);
    assert!(decorators1.is_empty());
    assert_eq!(processed_content1, "@@\nContent"); // Should be treated as content

    let content2 = "@@ \nContent";
    let (decorators2, processed_content2) = parse_decorators_from_content(content2);
    assert!(decorators2.is_empty());
    assert_eq!(processed_content2, "@@ \nContent"); // Should be treated as content

    // Test @@@ followed by nothing or whitespace
    let content3 = "@@main val\n@@@\nContent";
    let (decorators3, processed_content3) = parse_decorators_from_content(content3);
    assert_eq!(decorators3.len(), 1);
    assert!(decorators3[0].fallbacks.is_empty());
    assert_eq!(processed_content3, "@@@\nContent"); // @@@ treated as content

    let content4 = "@@main val\n@@@ \nContent";
    let (decorators4, processed_content4) = parse_decorators_from_content(content4);
     assert_eq!(decorators4.len(), 1);
    assert!(decorators4[0].fallbacks.is_empty());
    assert_eq!(processed_content4, "@@@ \nContent"); // @@@ treated as content

    // Test @@@ fallback_name (no value) with leading whitespace
    let content5 = "@@main val\n  @@@fallback_no_val\nContent";
    let (decorators5, processed_content5) = parse_decorators_from_content(content5);
    assert_eq!(decorators5.len(), 1);
    assert!(decorators5[0].fallbacks.is_empty()); // Fallback treated as content due to whitespace + no value
    assert_eq!(processed_content5, "  @@@fallback_no_val\nContent");

     // Test @@@ with empty name
    let content6 = "@@main val\n@@@ \nContent"; // Already tested by content4, but re-verify logic
    let (decorators6, processed_content6) = parse_decorators_from_content(content6);
    assert_eq!(decorators6.len(), 1);
    assert!(decorators6[0].fallbacks.is_empty());
    assert_eq!(processed_content6, "@@@ \nContent");

    // Test @@ with empty name
    let content7 = "@@ \nContent"; // Already tested by content2, but re-verify logic
    let (decorators7, processed_content7) = parse_decorators_from_content(content7);
    assert!(decorators7.is_empty());
    assert_eq!(processed_content7, "@@ \nContent");
}

// --- Tests for NewCharacter::from_parsed_card ---

// Helper function to create a minimal ParsedCharacterCard::V2Fallback
// Need to import ParsedCharacterCard and CharacterCardDataV3 from the parent module if not already done
use crate::services::character_parser::ParsedCharacterCard; // Assuming this path is correct
use crate::models::character_card::CharacterCardDataV3; // Assuming this path is correct
use uuid::Uuid; // Need Uuid for user_id

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
    assert_eq!(new_char.spec, "chara_card_v2_fallback");
    assert_eq!(new_char.spec_version, "2.0");
    assert!(new_char.tags.is_none()); // Should be None when empty
    assert!(new_char.alternate_greetings.is_none()); // Should be None when empty
    assert!(new_char.description.is_none()); // Default empty string becomes None
}

#[test]
fn test_from_parsed_card_v2_with_collections() {
     let user_id = Uuid::new_v4();
     let data_v2 = CharacterCardDataV3 { // Removed mut, not needed
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
     assert_eq!(new_char.spec, "chara_card_v2_fallback");
     assert_eq!(new_char.spec_version, "2.0");
     assert_eq!(new_char.tags, Some(vec![Some("tag1".to_string()), Some("tag2".to_string())]));
     assert_eq!(new_char.alternate_greetings, Some(vec![Some("hi".to_string())]));
     assert_eq!(new_char.description, Some("A description".to_string()));
}

// Add a test for V3 conversion as well for completeness
#[test]
fn test_from_parsed_card_v3() {
    let user_id = Uuid::new_v4();
    let card_v3 = CharacterCardV3 {
        spec: "chara_card_v3".to_string(),
        spec_version: "3.0".to_string(),
        data: CharacterCardDataV3 {
            name: Some("V3 Test Convert".to_string()),
            description: "V3 Desc".to_string(),
            tags: vec!["v3tag".to_string()],
            alternate_greetings: vec![], // Empty greetings
            creation_date: Some(1700000000),
            modification_date: None,
            creator_notes_multilingual: Some([("es".to_string(), "nota".to_string())].iter().cloned().collect()),
            ..Default::default()
        }
    };
    let parsed_v3 = ParsedCharacterCard::V3(card_v3);
    let new_char = NewCharacter::from_parsed_card(&parsed_v3, user_id);

    assert_eq!(new_char.user_id, user_id);
    assert_eq!(new_char.name, "V3 Test Convert");
    assert_eq!(new_char.spec, "chara_card_v3");
    assert_eq!(new_char.spec_version, "3.0");
    assert_eq!(new_char.description, Some("V3 Desc".to_string()));
    assert_eq!(new_char.tags, Some(vec![Some("v3tag".to_string())]));
    assert!(new_char.alternate_greetings.is_none()); // Empty vec becomes None
    assert!(new_char.creation_date.is_some());
    assert!(new_char.modification_date.is_none());
    assert!(new_char.creator_notes_multilingual.is_some());
    let notes_json = new_char.creator_notes_multilingual.unwrap();
    assert_eq!(notes_json.get("es").unwrap().as_str().unwrap(), "nota");
}