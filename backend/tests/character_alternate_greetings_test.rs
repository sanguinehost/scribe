// Test for alternate greetings parsing and conversion
use scribe_backend::models::character_card::{CharacterCardDataV3, CharacterCardV3, NewCharacter};
use scribe_backend::services::character_parser::ParsedCharacterCard;
use uuid::Uuid;

#[test]
fn test_alternate_greetings_v3_conversion() {
    // Create a V3 character card with alternate greetings
    let test_greetings = vec![
        "Hey there!".to_string(),
        "What's up?".to_string(),
        "Good morning!".to_string(),
    ];

    let card_data = CharacterCardDataV3 {
        name: Some("Test Character".to_string()),
        description: "A test character".to_string(),
        first_mes: "Hello!".to_string(),
        alternate_greetings: test_greetings.clone(),
        ..Default::default()
    };

    let card = CharacterCardV3 {
        spec: "chara_card_v3".to_string(),
        spec_version: "3.0".to_string(),
        data: card_data,
        ..Default::default()
    };

    let parsed_card = ParsedCharacterCard::V3(card);
    let user_id = Uuid::new_v4();

    // Convert to NewCharacter
    let new_character = NewCharacter::from_parsed_card(&parsed_card, user_id);

    // Check that alternate_greetings are properly converted
    assert!(new_character.alternate_greetings.is_some());
    let db_greetings = new_character.alternate_greetings.unwrap();

    // Should be Option<Vec<Option<String>>> format for database
    assert_eq!(db_greetings.len(), 3);
    assert_eq!(db_greetings[0], Some("Hey there!".to_string()));
    assert_eq!(db_greetings[1], Some("What's up?".to_string()));
    assert_eq!(db_greetings[2], Some("Good morning!".to_string()));

    println!("✓ Alternate greetings correctly converted from V3 to NewCharacter");
}

#[test]
fn test_alternate_greetings_v2_fallback_conversion() {
    // Create a V2 fallback with alternate greetings
    let test_greetings = vec!["Hi!".to_string(), "Greetings!".to_string()];

    let card_data = CharacterCardDataV3 {
        name: Some("Test V2 Character".to_string()),
        description: "A test V2 character".to_string(),
        first_mes: "Hello from V2!".to_string(),
        alternate_greetings: test_greetings.clone(),
        ..Default::default()
    };

    let parsed_card = ParsedCharacterCard::V2Fallback(card_data);
    let user_id = Uuid::new_v4();

    // Convert to NewCharacter
    let new_character = NewCharacter::from_parsed_card(&parsed_card, user_id);

    // Check that alternate_greetings are properly converted
    assert!(new_character.alternate_greetings.is_some());
    let db_greetings = new_character.alternate_greetings.unwrap();

    // Should be Option<Vec<Option<String>>> format for database
    assert_eq!(db_greetings.len(), 2);
    assert_eq!(db_greetings[0], Some("Hi!".to_string()));
    assert_eq!(db_greetings[1], Some("Greetings!".to_string()));

    println!("✓ Alternate greetings correctly converted from V2 fallback to NewCharacter");
}

#[test]
fn test_empty_alternate_greetings_conversion() {
    // Create a character card with empty alternate greetings
    let card_data = CharacterCardDataV3 {
        name: Some("Test Character".to_string()),
        description: "A test character".to_string(),
        first_mes: "Hello!".to_string(),
        alternate_greetings: vec![], // Empty
        ..Default::default()
    };

    let card = CharacterCardV3 {
        spec: "chara_card_v3".to_string(),
        spec_version: "3.0".to_string(),
        data: card_data,
        ..Default::default()
    };

    let parsed_card = ParsedCharacterCard::V3(card);
    let user_id = Uuid::new_v4();

    // Convert to NewCharacter
    let new_character = NewCharacter::from_parsed_card(&parsed_card, user_id);

    // Check that empty alternate_greetings results in None
    assert!(new_character.alternate_greetings.is_none());

    println!("✓ Empty alternate greetings correctly converted to None");
}
