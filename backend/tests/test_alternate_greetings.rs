// Test script to verify alternate_greetings parsing
use serde_json::json;

fn main() {
    // Test data with alternate greetings
    let test_json = json!({
        "spec": "chara_card_v3",
        "spec_version": "3.0",
        "data": {
            "name": "Test Character",
            "description": "A test character",
            "first_mes": "Hello there!",
            "alternate_greetings": ["Hey!", "What's up?", "Good morning!"]
        }
    });

    println!("Test JSON: {}", serde_json::to_string_pretty(&test_json).unwrap());
    
    // Test parsing with our character card structure
    let card_result: Result<sanguine_scribe_backend::models::character_card::CharacterCardV3, _> = 
        serde_json::from_value(test_json);
    
    match card_result {
        Ok(card) => {
            println!("Parsing successful!");
            println!("Character name: {:?}", card.data.name);
            println!("Alternate greetings: {:?}", card.data.alternate_greetings);
        },
        Err(e) => {
            println!("Parsing failed: {}", e);
        }
    }
}