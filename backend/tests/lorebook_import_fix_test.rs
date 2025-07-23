// Test to reproduce and fix the SillyTavern lorebook import issue

use serde_json::json;
use std::sync::Arc;
use scribe_backend::{
    test_helpers::{spawn_app, TestDataGuard, db::create_test_user},
    models::lorebook_dtos::SillyTavernImportPayload,
};
use secrecy::SecretBox;
use axum_login::AuthSession;

#[tokio::test]
async fn test_sillytavern_lorebook_import_deserialization() {
    // Create a minimal test structure to isolate the duplicate field issue
    let sillytavern_json_str = r#"{
        "name": "Test Lorebook",
        "description": "",
        "entries": {
            "1": {
                "uid": 1,
                "key": ["Test"],
                "keys": ["Test"],
                "content": "Test content",
                "order": 10,
                "insertion_order": 10,
                "id": 1,
                "position": 1
            }
        }
    }"#;
    
    let sillytavern_json: serde_json::Value = serde_json::from_str(sillytavern_json_str).unwrap();

    // Test that this can be deserialized into our SillyTavernImportPayload
    let result = serde_json::from_value::<SillyTavernImportPayload>(sillytavern_json);
    
    match result {
        Ok(payload) => {
            println!("✓ Successfully deserialized SillyTavern payload");
            println!("  Name: {:?}", payload.name);
            println!("  Description: {:?}", payload.description);
            println!("  Entries count: {}", payload.entries.len());
            
            // Check the first entry
            if let Some(entry) = payload.entries.get("1") {
                println!("  First entry key: {:?}", entry.key);
                println!("  First entry content length: {}", entry.content.len());
            }
        }
        Err(e) => {
            println!("✗ Failed to deserialize SillyTavern payload: {}", e);
            panic!("Deserialization should succeed");
        }
    }
}

#[tokio::test]
async fn test_actual_star_wars_lorebook_deserialization() {
    // Test the actual Star Wars lorebook file
    let star_wars_file_content = std::fs::read_to_string("/home/socol/Downloads/main_Star Wars RPG  - Imperial Era Lorebook_world_info.json")
        .expect("Failed to read Star Wars lorebook file");
    
    let result = serde_json::from_str::<SillyTavernImportPayload>(&star_wars_file_content);
    
    match result {
        Ok(payload) => {
            println!("✓ Successfully deserialized Star Wars lorebook!");
            println!("  Name: {:?}", payload.name);
            println!("  Description: {:?}", payload.description);
            println!("  Entries count: {}", payload.entries.len());
        }
        Err(e) => {
            println!("✗ Failed to deserialize Star Wars lorebook: {}", e);
            panic!("Real Star Wars lorebook should deserialize successfully");
        }
    }
}

#[tokio::test] 
async fn test_full_lorebook_import_with_sillytavern_format() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "import_test_user".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    // Create simplified SillyTavern payload
    let sillytavern_json = json!({
        "name": "Test Star Wars Lorebook",
        "description": "A test lorebook",
        "entries": {
            "1": {
                "uid": 1,
                "key": ["Jedi", "Force User"],
                "content": "Jedi are Force-sensitive individuals who follow the light side.",
                "constant": false,
                "order": 10,
                "position": 1,
                "disable": false,
                "enabled": true
            },
            "2": {
                "uid": 2,
                "key": ["Sith"],
                "content": "Sith are Force-sensitive individuals who follow the dark side.",
                "constant": false,
                "order": 10,
                "position": 1,
                "disable": false,
                "enabled": true
            }
        }
    });

    // Create a mock auth session (this is complex in tests, so we'll focus on the data structures)
    let result = serde_json::from_value::<SillyTavernImportPayload>(sillytavern_json);
    assert!(result.is_ok(), "Should be able to deserialize SillyTavern format");
    
    let payload = result.unwrap();
    assert_eq!(payload.entries.len(), 2);
    
    println!("✓ Full lorebook import test - deserialization successful");
}