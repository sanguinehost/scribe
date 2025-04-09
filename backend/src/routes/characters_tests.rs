// backend/src/routes/characters_tests.rs
#![cfg(test)]
use super::*; // Access handlers and types from characters.rs
use crate::models::character_card::{CharacterCardV3, Character, NewCharacter};
use crate::routes::characters::{upload_character, list_characters, get_character};
use crate::state::AppState;
use axum::{
    body::Body,
    // extract::{Path, State}, // Unused imports
    http::{self, Request, StatusCode},
    routing::{get, post},
    // Json, // Unused import
    Router,
};
use tower::ServiceExt;
use base64::{engine::general_purpose::STANDARD as base64_standard};
use crc32fast;
use http_body_util::BodyExt;
use mime;
use serde_json::{json, Value};
use std::sync::Arc;
use std::env;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::PgConnection;
use dotenvy;
use crate::schema::characters;
use uuid::Uuid;
// use chrono::Utc; // Unused import
use crate::models::users::{NewUser, User};
use crate::schema::users;
use anyhow::{Error as AnyhowError}; // Removed unused Context
use std::collections::HashSet;
// use diesel::prelude::*; // Unused import

// --- Test Helpers ---

fn create_test_png_with_text_chunk(keyword: &[u8], json_payload: &str) -> Vec<u8> {
    let base64_payload = base64_standard.encode(json_payload);
    let chunk_data = base64_payload.as_bytes();

    let mut png_bytes = Vec::new();
    png_bytes.extend_from_slice(&[137, 80, 78, 71, 13, 10, 26, 10]); // Signature
    // Dummy IHDR
    let ihdr_data = &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0];
    let ihdr_len = (ihdr_data.len() as u32).to_be_bytes();
    png_bytes.extend_from_slice(&ihdr_len);
    let chunk_type_ihdr = b"IHDR";
    png_bytes.extend_from_slice(chunk_type_ihdr);
    png_bytes.extend_from_slice(ihdr_data);
    let crc_ihdr = crc32fast::hash(&[&chunk_type_ihdr[..], &ihdr_data[..]].concat());
    png_bytes.extend_from_slice(&crc_ihdr.to_be_bytes());
    // --- tEXt chunk ---
    let text_chunk_data_internal = [&keyword[..], &[0u8], &chunk_data[..]].concat();
    let text_chunk_len = (text_chunk_data_internal.len() as u32).to_be_bytes();
    png_bytes.extend_from_slice(&text_chunk_len);
    let chunk_type_text = b"tEXt";
    png_bytes.extend_from_slice(chunk_type_text);
    png_bytes.extend_from_slice(&text_chunk_data_internal);
    let crc_text = crc32fast::hash(&[&chunk_type_text[..], &text_chunk_data_internal[..]].concat());
    png_bytes.extend_from_slice(&crc_text.to_be_bytes());
    // Dummy IDAT
    let idat_data = &[8, 29, 99, 96, 0, 0, 0, 3, 0, 1];
    let idat_len = (idat_data.len() as u32).to_be_bytes();
    png_bytes.extend_from_slice(&idat_len);
    let chunk_type_idat = b"IDAT";
    png_bytes.extend_from_slice(chunk_type_idat);
    png_bytes.extend_from_slice(idat_data);
    let crc_idat = crc32fast::hash(&[&chunk_type_idat[..], &idat_data[..]].concat());
    png_bytes.extend_from_slice(&crc_idat.to_be_bytes());
    // IEND
    png_bytes.extend_from_slice(&[0, 0, 0, 0]);
    png_bytes.extend_from_slice(b"IEND");
    png_bytes.extend_from_slice(&[174, 66, 96, 130]);
    png_bytes
}

// Helper function to create a real pool for tests
fn create_test_pool() -> Arc<Pool<ConnectionManager<PgConnection>>> {
    dotenvy::dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set for test pool");
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = Pool::builder()
        .test_on_check_out(true) // Ensure connections are valid
        .max_size(5) // Increased pool size slightly
        .build(manager)
        .expect("Failed to create test DB pool.");
    Arc::new(pool)
}

// Helper to build the app router for testing
fn test_app_router() -> Router {
     let pool = create_test_pool(); // Create a pool for AppState
     let app_state = AppState { pool };

     Router::new()
         .route("/api/characters", post(upload_character))
         .route("/api/characters", get(list_characters))
         .route("/api/characters/:id", get(get_character))
         .with_state(app_state)
}

// Helper struct to manage test data cleanup
struct TestDataGuard {
    pool: Arc<Pool<ConnectionManager<PgConnection>>>,
    user_ids: Vec<Uuid>,
    character_ids: Vec<Uuid>,
}

impl TestDataGuard {
    fn new(pool: Arc<Pool<ConnectionManager<PgConnection>>>) -> Self {
        TestDataGuard { pool, user_ids: Vec::new(), character_ids: Vec::new() }
    }

    fn add_user(&mut self, user_id: Uuid) {
        self.user_ids.push(user_id);
    }

    fn add_character(&mut self, character_id: Uuid) {
        self.character_ids.push(character_id);
    }
}

// Implement Drop to automatically clean up test data
impl Drop for TestDataGuard {
    fn drop(&mut self) {
        if self.character_ids.is_empty() && self.user_ids.is_empty() {
            return;
        }
        println!("--- Cleaning up test data ---");
        let mut conn = self.pool.get().expect("Failed to get DB connection for cleanup");

        if !self.character_ids.is_empty() {
            let delete_chars = diesel::delete(characters::table.filter(characters::id.eq_any(&self.character_ids)))
                .execute(&mut conn);
            if let Err(e) = delete_chars {
                eprintln!("Error cleaning up characters: {:?}", e);
            } else {
                 println!("Cleaned up {} characters.", self.character_ids.len());
            }
        }

        if !self.user_ids.is_empty() {
            // Important: Delete characters associated with the user *before* deleting the user
            // if there's a foreign key constraint. Assuming characters are handled above or cascade.
            let delete_users = diesel::delete(users::table.filter(users::id.eq_any(&self.user_ids)))
                .execute(&mut conn);
             if let Err(e) = delete_users {
                eprintln!("Error cleaning up users: {:?}", e);
            } else {
                 println!("Cleaned up {} users.", self.user_ids.len());
            }
        }
         println!("--- Cleanup complete ---");
    }
}


// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    // use diesel::Connection; // No longer needed for test_transaction

    // --- Upload Tests (Don't need DB setup/cleanup) ---

    #[tokio::test]
    async fn test_upload_valid_v3_card() {
        let app = test_app_router();

        let v3_json = r#"{
            "spec": "chara_card_v3",
            "spec_version": "3.0",
            "data": {
                "name": "Test V3 Upload",
                "description": "Uploaded via API."
            }
        }"#;
        let png_bytes = create_test_png_with_text_chunk(b"ccv3", v3_json);
        let png_base64 = base64_standard.encode(&png_bytes);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/characters")
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(json!({ "png_base64": png_base64 }).to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let card: CharacterCardV3 = serde_json::from_slice(&body).expect("Failed to deserialize response");

        assert_eq!(card.spec, "chara_card_v3");
        assert_eq!(card.data.name, Some("Test V3 Upload".to_string()));
        assert_eq!(card.data.description, "Uploaded via API.");
    }

    #[tokio::test]
    async fn test_upload_valid_v2_card_fallback() {
        let app = test_app_router();

        let v2_json = r#"{
            "name": "Test V2 Upload",
            "first_mes": "Hello from V2!"
        }"#;
        let png_bytes = create_test_png_with_text_chunk(b"chara", v2_json);
        let png_base64 = base64_standard.encode(&png_bytes);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/characters")
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(json!({ "png_base64": png_base64 }).to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let card: CharacterCardV3 = serde_json::from_slice(&body).expect("Failed to deserialize response");

        assert_eq!(card.spec, "chara_card_v2_fallback");
        assert_eq!(card.data.name, Some("Test V2 Upload".to_string()));
        assert_eq!(card.data.first_mes, "Hello from V2!");
    }

    #[tokio::test]
    async fn test_upload_invalid_base64() {
        let app = test_app_router();
        let invalid_base64 = "this is not base64";

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/characters")
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(json!({ "png_base64": invalid_base64 }).to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_upload_not_png() {
        let app = test_app_router();
        let not_png_bytes = b"definitely not a png";
        let not_png_base64 = base64_standard.encode(not_png_bytes);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/characters")
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(json!({ "png_base64": not_png_base64 }).to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_upload_png_no_data_chunk() {
        let app = test_app_router();
        let mut png_bytes = Vec::new();
        png_bytes.extend_from_slice(&[137, 80, 78, 71, 13, 10, 26, 10]); // Signature
        let ihdr_data = &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0];
        let ihdr_len = (ihdr_data.len() as u32).to_be_bytes();
        png_bytes.extend_from_slice(&ihdr_len);
        let chunk_type_ihdr = b"IHDR";
        png_bytes.extend_from_slice(chunk_type_ihdr);
        png_bytes.extend_from_slice(ihdr_data);
        let crc_ihdr = crc32fast::hash(&[&chunk_type_ihdr[..], &ihdr_data[..]].concat());
        png_bytes.extend_from_slice(&crc_ihdr.to_be_bytes());
        let idat_data = &[8, 29, 99, 96, 0, 0, 0, 3, 0, 1];
        let idat_len = (idat_data.len() as u32).to_be_bytes();
        png_bytes.extend_from_slice(&idat_len);
        let chunk_type_idat = b"IDAT";
        png_bytes.extend_from_slice(chunk_type_idat);
        png_bytes.extend_from_slice(idat_data);
        let crc_idat = crc32fast::hash(&[&chunk_type_idat[..], &idat_data[..]].concat());
        png_bytes.extend_from_slice(&crc_idat.to_be_bytes());
        png_bytes.extend_from_slice(&[0, 0, 0, 0]);
        png_bytes.extend_from_slice(b"IEND");
        png_bytes.extend_from_slice(&[174, 66, 96, 130]);

        let png_base64 = base64_standard.encode(&png_bytes);

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/api/characters")
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(json!({ "png_base64": png_base64 }).to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // --- DB Interaction Tests (Manual Setup/Cleanup) ---

    #[tokio::test] // Use tokio test for async setup/call/cleanup
    async fn test_list_characters_manual_cleanup() -> Result<(), AnyhowError> {
        let app = test_app_router();
        let pool = create_test_pool(); // Get pool for direct DB access
        let mut guard = TestDataGuard::new(pool.clone()); // RAII guard for cleanup
        let mut conn = pool.get()?;

        // --- Setup ---
        // Clean potentially conflicting data (optional but safer)
        // Note: Depending on test environment, might not be strictly necessary if DB is clean
        diesel::delete(characters::table).execute(&mut conn)?;
        diesel::delete(users::table).execute(&mut conn)?;

        let test_user = diesel::insert_into(users::table)
            .values(NewUser {
                username: format!("list_user_{}", Uuid::new_v4()),
                password_hash: "test_hash",
            })
            .get_result::<User>(&mut conn)?;
        guard.add_user(test_user.id); // Register user for cleanup

        let character_data = vec![
            NewCharacter { user_id: test_user.id, name: "List Character 1".to_string(), ..Default::default() },
            NewCharacter { user_id: test_user.id, name: "List Character 2".to_string(), ..Default::default() },
        ];
        let inserted_characters: Vec<Character> = diesel::insert_into(characters::table)
            .values(&character_data)
            .get_results(&mut conn)?;
        assert_eq!(inserted_characters.len(), 2);
        for char in &inserted_characters {
            guard.add_character(char.id); // Register characters for cleanup
        }

        // --- API Call ---
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/api/characters")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await?;

        // --- Assertions ---
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await?.to_bytes();
        let characters_from_api: Vec<Character> = serde_json::from_slice(&body)?;

        // Filter API results to only include characters created in this test run
        let inserted_ids: HashSet<Uuid> = inserted_characters.iter().map(|c| c.id).collect();
        let relevant_characters_from_api: Vec<&Character> = characters_from_api
            .iter()
            .filter(|c| inserted_ids.contains(&c.id))
            .collect();

        assert_eq!(relevant_characters_from_api.len(), inserted_characters.len(), "API returned wrong number of *test* characters");
        let api_names: HashSet<String> = relevant_characters_from_api.iter().map(|c| c.name.clone()).collect();
        let inserted_names: HashSet<String> = inserted_characters.iter().map(|c| c.name.clone()).collect();
        assert_eq!(api_names, inserted_names, "API character names do not match inserted names");

        Ok(()) // Test passes, cleanup happens when guard goes out of scope
    }

    #[tokio::test] // Use tokio test for async setup/call/cleanup
    async fn test_get_character_manual_cleanup() -> Result<(), AnyhowError> {
        let app = test_app_router();
        let pool = create_test_pool();
        let mut guard = TestDataGuard::new(pool.clone());
        let mut conn = pool.get()?;

        // --- Setup ---
        diesel::delete(characters::table).execute(&mut conn)?;
        diesel::delete(users::table).execute(&mut conn)?;

        let test_user = diesel::insert_into(users::table)
            .values(NewUser {
                username: format!("get_user_{}", Uuid::new_v4()),
                password_hash: "test_hash",
            })
            .get_result::<User>(&mut conn)?;
        guard.add_user(test_user.id);

        let new_character = NewCharacter {
            user_id: test_user.id,
            name: "Get Test Character".to_string(),
            description: Some("A character to get".to_string()),
            ..Default::default()
        };
        let inserted_character: Character = diesel::insert_into(characters::table)
            .values(new_character)
            .get_result(&mut conn)?;
        guard.add_character(inserted_character.id);

        // --- API Call ---
        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/api/characters/{}", inserted_character.id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await?;

        // --- Assertions ---
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await?.to_bytes();
        let character_from_api: Character = serde_json::from_slice(&body)?;

        assert_eq!(character_from_api.id, inserted_character.id);
        assert_eq!(character_from_api.name, inserted_character.name);
        assert_eq!(character_from_api.description, inserted_character.description);

        Ok(()) // Test passes, cleanup happens when guard goes out of scope
    }

    // Test for non-existent character (doesn't need DB setup/cleanup)
    #[tokio::test]
    async fn test_get_nonexistent_character() {
        let app = test_app_router();

        let nonexistent_id = Uuid::new_v4();
        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("/api/characters/{}", nonexistent_id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let error: Value = serde_json::from_slice(&body).expect("Failed to deserialize error response");
        assert_eq!(error["error"], "Character not found");
    }
}