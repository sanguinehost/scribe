// backend/src/routes/characters_tests.rs 
#![cfg(test)]
use super::*; // Access handlers and types from characters.rs
use crate::models::character_card::{CharacterCardV3}; // Removed routes, services::character_parser
use crate::routes::characters::{upload_character};
use crate::state::AppState;
use axum::{
    body::Body,
    http::{self, Request, StatusCode},
    routing::{post},
    Router, routing::future::RouteFuture, // Import RouteFuture
};
use base64::{engine::general_purpose::STANDARD as base64_standard};
use crc32fast; // For test PNG helper
use http_body_util::BodyExt; // for response.body().collect()
use mime;
use serde_json::json;
use std::sync::Arc; // Import std::sync::Arc for Arc type
use std::convert::Infallible; // Import Infallible for RouteFuture
use std::env; // Import std::env for env::var
use tower::Service; // Explicitly import base trait for resolution
use diesel::r2d2::{ConnectionManager, Pool}; // Import necessary DB items for state creation
use diesel::PgConnection;
use dotenvy; // Import dotenvy for .env file loading

// --- Test Helpers ---

// Helper to create a minimal valid PNG with a tEXt chunk (copied from parser tests)
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

// Helper to build the app router for testing
fn test_app() -> Router { // Router<()> implements Service
     // Set up a dummy database connection pool for the test state
     // This likely won't connect, but satisfies the type requirement for AppState
     // Ensure DATABASE_URL is set in a .env file or environment for this not to panic
     // Alternatively, handle the error more gracefully if needed for tests that *don't* need DB
     dotenvy::dotenv().ok(); // Load .env if present
     let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "postgresql://dummy:dummy@localhost/test".to_string());
     let manager = ConnectionManager::<PgConnection>::new(database_url);
     // Use a small pool size for tests
     let pool = Pool::builder()
         .max_size(1)
         .build(manager)
         .expect("Failed to create dummy DB pool for test.");

     let app_state = AppState { pool: Arc::new(pool) };

     Router::new()
         .route("/api/characters", post(upload_character))
         .with_state(app_state) // Provide the state
         // Add other character routes here if testing them
         // .route("/api/characters", get(list_characters))
         // .route("/api/characters/:id", get(get_character))
}

// --- Tests for POST /api/characters --- 

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_upload_valid_v3_card() {
        let mut app = test_app(); // Use Router directly, make mutable for call()

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

        let future: RouteFuture<Infallible> = app.call(request); // Explicit type annotation
        let response = future.await.unwrap(); // Await the future

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let card: CharacterCardV3 = serde_json::from_slice(&body).expect("Failed to deserialize response");

        assert_eq!(card.spec, "chara_card_v3");
        assert_eq!(card.data.name, Some("Test V3 Upload".to_string()));
        assert_eq!(card.data.description, "Uploaded via API.");
    }

    #[tokio::test]
    async fn test_upload_valid_v2_card_fallback() {
         let mut app = test_app(); // Use Router directly, make mutable for call()

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

        let future: RouteFuture<Infallible> = app.call(request); // Explicit type annotation
        let response = future.await.unwrap(); // Await the future

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let card: CharacterCardV3 = serde_json::from_slice(&body).expect("Failed to deserialize response");

        assert_eq!(card.spec, "chara_card_v2_fallback"); // Check fallback spec
        assert_eq!(card.data.name, Some("Test V2 Upload".to_string()));
        assert_eq!(card.data.first_mes, "Hello from V2!");
    }

    #[tokio::test]
    async fn test_upload_invalid_base64() {
        let mut app = test_app(); // Use Router directly, make mutable for call()
        let invalid_base64 = "this is not base64";

         let request = Request::builder()
                .method(http::Method::POST)
                .uri("/api/characters")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(json!({ "png_base64": invalid_base64 }).to_string()))
                .unwrap();

        let future: RouteFuture<Infallible> = app.call(request); // Explicit type annotation
        let response = future.await.unwrap(); // Await the future

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        // TODO: Check error message in body
    }

    #[tokio::test]
    async fn test_upload_not_png() {
         let mut app = test_app(); // Use Router directly, make mutable for call()
        let not_png_bytes = b"definitely not a png";
        let not_png_base64 = base64_standard.encode(not_png_bytes);

         let request = Request::builder()
                .method(http::Method::POST)
                .uri("/api/characters")
                .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                .body(Body::from(json!({ "png_base64": not_png_base64 }).to_string()))
                .unwrap();

         let future: RouteFuture<Infallible> = app.call(request); // Explicit type annotation
         let response = future.await.unwrap(); // Await the future

         assert_eq!(response.status(), StatusCode::BAD_REQUEST);
         // Should result in a PngError from the parser
         // TODO: Check error message in body
    }

    #[tokio::test]
    async fn test_upload_png_no_data_chunk() {
        let mut app = test_app(); // Use Router directly, make mutable for call()
        // Create a valid PNG structure but without ccv3 or chara tEXt chunks
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

        let future: RouteFuture<Infallible> = app.call(request); // Explicit type annotation
        let response = future.await.unwrap(); // Await the future

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        // Should result in ChunkNotFound from the parser
        // TODO: Check error message in body
    } 
} 