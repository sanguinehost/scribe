// backend/src/routes/characters_tests.rs 
use super::*; // Access handlers and types from characters.rs
use crate::{models::character_card::CharacterCardV3, routes, services::character_parser}; // Need full paths sometimes
use axum::{routing::post, Router, body::Body, http::{self, Request, StatusCode}};
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use crc32fast; // For test PNG helper
use http_body_util::BodyExt; // for response.body().collect()
use serde_json::json;
use std::net::{SocketAddr, TcpListener};
use tower::ServiceExt; // for oneshot

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
fn test_app() -> Router {
     Router::new()
         .route("/api/characters", post(upload_character))
         // Add other character routes here if testing them
         // .route("/api/characters", get(list_characters))
         // .route("/api/characters/:id", get(get_character))
}

// --- Tests for POST /api/characters --- 

#[tokio::test]
async fn test_upload_valid_v3_card() {
    let app = test_app();

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

    let response = app
        .oneshot(Request::builder()
            .method(http::Method::POST)
            .uri("/api/characters")
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(json!({ "png_base64": png_base64 }).to_string()))
            .unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let card: CharacterCardV3 = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert_eq!(card.spec, "chara_card_v3");
    assert_eq!(card.data.name, Some("Test V3 Upload".to_string()));
    assert_eq!(card.data.description, "Uploaded via API.");
}

#[tokio::test]
async fn test_upload_valid_v2_card_fallback() {
     let app = test_app();

    let v2_json = r#"{
        "name": "Test V2 Upload",
        "first_mes": "Hello from V2!"
    }"#;
    let png_bytes = create_test_png_with_text_chunk(b"chara", v2_json);
    let png_base64 = base64_standard.encode(&png_bytes);

    let response = app
        .oneshot(Request::builder()
            .method(http::Method::POST)
            .uri("/api/characters")
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(json!({ "png_base64": png_base64 }).to_string()))
            .unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let card: CharacterCardV3 = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert_eq!(card.spec, "chara_card_v2_fallback"); // Check fallback spec
    assert_eq!(card.data.name, Some("Test V2 Upload".to_string()));
    assert_eq!(card.data.first_mes, "Hello from V2!");
}

#[tokio::test]
async fn test_upload_invalid_base64() {
    let app = test_app();
    let invalid_base64 = "this is not base64";

    let response = app
        .oneshot(Request::builder()
            .method(http::Method::POST)
            .uri("/api/characters")
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(json!({ "png_base64": invalid_base64 }).to_string()))
            .unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    // TODO: Check error message in body
}

#[tokio::test]
async fn test_upload_not_png() {
     let app = test_app();
    let not_png_bytes = b"definitely not a png";
    let not_png_base64 = base64_standard.encode(not_png_bytes);

     let response = app
        .oneshot(Request::builder()
            .method(http::Method::POST)
            .uri("/api/characters")
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(json!({ "png_base64": not_png_base64 }).to_string()))
            .unwrap())
        .await
        .unwrap();

     assert_eq!(response.status(), StatusCode::BAD_REQUEST);
     // Should result in a PngError from the parser
     // TODO: Check error message in body
}

#[tokio::test]
async fn test_upload_png_no_data_chunk() {
    let app = test_app();
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

    let response = app
        .oneshot(Request::builder()
            .method(http::Method::POST)
            .uri("/api/characters")
            .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(json!({ "png_base64": png_base64 }).to_string()))
            .unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    // Should result in ChunkNotFound from the parser
    // TODO: Check error message in body
} 