// backend/src/routes/characters.rs
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::sync::Arc;
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};

use crate::models::character_card::CharacterCardV3;
use crate::services::character_parser::{parse_character_card_png, ParserError};

// Shared application state (if needed later, e.g., for DB pool)
// type AppState = Arc<()>; // Placeholder

// --- Upload Handler --- 
#[derive(Deserialize, Debug)]
pub struct UploadPayload {
    // How will the PNG data be sent? Base64 string? Raw bytes?
    // Let's assume raw bytes for now via axum::body::Bytes
    // Or potentially multipart form data using axum::extract::Multipart
    // For simplicity in this step, let's assume base64 string in JSON
    png_base64: String,
}

pub async fn upload_character(
    // State(state): State<AppState>, // Uncomment when state is needed
    Json(payload): Json<UploadPayload>,
) -> Result<Json<CharacterCardV3>, UploadError> {
    // 1. Decode base64
    let png_bytes = base64_standard.decode(&payload.png_base64)?;

    // 2. Call parser
    let card_data = parse_character_card_png(&png_bytes)?;

    // 3. (Later) Save metadata to DB
    println!("Successfully parsed character: {}", card_data.data.name.as_deref().unwrap_or("Unnamed"));

    // 4. Return parsed card data
    Ok(Json(card_data))
}

// --- List Handler --- 
pub async fn list_characters(
    // State(state): State<AppState>, // Uncomment when state is needed
) -> Result<Json<Vec<()>>, UploadError> { // Return type is placeholder
    // 1. (Later) Get user ID from auth
    // 2. (Later) Query DB for characters associated with user
    // 3. Return list (metadata only initially)
    unimplemented!("List logic not implemented")
}

// --- Get Handler --- 
pub async fn get_character(
    // State(state): State<AppState>, // Uncomment when state is needed
    Path(character_id): Path<i32>, // Assuming i32 is the ID type
) -> Result<Json<()>, UploadError> { // Return type is placeholder
     // 1. (Later) Get user ID from auth
     // 2. (Later) Query DB for character with ID, ensuring ownership/access rights
     // 3. Return full character details
    unimplemented!("Get logic not implemented")
}

// --- Error Handling for Routes --- 
#[derive(Debug)]
pub enum UploadError {
    Base64Decode(base64::DecodeError),
    Parse(ParserError),
    // DatabaseError(sqlx::Error), // Example for later
    // Unauthorized,
    // NotFound,
}

impl From<base64::DecodeError> for UploadError {
    fn from(err: base64::DecodeError) -> Self {
        UploadError::Base64Decode(err)
    }
}

impl From<ParserError> for UploadError {
    fn from(err: ParserError) -> Self {
        UploadError::Parse(err)
    }
}

impl IntoResponse for UploadError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            UploadError::Base64Decode(e) => {
                println!("Base64 decode error: {}", e);
                (StatusCode::BAD_REQUEST, "Invalid base64 data for PNG".to_string())
            }
            UploadError::Parse(ParserError::ChunkNotFound) => {
                 println!("Parser error: Chunk not found");
                (StatusCode::BAD_REQUEST, "Character data not found in PNG".to_string())
            }
             UploadError::Parse(ParserError::InvalidTextChunkFormat) => {
                 println!("Parser error: Invalid tEXt chunk");
                (StatusCode::BAD_REQUEST, "Malformed character data chunk in PNG".to_string())
            }
            UploadError::Parse(ParserError::JsonError(e)) => {
                println!("Parser error: JSON - {}", e);
                 (StatusCode::BAD_REQUEST, "Invalid JSON data in character card".to_string())
            }
             UploadError::Parse(ParserError::Base64Error(e)) => {
                 // This might duplicate the top-level Base64Decode, but keeps concerns separated
                 println!("Parser error: Base64 - {}", e);
                 (StatusCode::BAD_REQUEST, "Invalid base64 encoding within character data".to_string())
            }
            UploadError::Parse(e) => { // Catch other parser errors (IO, PNG format)
                 println!("Parser error: Other - {:?}", e);
                (StatusCode::BAD_REQUEST, "Failed to parse PNG file".to_string())
            }
            // Add cases for DB errors, NotFound, Unauthorized etc. later
        };

        (status, Json(serde_json::json!({ "error": error_message }))).into_response()
    }
}

// Declare the test module
#[cfg(test)]
#[path = "characters_tests.rs"]
mod tests; 