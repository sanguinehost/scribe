// backend/src/routes/characters.rs
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use diesel::prelude::*;
use diesel::r2d2;
use uuid::Uuid;

use crate::models::character_card::{Character, CharacterCardV3};
use crate::services::character_parser::{parse_character_card_png, ParserError};
use crate::state::{AppState};

// --- Upload Handler --- 
#[derive(Deserialize, Debug)]
pub struct UploadPayload {
    png_base64: String,
}

pub async fn upload_character(
    State(_state): State<AppState>,
    Json(payload): Json<UploadPayload>,
) -> Result<Json<CharacterCardV3>, ApiError> {
    // 1. Decode base64
    let png_bytes = base64_standard.decode(&payload.png_base64).map_err(ApiError::from)?;

    // 2. Call parser
    let card_data = parse_character_card_png(&png_bytes).map_err(ApiError::from)?;

    // 3. TODO: Save metadata to DB using _state.pool
    println!("Successfully parsed character: {}", card_data.data.name.as_deref().unwrap_or("Unnamed"));

    // 4. Return parsed card data
    Ok(Json(card_data))
}

// --- List Handler --- 
pub async fn list_characters(
    State(state): State<AppState>, // Use the pool from state
) -> Result<Json<Vec<Character>>, ApiError> { // Return Vec of Character model
    // TODO: Get user ID from auth later
    // let user_id = ...; 

    let mut conn = state.pool.get().map_err(|e| ApiError::Internal(e.to_string()))?;

    // Query DB for all characters for now
    use crate::schema::characters::dsl::*;
    
    let results = characters
        // .filter(user_id.eq(user_id)) // TODO: Add filter when auth is ready
        .select(Character::as_select())
        .load(&mut conn)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(results))
}

// --- Get Handler --- 
pub async fn get_character(
    State(state): State<AppState>, // Use the pool from state
    Path(character_uuid): Path<Uuid>, // Use Uuid based on schema/model
) -> Result<Json<Character>, ApiError> { // Return single Character model
    // TODO: Get user ID from auth later
    // let user_id = ...;

    let mut conn = state.pool.get().map_err(|e| ApiError::Internal(e.to_string()))?;
    
    use crate::schema::characters::dsl::*;
    
    let result = characters
        .filter(id.eq(character_uuid))
        // .filter(user_id.eq(user_id)) // TODO: Add filter for ownership check
        .select(Character::as_select())
        .first(&mut conn)
        // Handle not found specifically
        .optional()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    match result {
        Some(character) => Ok(Json(character)),
        None => Err(ApiError::NotFound("Character not found".to_string())),
    }
}

// --- Error Handling for Routes (Consolidated) --- 
#[derive(Debug)]
pub enum ApiError {
    Base64Decode(base64::DecodeError),
    Parse(ParserError),
    Internal(String), // Generic internal error (DB connection, query, etc.)
    NotFound(String),
    // Unauthorized,
}

impl From<base64::DecodeError> for ApiError {
    fn from(err: base64::DecodeError) -> Self {
        ApiError::Base64Decode(err)
    }
}

impl From<ParserError> for ApiError {
    fn from(err: ParserError) -> Self {
        ApiError::Parse(err)
    }
}

// Generic way to handle R2D2 pool errors
impl From<r2d2::Error> for ApiError {
    fn from(err: r2d2::Error) -> Self {
        ApiError::Internal(format!("DB Pool Error: {}", err))
    }
}

// Generic way to handle Diesel query errors
impl From<diesel::result::Error> for ApiError {
    fn from(err: diesel::result::Error) -> Self {
        match err {
            diesel::result::Error::NotFound => ApiError::NotFound("Record not found".to_string()),
            _ => ApiError::Internal(format!("DB Query Error: {}", err)),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            ApiError::Base64Decode(e) => {
                println!("Base64 decode error: {}", e);
                (StatusCode::BAD_REQUEST, "Invalid base64 data".to_string())
            }
            ApiError::Parse(ParserError::ChunkNotFound) => {
                 println!("Parser error: Chunk not found");
                (StatusCode::BAD_REQUEST, "Character data not found in PNG".to_string())
            }
             ApiError::Parse(ParserError::InvalidTextChunkFormat) => {
                 println!("Parser error: Invalid tEXt chunk");
                (StatusCode::BAD_REQUEST, "Malformed character data chunk in PNG".to_string())
            }
            ApiError::Parse(ParserError::JsonError(e)) => {
                println!("Parser error: JSON - {}", e);
                 (StatusCode::BAD_REQUEST, "Invalid JSON data in character card".to_string())
            }
             ApiError::Parse(ParserError::Base64Error(e)) => {
                 println!("Parser error: Base64 - {}", e);
                 (StatusCode::BAD_REQUEST, "Invalid base64 encoding within character data".to_string())
            }
            ApiError::Parse(e) => { // Catch other parser errors (IO, PNG format)
                 println!("Parser error: Other - {:?}", e);
                (StatusCode::BAD_REQUEST, "Failed to parse PNG file".to_string())
            }
            ApiError::NotFound(msg) => {
                println!("Not Found: {}", msg);
                (StatusCode::NOT_FOUND, msg)
            }
            ApiError::Internal(msg) => {
                println!("Internal Server Error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "An internal error occurred".to_string())
            }
            // Add cases for Unauthorized etc. later
        };

        (status, Json(serde_json::json!({ "error": error_message }))).into_response()
    }
}

// Declare the test module
#[cfg(test)]
#[path = "characters_tests.rs"]
mod tests; 