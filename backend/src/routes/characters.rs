// backend/src/routes/characters.rs
use axum::{
    Json,
    extract::{Extension, Multipart, Path, State},
};
// use chrono::DateTime; // <-- Removed unused import
use diesel::prelude::*;
use uuid::Uuid;

use crate::errors::{AppError, Result};
use crate::models::character_card::{Character, NewCharacter};
use crate::models::users::User; // Needed for Extension / test user
use crate::schema::characters;
use crate::services::character_parser::parse_character_card_png;
use crate::state::AppState; // <-- Removed unused ParsedCharacterCard

// Define a static UUID for the test user
// #[cfg(test)] // No longer needed here, user comes from Extension
// const TEST_USER_ID: Uuid = Uuid::from_u128(0x00000000_0000_0000_0000_000000000001); // Example UUID

pub async fn upload_character(
    State(state): State<AppState>,
    Extension(current_user): Extension<User>,
    mut multipart: Multipart,
) -> Result<Json<Character>> {
    // --- Get user_id from Extension (provided by test setup or actual auth) ---
    let user_id = current_user.id;

    let mut png_bytes: Option<Vec<u8>> = None;
    let mut found_field = false;

    while let Some(field) = multipart.next_field().await.map_err(AppError::from)? {
        let name = field.name().unwrap_or("").to_string();
        if name == "character_card" {
            found_field = true;
            let content_type = field.content_type().map(|ct| ct.to_string());
            if content_type.as_deref() != Some("image/png") {
                return Err(AppError::BadRequest(
                    "Uploaded file must be a PNG image.".to_string(),
                ));
            }
            png_bytes = Some(field.bytes().await.map_err(AppError::from)?.to_vec());
        } else {
            let _ = field.bytes().await; // Drain other fields
        }
    }

    if !found_field {
        return Err(AppError::BadRequest(
            "Missing 'character_card' PNG file in upload form data.".to_string(),
        ));
    }
    let png_bytes = png_bytes.ok_or_else(|| {
        AppError::BadRequest(
            "Failed to read bytes from 'character_card' PNG file field.".to_string(),
        )
    })?;

    // Parse the PNG data
    let parsed_card = parse_character_card_png(&png_bytes)?;

    // Convert the parsed card data (V3 or V2Fallback) into the NewCharacter struct for DB insertion
    let new_character = NewCharacter::from_parsed_card(&parsed_card, user_id);

    let mut conn = state.pool.get()?;
    let inserted_character = diesel::insert_into(characters::table)
        .values(&new_character)
        .returning(Character::as_returning())
        .get_result(&mut conn)?;

    tracing::info!(character_id = %inserted_character.id, character_name = %inserted_character.name, "Successfully saved character");
    Ok(Json(inserted_character))
}

// --- List Handler ---
pub async fn list_characters(State(state): State<AppState>) -> Result<Json<Vec<Character>>> {
    let mut conn = state.pool.get()?;
    use crate::schema::characters::dsl::*;
    let results = characters.select(Character::as_select()).load(&mut conn)?;
    Ok(Json(results))
}

// --- Get Handler ---
pub async fn get_character(
    State(state): State<AppState>,
    Path(character_uuid): Path<Uuid>,
) -> Result<Json<Character>> {
    let mut conn = state.pool.get()?;
    use crate::schema::characters::dsl::*;
    let result = characters
        .filter(id.eq(character_uuid))
        .select(Character::as_select())
        .first(&mut conn)
        .optional()?
        .ok_or_else(|| {
            AppError::NotFound(format!("Character with ID {} not found", character_uuid))
        })?;
    Ok(Json(result))
}