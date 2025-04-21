// backend/src/routes/characters.rs

use crate::errors::AppError;
use crate::models::characters::Character;
use crate::models::character_card::NewCharacter;
use crate::schema::characters::dsl::*; // DSL needed for table/columns
use crate::services::character_parser::{self};
use crate::state::AppState;
use axum::{
    extract::{multipart::Multipart, Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use diesel::prelude::*; // Needed for .filter(), .load(), .first(), etc.
use tracing::{info, instrument}; // Use needed tracing macros
use uuid::Uuid;
use anyhow::anyhow;
use diesel::SelectableHelper;
use diesel::RunQueryDsl;
use axum::body::Bytes; // Added import for Bytes
use axum_login::AuthSession; // <-- Add this import
use crate::auth::user_store::Backend as AuthBackend; // <-- Import the backend type
 // Import User model
use diesel::result::Error as DieselError; // Add import for DieselError

// Define the type alias for the auth session specific to our AuthBackend
// type CurrentAuthSession = AuthSession<AppState>;
type CurrentAuthSession = AuthSession<AuthBackend>; // <-- Use correct Backend type

// POST /api/characters/upload
#[instrument(skip(state, multipart, auth_session), err)]
pub async fn upload_character_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession, // <-- Add AuthSession extractor
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<Character>), AppError> {
    // Get the user from the session
    let user = auth_session.user.ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?; // CHANGED
    let local_user_id = user.id; // <-- Get ID from the user struct

    let mut file_data: Option<Bytes> = None;
    let mut _filename: Option<String> = None; // Renamed to _filename to silence warning

    while let Some(field) = multipart.next_field().await? {
        let local_field_name = field.name().unwrap_or("").to_string(); // Renamed variable
        if local_field_name == "character_card" {
            // Get filename *before* consuming the field with .bytes()
            _filename = field.file_name().map(|f| f.to_string()); // Corrected method name: file_name
            let data = field.bytes().await?; // Consumes the field
            file_data = Some(data); // Assign Bytes directly
            break;
        }
    }
    let png_data = file_data
        .ok_or_else(|| AppError::BadRequest("Missing 'character_card' field in upload".to_string()))?;

    let parsed_card = character_parser::parse_character_card_png(&png_data)?; // Pass Bytes directly
    let new_character = NewCharacter::from_parsed_card(&parsed_card, local_user_id); // Use user_id from session

    // Log the character data just before insertion
    info!(?new_character, user_id = %local_user_id, "Attempting to insert character into DB for user"); // Updated log

    let conn = state.pool.get().await.map_err(AppError::DbPoolError)?;

    let inserted_character: Character = conn
        .interact(move |conn| {
            diesel::insert_into(characters)
                .values(&new_character)
                .returning(Character::as_select())
                .get_result::<Character>(conn)
        })
        .await
        .map_err(|e| AppError::InternalServerError(anyhow!(e.to_string())))??;

    info!(character_id = %inserted_character.id, "Character uploaded and saved");

    Ok((StatusCode::CREATED, Json(inserted_character)))
}

// GET /api/characters
#[instrument(skip(state, auth_session), err)]
pub async fn list_characters_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession, // <-- Add AuthSession extractor
) -> Result<Json<Vec<Character>>, AppError> {
    // Get the user from the session
    let user = auth_session.user.ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?; // CHANGED
    let local_user_id = user.id; // <-- Get ID from the user struct

    info!(%local_user_id, "Listing characters for user"); // Updated log message

    let conn = state.pool.get().await.map_err(AppError::DbPoolError)?;

    let characters_result = conn
        .interact(move |conn| {
            characters
                .filter(user_id.eq(local_user_id))
                .select(Character::as_select())
                .load::<Character>(conn)
                .map_err(AppError::DatabaseQueryError)
        })
        .await??;

    Ok(Json(characters_result))
}

// GET /api/characters/:id
#[instrument(skip(state, auth_session), err)]
pub async fn get_character_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession, // <-- Add AuthSession extractor
    Path(character_id): Path<Uuid>,
) -> Result<Json<Character>, AppError> {
    // Get the user from the session
    let user = auth_session.user.ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?; // CHANGED
    let local_user_id = user.id; // <-- Get ID from the user struct

    info!(%character_id, %local_user_id, "Fetching character details for user"); // Updated log message

    let conn = state.pool.get().await.map_err(AppError::DbPoolError)?;

    let character_result = conn
        .interact(move |conn| {
            characters
                .filter(id.eq(character_id))
                .filter(user_id.eq(local_user_id))
                .select(Character::as_select())
                .first::<Character>(conn)
                .map_err(|e| match e {
                    DieselError::NotFound => AppError::NotFound(format!("Character {} not found", character_id)),
                    _ => AppError::DatabaseQueryError(e),
                })
        })
        .await??;

    Ok(Json(character_result))
}

// --- Character Router ---
pub fn characters_router(state: AppState) -> Router {
    Router::new()
        .route("/upload", post(upload_character_handler))
        .route("/", get(list_characters_handler))
        .route("/{id}", get(get_character_handler))
        .with_state(state)
}