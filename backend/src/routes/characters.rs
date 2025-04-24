// backend/src/routes/characters.rs

use crate::errors::AppError;
use crate::models::characters::{Character, CharacterMetadata};
use crate::models::character_card::{NewCharacter};
use crate::models::users::User;
use crate::schema::characters::dsl::*; // DSL needed for table/columns
use crate::services::character_parser::{self};
use crate::state::AppState;
use axum::{
    body::Body,
    debug_handler,
    extract::{multipart::Multipart, Path, State, Extension},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post, delete},
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
use diesel::result::Error as DieselError; // Add import for DieselError
use serde::{Deserialize}; // Add serde import

// Define the type alias for the auth session specific to our AuthBackend
// type CurrentAuthSession = AuthSession<AppState>;
type CurrentAuthSession = AuthSession<AuthBackend>; // <-- Use correct Backend type

// Define input structure for the generation prompt
#[derive(Deserialize, Debug)]
pub struct GenerateCharacterPayload {
    prompt: String,
}

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

    let conn = state.pool.get().await.map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let inserted_character: Character = conn
        .interact(move |conn| {
            diesel::insert_into(characters)
                .values(&new_character)
                .returning(Character::as_select())
                .get_result::<Character>(conn)
        })
        .await
        .map_err(|e| AppError::InternalServerError(e.to_string()))??;

    info!(character_id = %inserted_character.id, "Character uploaded and saved");

    Ok((StatusCode::CREATED, Json(inserted_character)))
}

// GET /api/characters
#[instrument(skip(state, auth_session), err)]
pub async fn list_characters_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession, // <-- Add AuthSession extractor
) -> Result<Json<Vec<CharacterMetadata>>, AppError> {
    // Get the user from the session
    let user = auth_session.user.ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?; // CHANGED
    let local_user_id = user.id; // <-- Get ID from the user struct

    info!(%local_user_id, "Listing characters for user"); // Updated log message

    let conn = state.pool.get().await.map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let characters_result = conn
        .interact(move |conn| {
            characters
                .filter(user_id.eq(local_user_id))
                .select(CharacterMetadata::as_select())
                .load::<CharacterMetadata>(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await??;

    Ok(Json(characters_result))
}

// GET /api/characters/:id
#[instrument(skip(_state, auth_session), err)]
pub async fn get_character_handler(
    State(_state): State<AppState>,
    auth_session: CurrentAuthSession,
    Path(character_id): Path<Uuid>,
) -> Result<Json<CharacterMetadata>, AppError> {
    // Get the user from the session
    let user = auth_session.user.ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?; // CHANGED
    let local_user_id = user.id; // <-- Get ID from the user struct

    info!(%character_id, %local_user_id, "Fetching character details for user"); // Updated log message

    let conn = _state.pool.get().await.map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let character_result = conn
        .interact(move |conn| {
            characters
                .filter(id.eq(character_id))
                .filter(user_id.eq(local_user_id))
                .select(CharacterMetadata::as_select())
                .first::<CharacterMetadata>(conn)
                .map_err(|e| match e {
                    DieselError::NotFound => AppError::NotFound(format!("Character {} not found", character_id)),
                    _ => AppError::DatabaseQueryError(e.to_string()),
                })
        })
        .await??;

    Ok(Json(character_result))
}

// POST /api/characters/generate
#[instrument(skip(_state, auth_session, payload), err)]
pub async fn generate_character_handler(
    State(_state): State<AppState>,
    auth_session: CurrentAuthSession,
    Json(payload): Json<GenerateCharacterPayload>,
) -> Result<(StatusCode, Json<Character>), AppError> {
    let user = auth_session.user.ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let user_id_val = user.id; // Capture user id

    info!(%user_id_val, prompt = %payload.prompt, "Generating character requested by user");

    // --- TODO: Implement AI character generation logic ---
    // 1. Call state.ai_client.generate_character(payload.prompt) -> This needs to be implemented
    // 2. Parse the AI response into character fields (name, description, etc.)
    // 3. Create a NewCharacter struct
    // 4. Save the NewCharacter to the database using interact
    // 5. Return the created Character

    // Placeholder implementation: Return an error indicating not implemented yet
    // Err(AppError::InternalServerError(anyhow!("Character generation not yet implemented")))

    // Placeholder implementation 2: Return a dummy character (for testing the route)
    let dummy_character = Character {
        id: Uuid::new_v4(), // Generate a new ID
        user_id: user_id_val,
        name: "Generated Placeholder".to_string(),
        description: Some(format!("Based on prompt: '{}'", payload.prompt)),
        personality: Some("Placeholder".to_string()),
        scenario: Some("Placeholder".to_string()),
        first_mes: Some("Placeholder".to_string()),
        mes_example: Some("Placeholder".to_string()),
        created_at: chrono::Utc::now(), // Fixed: Use DateTime<Utc>
        updated_at: chrono::Utc::now(), // Fixed: Use DateTime<Utc>
        persona: None,
        world_scenario: None,
        creator_notes: None,
        system_prompt: None,
        post_history_instructions: None,
        tags: None,
        creator: None,
        character_version: None,
        alternate_greetings: None,
        avatar: None,
        chat: None,
        greeting: None,
        definition: None,
        default_voice: None,
        extensions: None,
        data_id: None,
        category: None,
        definition_visibility: None,
        depth: None,
        example_dialogue: None,
        favorite: None,
        first_message_visibility: None,
        height: None,
        last_activity: None,
        migrated_from: None,
        model_prompt: None,
        model_prompt_visibility: None,
        model_temperature: None,
        num_interactions: None,
        permanence: None,
        persona_visibility: None,
        revision: None,
        sharing_visibility: None,
        status: None,
        system_prompt_visibility: None,
        system_tags: None,
        token_budget: None,
        usage_hints: None,
        user_persona: None,
        user_persona_visibility: None,
        visibility: None,
        weight: None,
        world_scenario_visibility: None,
        creator_notes_multilingual: None,
    };

    // --- TODO: Optionally save the dummy character to DB if needed for testing downstream GET ---
    // If saving, ensure the dummy_character above matches the NewCharacter structure and use interact

    Ok((StatusCode::OK, Json(dummy_character))) // Return OK for now
}

// DELETE /api/characters/:id
#[instrument(skip(state, auth_session), err)]
pub async fn delete_character_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    Path(character_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session.user.ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let user_id_val = user.id;

    info!(%character_id, %user_id_val, "Deleting character for user");

    let conn = state.pool.get().await.map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let rows_deleted = conn
        .interact(move |conn| {
            diesel::delete(
                characters
                    .filter(id.eq(character_id))
                    .filter(user_id.eq(user_id_val))
            )
            .execute(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await??;

    if rows_deleted == 0 {
        // This could be NotFound or Forbidden, but NotFound is common if ID doesn't exist
        // or doesn't belong to the user.
        Err(AppError::NotFound(format!(
            "Character {} not found or not owned by user {}",
            character_id,
            user_id_val
        )))
    } else {
        Ok(StatusCode::NO_CONTENT)
    }
}

// --- Character Router ---
pub fn characters_router(state: AppState) -> Router {
    Router::new()
        .route("/upload", post(upload_character_handler))
        .route("/", get(list_characters_handler))
        .route("/{id}", get(get_character_handler))
        .route("/{id}", delete(delete_character_handler))
        .route("/generate", post(generate_character_handler))
        .with_state(state)
}

#[debug_handler]
pub async fn get_character_image(
    Path(character_id): Path<Uuid>,
    State(_state): State<AppState>,
    Extension(user): Extension<User>,
) -> Result<Response<Body>, AppError> {
    tracing::info!(%character_id, user_id = %user.id, "Fetching character image");

    // TODO: Implement actual logic to fetch the image data
    // This would involve querying the database or file storage based on character_id and user_id
    // For now, return a placeholder response or error

    Err(AppError::NotImplemented(
        "Character image retrieval not yet implemented".to_string(),
    ))
}