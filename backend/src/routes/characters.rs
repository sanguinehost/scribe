// backend/src/routes/characters.rs
#![allow(clippy::items_after_statements)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::unused_async)]

use crate::auth::session_dek::SessionDek;
use crate::crypto;
use crate::errors::AppError;
use crate::models::character_assets::{CharacterAsset, NewCharacterAsset};
use crate::models::character_card::NewCharacter;
use crate::models::characters::{Character, CharacterDataForClient};
use crate::schema::character_assets::dsl::character_assets;
use crate::schema::characters::dsl::{characters, id, user_id};
use crate::services::character_parser::{self};
use crate::state::AppState;
use axum::{
    Router,
    body::Body,
    debug_handler,
    extract::{Path, Query, State, multipart::Multipart}, // Added Query
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post, put},
};
use diesel::{
    BoolExpressionMethods, ExpressionMethods, OptionalExtension, QueryDsl, RunQueryDsl,
    SelectableHelper, result::Error as DieselError,
}; // Needed for .filter(), .load(), .first(), etc.
use std::sync::Arc;
use tracing::{debug, error, info, instrument, trace, warn}; // Use needed tracing macros
use uuid::Uuid;
// use anyhow::anyhow; // Unused import
use crate::auth::user_store::Backend as AuthBackend; // <-- Import the backend type
use crate::models::character_dto::{CharacterCreateDto, CharacterUpdateDto};
use crate::schema::chat_sessions;
use crate::services::character_service::CharacterService;
use crate::services::encryption_service::EncryptionService; // Added import
use crate::services::lorebook_service::LorebookService;
use axum::body::Bytes;
use axum_login::AuthSession; // <-- Removed login_required import
// DieselError moved to main diesel imports
use image::ImageFormat; // Added for image processing
use image::ImageReader; // Use the new name for clarity
use secrecy::ExposeSecret; // Added for DEK expose
use serde::Deserialize; // Add serde import
use std::io::Cursor; // Added for image processing

// Define input structure for image query parameters
#[derive(Deserialize, Debug)]
pub struct ImageQueryParams {
    width: Option<u32>,
    height: Option<u32>,
}

// Define the type alias for the auth session specific to our AuthBackend
// type CurrentAuthSession = AuthSession<AppState>;
type CurrentAuthSession = AuthSession<AuthBackend>; // <-- Use correct Backend type

// Define input structure for the generation prompt
#[derive(Deserialize, Debug)]
pub struct GenerateCharacterPayload {
    prompt: String,
}

// --- Character Router ---
pub fn characters_router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/upload", post(upload_character_handler))
        .route(
            "/",
            get(list_characters_handler).post(create_character_handler),
        ) // Added POST for manual creation
        // NOTE (of frustration): The routes for getting and deleting a character were changed
        // to `/fetch/:id` and `/remove/:id` respectively.
        // Attempts to use  `/:id` for GET and DELETE resulted in
        // persistent and inexplicable 404 errors, despite various debugging attempts.
        // This change to more distinct paths was a pragmatic workaround,
        // born from a fuck-ton (three days) of deep-seated frustration with Axum routing obscurities in this context
        // that my fucking mortal monkey brain just cannot wrap itself around.
        .route("/fetch/:id", get(get_character_handler))
        .route("/:id", put(update_character_handler)) // Added PUT for update on /:id
        .route("/remove/:id", delete(delete_character_handler))
        .route("/generate", post(generate_character_handler))
        .route(
            "/:character_id/assets/:asset_id",
            get(get_character_asset_handler),
        )
        // Apply LoginRequired middleware to all routes in this router
        // It checks auth_session.user and returns 401 if None.
        .with_state(state)
}

// POST /api/characters/upload
#[instrument(skip(state, multipart, auth_session), err)]
pub async fn upload_character_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    dek: SessionDek, // Added SessionDek extractor
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<CharacterDataForClient>), AppError> {
    // Return CharacterDataForClient
    // Get the user from the session
    let user = auth_session
        .user
        .as_ref()
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let local_user_id = user.id;

    let mut file_data: Option<Bytes> = None;
    let mut content_type: Option<String> = None; // Added to store content type

    info!("Starting character card upload process. Searching for 'character_card' field.");
    while let Some(field) = multipart.next_field().await? {
        let field_name = field.name().unwrap_or("unknown_field").to_string();
        let file_name = field.file_name().map(|s| s.to_string());
        let ct = field.content_type().map(|s| s.to_string());
        info!(field_name = %field_name, file_name = ?file_name, content_type = ?ct, "Processing multipart field");

        if field_name == "character_card" {
            content_type = ct;
            let data = field.bytes().await?;
            info!("Found 'character_card' field with {} bytes.", data.len());
            file_data = Some(data);
            break;
        }
    }
    let png_data = file_data.ok_or_else(|| {
        AppError::BadRequest("Missing 'character_card' field in upload".to_string())
    })?;

    // Validate image data using the 'image' crate
    if let Some(ct) = &content_type {
        if ct.starts_with("image/") {
            let format = match ct.as_str() {
                "image/png" => Some(image::ImageFormat::Png),
                "image/jpeg" => Some(image::ImageFormat::Jpeg),
                _ => None,
            };

            if let Some(fmt) = format {
                match image::load_from_memory_with_format(&png_data, fmt) {
                    Ok(_) => info!("Image data validated successfully as {}", ct),
                    Err(e) => {
                        error!("Failed to decode image data as {}: {}", ct, e);
                        return Err(AppError::BadRequest(format!("Invalid image data: {}", e)));
                    }
                }
            } else {
                warn!("Unsupported image content type: {}", ct);
                // Allow upload but log warning, or return error if strict
            }
        }
    } else {
        warn!("No content type provided for character_card upload.");
    }

    let parsed_card = character_parser::parse_character_card_png(&png_data)?;
    let mut new_character_for_db = NewCharacter::from_parsed_card(&parsed_card, local_user_id);

    // --- Encrypt all designated fields before saving ---
    // Helper macro to reduce boilerplate for encrypting Option<Vec<u8>> fields
    macro_rules! encrypt_field {
        ($self:ident, $field:ident, $nonce_field:ident, $dek:expr) => {
            if let Some(plaintext_bytes) = $self.$field.take() {
                if !plaintext_bytes.is_empty() {
                    match String::from_utf8(plaintext_bytes) {
                        Ok(string_version) => {
                            if !string_version.is_empty() {
                                // Use the higher-level EncryptionService for encryption
                                let enc_service = EncryptionService::new();
                                match enc_service.encrypt(&string_version, $dek.expose_secret()) {
                                    Ok((ciphertext, nonce)) => {
                                        $self.$field = Some(ciphertext);
                                        $self.$nonce_field = Some(nonce);
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            "Failed to encrypt character field '{}': {}",
                                            stringify!($field),
                                            e
                                        );
                                        return Err(AppError::EncryptionError(format!(
                                            "Encryption failed for {}: {e}",
                                            stringify!($field)
                                        )));
                                    }
                                }
                            } else {
                                $self.$field = None;
                                $self.$nonce_field = None;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Field '{}' bytes not valid UTF-8: {}. Storing as None.",
                                stringify!($field),
                                e
                            );
                            $self.$field = None;
                            $self.$nonce_field = None;
                        }
                    }
                } else {
                    $self.$field = None;
                    $self.$nonce_field = None;
                }
            }
        };
    }

    encrypt_field!(new_character_for_db, description, description_nonce, &dek.0);
    encrypt_field!(new_character_for_db, personality, personality_nonce, &dek.0);
    encrypt_field!(new_character_for_db, scenario, scenario_nonce, &dek.0);
    encrypt_field!(new_character_for_db, first_mes, first_mes_nonce, &dek.0);
    encrypt_field!(new_character_for_db, mes_example, mes_example_nonce, &dek.0);
    encrypt_field!(
        new_character_for_db,
        creator_notes,
        creator_notes_nonce,
        &dek.0
    );
    encrypt_field!(
        new_character_for_db,
        system_prompt,
        system_prompt_nonce,
        &dek.0
    );
    encrypt_field!(new_character_for_db, persona, persona_nonce, &dek.0);
    encrypt_field!(
        new_character_for_db,
        world_scenario,
        world_scenario_nonce,
        &dek.0
    );
    encrypt_field!(new_character_for_db, greeting, greeting_nonce, &dek.0);
    encrypt_field!(new_character_for_db, definition, definition_nonce, &dek.0);
    encrypt_field!(
        new_character_for_db,
        example_dialogue,
        example_dialogue_nonce,
        &dek.0
    );
    encrypt_field!(
        new_character_for_db,
        model_prompt,
        model_prompt_nonce,
        &dek.0
    );
    encrypt_field!(
        new_character_for_db,
        user_persona,
        user_persona_nonce,
        &dek.0
    );

    // Encrypt SillyTavern v3 fields that contain sensitive data
    encrypt_field!(
        new_character_for_db,
        creator_comment,
        creator_comment_nonce,
        &dek.0
    );

    // For depth_prompt, we need to encrypt the text content into depth_prompt_ciphertext
    if let Some(depth_prompt_text_bytes) = new_character_for_db.depth_prompt.take() {
        if !depth_prompt_text_bytes.is_empty() {
            match String::from_utf8(depth_prompt_text_bytes) {
                Ok(depth_prompt_text) if !depth_prompt_text.is_empty() => {
                    let enc_service = EncryptionService::new();
                    match enc_service.encrypt(&depth_prompt_text, dek.0.expose_secret()) {
                        Ok((ciphertext, nonce)) => {
                            new_character_for_db.depth_prompt_ciphertext = Some(ciphertext);
                            new_character_for_db.depth_prompt_nonce = Some(nonce);
                        }
                        Err(e) => {
                            tracing::error!("Failed to encrypt depth_prompt: {}", e);
                            return Err(AppError::EncryptionError(format!(
                                "Encryption failed for depth_prompt: {e}"
                            )));
                        }
                    }
                }
                _ => {
                    // Invalid UTF-8 or empty, leave as None
                    new_character_for_db.depth_prompt_ciphertext = None;
                    new_character_for_db.depth_prompt_nonce = None;
                }
            }
        }
    }

    // For world field, encrypt from the world string into world_ciphertext
    if let Some(world_text) = new_character_for_db.world.as_ref() {
        if !world_text.is_empty() {
            let enc_service = EncryptionService::new();
            match enc_service.encrypt(world_text, dek.0.expose_secret()) {
                Ok((ciphertext, nonce)) => {
                    new_character_for_db.world_ciphertext = Some(ciphertext);
                    new_character_for_db.world_nonce = Some(nonce);
                }
                Err(e) => {
                    tracing::error!("Failed to encrypt world field: {}", e);
                    return Err(AppError::EncryptionError(format!(
                        "Encryption failed for world field: {e}"
                    )));
                }
            }
        }
    }

    info!(?new_character_for_db.name, user_id = %local_user_id, "Attempting to insert character into DB for user");

    let conn_insert_op = state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let returned_id: Uuid = conn_insert_op
        .interact(move |conn_insert_block| {
            diesel::insert_into(characters)
                .values(new_character_for_db)
                .returning(id)
                .get_result::<Uuid>(conn_insert_block)
        })
        .await
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Insert interaction error: {e}"))
        })?
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Insert DB error: {e}")))?;

    info!(character_id = %returned_id, "Character basic info returned after insert");

    let conn_fetch_op = state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;
    let inserted_character: Character = conn_fetch_op
        .interact(move |conn_select_block| {
            characters
                .find(returned_id)
                .select(Character::as_select())
                .get_result::<Character>(conn_select_block)
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Fetch interaction error: {e}")))?
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Fetch DB error: {e}")))?;

    info!(character_id = %inserted_character.id, "Character uploaded and saved (full data fetched)");

    // --- Save the character avatar image to database ---
    // Create character asset record with binary data
    let new_asset = NewCharacterAsset::new_avatar(
        inserted_character.id,
        &format!("{}_avatar", inserted_character.name),
        png_data.to_vec(),
        content_type, // Pass the extracted content_type
    );

    // Save asset record to database
    let conn_asset_op = state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let asset_result: Result<CharacterAsset, diesel::result::Error> = conn_asset_op
        .interact(move |conn_asset_block| {
            diesel::insert_into(character_assets)
                .values(new_asset)
                .returning(CharacterAsset::as_returning())
                .get_result::<CharacterAsset>(conn_asset_block)
        })
        .await
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Asset insert interaction error: {e}"))
        })?;

    match asset_result {
        Ok(asset) => {
            info!(character_id = %inserted_character.id, asset_id = asset.id, "Character avatar stored in database successfully");

            // Update character record with asset reference (asset ID as string)
            let character_id_for_update = inserted_character.id;
            let asset_id_for_update = asset.id.to_string();
            let conn_update_op = state
                .pool
                .get()
                .await
                .map_err(|e| AppError::DbPoolError(e.to_string()))?;

            let update_result = conn_update_op
                .interact(move |conn_update_block| {
                    diesel::update(characters.find(character_id_for_update))
                        .set(crate::schema::characters::avatar.eq(Some(asset_id_for_update)))
                        .execute(conn_update_block)
                })
                .await
                .map_err(|e| {
                    AppError::InternalServerErrorGeneric(format!(
                        "Avatar update interaction error: {e}"
                    ))
                })?;

            match update_result {
                Ok(_) => {
                    info!(character_id = %inserted_character.id, "Character avatar field updated with asset ID");
                }
                Err(e) => {
                    warn!(character_id = %inserted_character.id, error = %e, "Failed to update character avatar field");
                }
            }
        }
        Err(e) => {
            warn!(character_id = %inserted_character.id, error = %e, "Failed to save avatar image to database, continuing without avatar");
        }
    }

    // Check if the parsed card has an embedded lorebook
    let character_book = match &parsed_card {
        crate::services::character_parser::ParsedCharacterCard::V3(card) => {
            &card.data.character_book
        }
        crate::services::character_parser::ParsedCharacterCard::V2Fallback(data) => {
            &data.character_book
        }
    };

    if let Some(lorebook_data) = character_book {
        // Import the lorebook
        let lorebook_service = crate::services::LorebookService::new(
            state.pool.clone(),
            state.encryption_service.clone(),
            state.qdrant_service.clone(),
        );

        // Convert SillyTavern lorebook format to our upload payload
        use std::collections::HashMap;
        let mut entries_map = HashMap::new();

        // Handle both array and object formats for entries
        if let Ok(lorebook_json) = serde_json::to_value(lorebook_data) {
            if let Some(entries_value) = lorebook_json.get("entries") {
                if let Some(entries_array) = entries_value.as_array() {
                    // Handle array format (common in character cards)
                    for (idx, entry_value) in entries_array.iter().enumerate() {
                        match serde_json::from_value::<
                            crate::models::lorebook_dtos::UploadedLorebookEntry,
                        >(entry_value.clone())
                        {
                            Ok(entry) => {
                                let uid = entry
                                    .uid
                                    .map(|u| u.to_string())
                                    .or_else(|| entry.id.map(|i| i.to_string()))
                                    .unwrap_or_else(|| idx.to_string());
                                tracing::info!(
                                    "Successfully parsed array entry {}: content length={}",
                                    uid,
                                    entry.content.len()
                                );
                                entries_map.insert(uid, entry);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to parse array entry {}: {}. Raw value: {}",
                                    idx,
                                    e,
                                    entry_value
                                );
                            }
                        }
                    }
                } else if let Some(entries_object) = entries_value.as_object() {
                    // Handle object format (SillyTavern format)
                    for (uid, entry_value) in entries_object {
                        match serde_json::from_value::<
                            crate::models::lorebook_dtos::UploadedLorebookEntry,
                        >(entry_value.clone())
                        {
                            Ok(entry) => {
                                tracing::info!(
                                    "Successfully parsed object entry {}: content length={}",
                                    uid,
                                    entry.content.len()
                                );
                                entries_map.insert(uid.clone(), entry);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to parse object entry {}: {}. Raw value: {}",
                                    uid,
                                    e,
                                    entry_value
                                );
                            }
                        }
                    }
                }
            }
        }

        let lorebook_payload = crate::models::lorebook_dtos::LorebookUploadPayload {
            name: format!("{} Lorebook", inserted_character.name),
            description: Some(format!("Lorebook for {}", inserted_character.name)),
            is_public: false,
            entries: entries_map,
        };

        // Import the lorebook
        match lorebook_service
            .import_lorebook(
                &auth_session,
                Some(&dek.0),
                lorebook_payload,
                Arc::new(state.clone()),
            )
            .await
        {
            Ok(lorebook) => {
                // Associate the lorebook with the character
                if let Err(e) = lorebook_service
                    .associate_lorebook_to_character(
                        &auth_session,
                        inserted_character.id,
                        lorebook.id,
                    )
                    .await
                {
                    warn!("Failed to associate lorebook with character: {}", e);
                }
            }
            Err(e) => {
                warn!("Failed to import embedded lorebook: {}", e);
            }
        }
    }

    let client_character_data =
        inserted_character.into_decrypted_for_client(Some(&dek.0), None)?;

    // Debug: Log the alternate_greetings in the final client response
    tracing::info!(
        "Final client character alternate_greetings: {:?}",
        client_character_data.alternate_greetings
    );

    Ok((StatusCode::CREATED, Json(client_character_data)))
}

// POST /api/characters - Manual character creation endpoint
#[instrument(skip(state, auth_session, dek, create_dto), err)]
pub async fn create_character_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    dek: SessionDek,
    Json(create_dto): Json<CharacterCreateDto>,
) -> Result<(StatusCode, Json<CharacterDataForClient>), AppError> {
    // Get the user from the session
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let local_user_id = user.id;

    // Instantiate services
    let enc_service = Arc::new(EncryptionService::new());
    let lorebook_service = Arc::new(LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    ));
    let character_service =
        CharacterService::new(state.pool.clone(), enc_service, lorebook_service);

    // Call the service method
    let client_data = character_service
        .create_character_manually(local_user_id, create_dto, &dek)
        .await?;

    Ok((StatusCode::CREATED, Json(client_data)))
}

// GET /api/characters
#[instrument(skip(state, auth_session, dek), err)]
pub async fn list_characters_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    dek: SessionDek, // Added SessionDek extractor
) -> Result<Json<Vec<CharacterDataForClient>>, AppError> {
    // Return Vec<CharacterDataForClient>
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let local_user_id = user.id;

    info!(%local_user_id, "Listing characters for user");

    let conn = state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let characters_db: Vec<Character> = conn
        .interact(move |conn_block| {
            characters
                .filter(user_id.eq(local_user_id))
                .select(Character::as_select()) // Select full Character
                .load::<Character>(conn_block)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
        })
        .await??;

    let mut characters_for_client = Vec::new();
    for char_db in characters_db {
        characters_for_client.push(char_db.into_decrypted_for_client(Some(&dek.0), None)?);
    }

    Ok(Json(characters_for_client))
}

// GET /api/characters/:id
#[debug_handler]
#[instrument(skip(state, auth_session, dek), err)]
pub async fn get_character_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    dek: SessionDek,
    Path(character_id): Path<Uuid>,
) -> Result<Json<CharacterDataForClient>, AppError> {
    trace!(target: "auth_debug", ">>> ENTERING get_character_handler for character_id: {}", character_id);

    let user = auth_session
        .user
        .clone() // Clone the user to avoid partial move
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let user_id_val = user.id;

    info!(target: "test_log", %character_id, %user_id_val, "Attempting to get character details for user (hybrid auth: direct owner OR session-based)");

    // --- Try 1: Direct Ownership Check ---
    let conn_direct_owner_check = state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;
    let user_id_for_direct_clone = user_id_val;
    let character_id_for_direct_clone = character_id;

    let directly_owned_character_result: Result<Option<Character>, AppError> =
        conn_direct_owner_check
            .interact(move |conn| {
                characters
                    .filter(
                        id.eq(character_id_for_direct_clone)
                            .and(user_id.eq(user_id_for_direct_clone)),
                    )
                    .select(Character::as_select())
                    .first::<Character>(conn)
                    .optional()
                    .map_err(|e| {
                        error!(
                            target: "test_log",
                            handler = "get_character_handler (direct ownership query)",
                            %character_id_for_direct_clone,
                            %user_id_for_direct_clone,
                            error = %e,
                            "DB error during direct ownership character query."
                        );
                        AppError::DatabaseQueryError(e.to_string())
                    })
            })
            .await // For the outer Result from interact (e.g., PoolError)
            .map_err(|interact_err| {
                error!(
                    target: "test_log",
                    handler = "get_character_handler (direct ownership interact)",
                    %character_id,
                    %user_id_val,
                    error = ?interact_err,
                    "Interact error during direct ownership character fetch."
                );
                AppError::DbInteractError(format!(
                    "Interact error during direct ownership character fetch: {interact_err}"
                ))
            })?;

    match directly_owned_character_result {
        Ok(Some(character)) => {
            info!(target: "test_log", handler = "get_character_handler", %character_id, %user_id_val, "Character directly owned, attempting decryption");

            // Fetch associated lorebook
            let lorebook_service = LorebookService::new(
                state.pool.clone(),
                state.encryption_service.clone(),
                state.qdrant_service.clone(),
            );
            let lorebooks = lorebook_service
                .list_character_lorebooks(&auth_session, character_id)
                .await?;
            let lorebook_id = lorebooks.first().map(|lb| lb.id);

            return match character.into_decrypted_for_client(Some(&dek.0), lorebook_id) {
                Ok(character_for_client) => {
                    info!(target: "test_log", handler = "get_character_handler", %character_id, %user_id_val, "Decryption SUCCESSFUL (direct ownership)");
                    Ok(Json(character_for_client))
                }
                Err(e) => {
                    error!(target: "test_log", handler = "get_character_handler", %character_id, %user_id_val, error = ?e, "Decryption FAILED (direct ownership)");
                    Err(e)
                }
            };
        }
        Ok(None) => {
            info!(target: "test_log", handler = "get_character_handler", %character_id, %user_id_val, "Not directly owned or not found by combined query. Checking session link...");
            // Proceed to session link check
        }
        Err(app_err) => {
            error!(target: "test_log", handler = "get_character_handler", %character_id, %user_id_val, error = ?app_err, "Error from direct ownership check, propagating");
            return Err(app_err); // Propagate DB errors from direct ownership check
        }
    }

    // --- Try 2: Session-Based Authorization Check (if not directly owned) ---
    info!(target: "test_log", %character_id, %user_id_val, "Attempting session-based auth for character details");
    let conn_auth_check = state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let user_id_for_session_clone = user_id_val;
    let character_id_for_session_clone = character_id;

    let has_session_with_character: bool = conn_auth_check
        .interact(move |conn| {
            diesel::select(diesel::dsl::exists(
                chat_sessions::table
                    .filter(chat_sessions::user_id.eq(user_id_for_session_clone))
                    .filter(chat_sessions::character_id.eq(character_id_for_session_clone))
            ))
            .get_result::<bool>(conn)
            .or_else(|e| if e == DieselError::NotFound {
                     error!(
                        target: "test_log",
                        handler = "get_character_handler (session link exists query)",
                        %character_id_for_session_clone,
                        %user_id_for_session_clone,
                        error = %e,
                        "DieselError::NotFound encountered unexpectedly for exists query. Interpreting as false."
                    );
                    Ok(false)
                } else {
                    error!(
                        target: "test_log",
                        handler = "get_character_handler (session link exists query)",
                        %character_id_for_session_clone,
                        %user_id_for_session_clone,
                        error = %e,
                        "DB error checking session link."
                    );
                    Err(AppError::DatabaseQueryError(format!("DB error checking session link: {e}")))
                })
        })
        .await
        .map_err(|e| {
             error!(
                target: "test_log",
                handler = "get_character_handler (session link interact)",
                %character_id,
                %user_id_val,
                error = %e,
                "Interact dispatch error checking session link."
            );
            AppError::DbInteractError(format!("Interact error checking session link: {e}"))
        })??;

    if !has_session_with_character {
        info!(
            target: "test_log",
            handler = "get_character_handler",
            %character_id,
            %user_id_val,
            "User does not directly own AND does not have an active session with this character. Returning NotFound."
        );
        return Err(AppError::NotFound(format!(
            "Character {character_id} not found or not accessible by user {user_id_val}"
        )));
    }

    // If session link exists, fetch the character details by character_id only
    info!(
        target: "test_log",
        handler = "get_character_handler",
        %character_id,
        %user_id_val,
        "User has session link. Fetching character by ID."
    );

    let conn_char_fetch = state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;
    let character_id_for_fetch_clone = character_id;

    let character_db_result: Option<Character> = conn_char_fetch
        .interact(move |conn| {
            characters
                .filter(id.eq(character_id_for_fetch_clone))
                .select(Character::as_select())
                .first::<Character>(conn)
                .optional()
                .map_err(|e| {
                    error!(
                        target: "test_log",
                        handler = "get_character_handler (fetch by ID after session auth)",
                        %character_id_for_fetch_clone,
                        error = %e,
                        "DB error fetching character by ID (after session auth)."
                    );
                    AppError::DatabaseQueryError(format!("DB error fetching character by ID: {e}"))
                })
        })
        .await
        .map_err(|e| {
            error!(
                target: "test_log",
                handler = "get_character_handler (fetch by ID interact)",
                %character_id,
                error = %e,
                "Interact dispatch error fetching character by ID."
            );
            AppError::DbInteractError(format!("Interact error fetching character by ID: {e}"))
        })??;

    if let Some(character) = character_db_result {
        info!(
            target: "test_log",
            handler = "get_character_handler",
            %character_id,
            %user_id_val,
            "Character (via session auth) retrieved, attempting decryption"
        );
        // Fetch associated lorebook
        let lorebook_service = LorebookService::new(
            state.pool.clone(),
            state.encryption_service.clone(),
            state.qdrant_service.clone(),
        );
        let lorebooks = lorebook_service
            .list_character_lorebooks(&auth_session, character_id)
            .await?;
        let lorebook_id = lorebooks.first().map(|lb| lb.id);

        match character.into_decrypted_for_client(Some(&dek.0), lorebook_id) {
            Ok(character_for_client) => {
                info!(
                    target: "test_log",
                    handler = "get_character_handler",
                    %character_id,
                    %user_id_val,
                    "Decryption SUCCESSFUL (via session auth)"
                );
                Ok(Json(character_for_client))
            }
            Err(e) => {
                error!(
                    target: "test_log",
                    handler = "get_character_handler",
                    %character_id,
                    %user_id_val,
                    error = ?e,
                    "Decryption FAILED (via session auth)"
                );
                Err(e)
            }
        }
    } else {
        error!(
            target: "test_log",
            handler = "get_character_handler",
            %character_id,
            %user_id_val,
            "Character was linked in a session but now not found in characters table. Data inconsistency or deleted character?"
        );
        Err(AppError::NotFound(format!(
            "Character {character_id} was expected (due to session link) but not found"
        )))
    }
}

// POST /api/characters/generate
#[instrument(skip(_app_state, auth_session, payload), err)]
pub async fn generate_character_handler(
    State(_app_state): State<AppState>,
    auth_session: CurrentAuthSession,
    dek: SessionDek, // Added SessionDek extractor
    Json(payload): Json<GenerateCharacterPayload>,
) -> Result<(StatusCode, Json<CharacterDataForClient>), AppError> {
    // Return CharacterDataForClient
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let user_id_val = user.id;

    info!(%user_id_val, prompt = %payload.prompt, "Generating character requested by user");

    // --- TODO: Implement AI character generation logic ---
    // This will involve creating a NewCharacter, encrypting its description, saving, then fetching and decrypting.

    // Placeholder: Create a dummy Character, encrypt its description, then convert for client.
    let mut dummy_char_for_db = Character {
        // This is a Character struct, not NewCharacter
        id: Uuid::new_v4(),
        user_id: user_id_val,
        spec: "dummy_spec_placeholder".to_string(),
        spec_version: "dummy_spec_version_placeholder".to_string(),
        name: "Generated Placeholder".to_string(),
        description: None, // Will be set after potential encryption
        description_nonce: None,
        personality: Some(b"Placeholder".to_vec()),
        personality_nonce: None,
        scenario: Some(b"Placeholder".to_vec()),
        scenario_nonce: None,
        first_mes: Some(b"Placeholder".to_vec()),
        first_mes_nonce: None,
        mes_example: Some(b"Placeholder".to_vec()),
        mes_example_nonce: None,
        creator_notes: None,
        creator_notes_nonce: None,
        system_prompt: None,
        system_prompt_nonce: None,
        post_history_instructions: None,
        post_history_instructions_nonce: None,
        tags: None,
        creator: None,
        character_version: None,
        alternate_greetings: None,
        nickname: None,
        creator_notes_multilingual: None,
        source: None,
        group_only_greetings: None,
        creation_date: None,
        modification_date: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        persona: None,
        persona_nonce: None,
        world_scenario: None,
        world_scenario_nonce: None,
        avatar: None,
        chat: None,
        greeting: None,
        greeting_nonce: None,
        definition: None,
        definition_nonce: None,
        default_voice: None,
        extensions: None,
        data_id: None,
        category: None,
        definition_visibility: None,
        depth: None,
        example_dialogue: None,
        example_dialogue_nonce: None,
        favorite: None,
        first_message_visibility: None,
        height: None,
        last_activity: None,
        migrated_from: None,
        model_prompt: None,
        model_prompt_nonce: None,
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
        user_persona_nonce: None,
        user_persona_visibility: None,
        visibility: None,
        weight: None,
        world_scenario_visibility: None,
        fav: None,
        world: None,
        creator_comment: None,
        creator_comment_nonce: None,
        depth_prompt: None,
        depth_prompt_depth: None,
        depth_prompt_role: None,
        talkativeness: None,
        depth_prompt_ciphertext: None,
        depth_prompt_nonce: None,
        world_ciphertext: None,
        world_nonce: None,
    };

    let plaintext_desc = format!("Based on prompt: '{}'", payload.prompt);
    if !plaintext_desc.is_empty() {
        match crypto::encrypt_gcm(plaintext_desc.as_bytes(), &dek.0) {
            Ok((ciphertext, nonce)) => {
                dummy_char_for_db.description = Some(ciphertext);
                dummy_char_for_db.description_nonce = Some(nonce);
            }
            Err(e) => {
                tracing::error!("Failed to encrypt dummy character description: {}", e);
                // Potentially return error or proceed with unencrypted description for dummy
            }
        }
    }

    // In a real scenario, we would save dummy_char_for_db (as NewCharacter)
    // then fetch it, then convert to client data.
    // For this placeholder, we convert the in-memory (potentially encrypted) Character.
    let client_data = dummy_char_for_db.into_decrypted_for_client(Some(&dek.0), None)?;

    // --- TODO: Save the character to DB if this route is meant to persist. ---

    Ok((StatusCode::OK, Json(client_data)))
}

// DELETE /api/characters/:id
#[debug_handler]
#[instrument(skip(state, auth_session), err)]
pub async fn delete_character_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    Path(character_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    info!(target: "handler_log", ">>> ENTERING delete_character_handler for character_id: {}", character_id);

    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let local_user_id = user.id;
    info!(target: "handler_log", user_id = %local_user_id, target_character_id = %character_id, "User attempting to DELETE character.");

    let conn = state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let character_exists = conn
        .interact(move |conn_block| {
            tracing::info!(target: "test_log", %character_id, "Checking if character exists at all");
            let exists = characters
                .filter(id.eq(character_id))
                .select(id)  // Just select the ID for efficiency
                .first::<Uuid>(conn_block)
                .optional()
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()));
            exists.map(|opt| opt.is_some())
        })
        .await
        .map_err(|e| AppError::DbInteractError(format!("Interact error checking character: {e}")))?;

    if !character_exists? {
        info!(target: "test_log", %character_id, "Character does not exist at all");
        return Err(AppError::NotFound(format!(
            "Character {character_id} not found"
        )));
    }

    // Character exists, now perform deletion with user_id filter
    info!(%character_id, %local_user_id, "Character exists, performing delete for user");

    let conn = state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let rows_deleted = conn
        .interact(move |conn_block| { // Renamed conn -> conn_block for clarity
            // Log inside interact block too, just in case
            info!(target: "test_log", handler = "delete_character_handler", character_id = %character_id, user_id = %local_user_id, "Executing delete query in interact block"); // Log values used
            let delete_result = diesel::delete(
                characters
                    .filter(id.eq(character_id))
                    .filter(user_id.eq(local_user_id)), // Ensure this user_id_val is correct
            );
            let execution_result = delete_result.execute(conn_block); // Use conn_block
            info!(target: "test_log", handler = "delete_character_handler", character_id = %character_id, user_id = %local_user_id, ?execution_result, "Delete query execution result (inside interact)"); // Log result
            execution_result.map_err(|e| { // Map error after logging
                error!(target: "test_log", handler = "delete_character_handler", character_id = %character_id, user_id = %local_user_id, "Delete query failed: {}", e); // Log DB error
                // Convert DieselError to AppError before returning from interact
                // Note: .execute() returns usize, not typically DieselError::NotFound directly unless the connection fails entirely.
                // The check for 0 rows deleted later handles the "not found" case for the specific character/user combo.
                AppError::DatabaseQueryError(e.to_string())
            })
        })
        .await // First await for interact result
        .map_err(|e| AppError::DbInteractError(format!("Interact error during delete: {e}")))? // Handle interact error
        ?; // Second await for the Result<usize, AppError> inside interact

    // Log the result (rows_deleted)
    info!(target: "test_log", handler = "delete_character_handler", character_id = %character_id, user_id = %local_user_id, rows_deleted = %rows_deleted, "Delete query completed (outside interact)");

    if rows_deleted == 0 {
        // Log why it's returning NotFound
        // This path should ideally not be hit if the query inside interact already returned AppError::NotFound
        // But keep it as a safeguard / for debugging potential logic flaws.
        info!(target: "test_log", handler = "delete_character_handler", %character_id, %local_user_id, "Delete resulted in 0 rows deleted, returning NotFound (or Forbidden if applicable)");
        Err(AppError::NotFound(format!(
            "Character {character_id} not found or not owned by user {local_user_id} (rows_deleted was 0)"
        )))
    } else {
        Ok(StatusCode::NO_CONTENT)
    }
}

// PUT /api/characters/:id - Update an existing character
#[instrument(skip(state, auth_session, dek, update_dto), err)]
pub async fn update_character_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    dek: SessionDek,
    Path(character_id_to_update): Path<Uuid>, // Renamed to avoid conflict
    Json(update_dto): Json<CharacterUpdateDto>,
) -> Result<Json<CharacterDataForClient>, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let local_user_id = user.id;

    // Instantiate services
    let enc_service = Arc::new(EncryptionService::new());
    let lorebook_service = Arc::new(LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    ));
    let character_service =
        CharacterService::new(state.pool.clone(), enc_service, lorebook_service);

    // Call the service method
    let client_data = character_service
        .update_character_details(character_id_to_update, local_user_id, update_dto, &dek)
        .await?;

    Ok(Json(client_data))
}

#[debug_handler]
#[instrument(skip(state, auth_session), err)]
pub async fn get_character_asset_handler(
    Path((character_id, asset_id)): Path<(Uuid, i32)>,
    Query(params): Query<ImageQueryParams>, // Extract query parameters
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
) -> Result<Response<Body>, AppError> {
    trace!(target: "auth_debug", ">>> ENTERING get_character_asset_handler for character_id: {}, asset_id: {}, params: {:?}", character_id, asset_id, params);

    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let local_user_id = user.id;

    tracing::info!(%character_id, %asset_id, %local_user_id, "Fetching character asset for user");

    // First, verify that the character belongs to the user
    let conn = state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let character = conn
        .interact(move |conn_block| {
            characters
                .find(character_id)
                .filter(user_id.eq(local_user_id))
                .select(Character::as_select())
                .first::<Character>(conn_block)
                .optional()
        })
        .await
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Character lookup interaction error: {e}"))
        })?
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Character lookup DB error: {e}"))
        })?;

    let _character = character
        .ok_or_else(|| AppError::NotFound("Character not found or not accessible".to_string()))?;

    // Load the asset from database
    let conn_asset = state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let asset = conn_asset
        .interact(move |conn_asset_block| {
            character_assets
                .find(asset_id)
                .filter(crate::schema::character_assets::character_id.eq(character_id))
                .select(CharacterAsset::as_select())
                .first::<CharacterAsset>(conn_asset_block)
                .optional()
        })
        .await
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Asset lookup interaction error: {e}"))
        })?
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Asset lookup DB error: {e}")))?;

    let asset = asset.ok_or_else(|| AppError::NotFound("Character asset not found".to_string()))?;

    // Get the image data from the asset
    let image_data = asset
        .data
        .ok_or_else(|| AppError::NotFound("Character asset has no image data".to_string()))?;

    // Get content type, default to image/png
    let mut content_type = asset
        .content_type
        .unwrap_or_else(|| "image/png".to_string());
    let mut final_image_data = image_data;

    // Resize image if width or height parameters are provided
    if let (Some(width), Some(height)) = (params.width, params.height) {
        info!(%character_id, %asset_id, %width, %height, "Resizing image asset");
        let format = ImageFormat::from_extension(content_type.split('/').last().unwrap_or("png"))
            .unwrap_or(ImageFormat::Png);

        let decoded_image = ImageReader::with_format(Cursor::new(&final_image_data), format)
            .decode()
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!(
                    "Failed to decode image for resizing: {e}"
                ))
            })?;

        let resized_image =
            decoded_image.resize_exact(width, height, image::imageops::FilterType::Lanczos3);

        let mut buffer = Cursor::new(Vec::new());
        resized_image.write_to(&mut buffer, format).map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to encode resized image: {e}"))
        })?;

        final_image_data = buffer.into_inner();
        // Ensure content type is still correct after re-encoding
        content_type = format!(
            "image/{}",
            format.extensions_str().iter().next().unwrap_or(&"png")
        );
    }

    // Return the image with appropriate headers
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", &content_type)
        .header("Cache-Control", "public, max-age=3600") // Cache for 1 hour
        .body(Body::from(final_image_data.clone()))
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to build response: {e}"))
        })?;

    debug!(character_id = %character_id, asset_id = %asset_id, content_type = %content_type, image_data_len = final_image_data.len(), "Character asset served successfully");
    Ok(response)
}
