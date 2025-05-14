// backend/src/routes/characters.rs

use crate::errors::AppError;
use crate::models::character_card::NewCharacter;
use crate::models::characters::{Character, CharacterDataForClient}; // Added CharacterDataForClient
use crate::auth::session_dek::SessionDek; // Added SessionDek
use crate::crypto; // Added crypto for encrypt_gcm
// use crate::models::users::User; // Removed unused import
use crate::schema::characters::dsl::*; // DSL needed for table/columns
use crate::services::character_parser::{self};
use crate::state::AppState;
use axum::{
    Router,
    body::Body,
    debug_handler,
    extract::{Path, State, multipart::Multipart}, // Removed unused Extension
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
};
use diesel::prelude::*; // Needed for .filter(), .load(), .first(), etc.
use tracing::{info, instrument, trace, error, warn}; // Use needed tracing macros, ADDED error, warn
use uuid::Uuid;
// use anyhow::anyhow; // Unused import
use crate::auth::user_store::Backend as AuthBackend; // <-- Import the backend type
use axum::body::Bytes;
use axum_login::AuthSession; // <-- Removed login_required import
use diesel::RunQueryDsl;
use diesel::SelectableHelper;
use diesel::result::Error as DieselError; // Add import for DieselError
use serde::Deserialize; // Add serde import
use crate::services::encryption_service::EncryptionService; // Added import
use secrecy::ExposeSecret; // Added for DEK expose

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
    auth_session: CurrentAuthSession,
    dek: SessionDek, // Added SessionDek extractor
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<CharacterDataForClient>), AppError> { // Return CharacterDataForClient
    // Get the user from the session
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let local_user_id = user.id;

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
    let png_data = file_data.ok_or_else(|| {
        AppError::BadRequest("Missing 'character_card' field in upload".to_string())
    })?;

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
                                match enc_service
                                    .encrypt(&string_version, $dek.expose_secret())
                                    .await
                                {
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
                                            "Encryption failed for {}: {}",
                                            stringify!($field),
                                            e
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
    encrypt_field!(new_character_for_db, creator_notes, creator_notes_nonce, &dek.0);
    encrypt_field!(new_character_for_db, system_prompt, system_prompt_nonce, &dek.0);
    encrypt_field!(new_character_for_db, persona, persona_nonce, &dek.0);
    encrypt_field!(new_character_for_db, world_scenario, world_scenario_nonce, &dek.0);
    encrypt_field!(new_character_for_db, greeting, greeting_nonce, &dek.0);
    encrypt_field!(new_character_for_db, definition, definition_nonce, &dek.0);
    encrypt_field!(new_character_for_db, example_dialogue, example_dialogue_nonce, &dek.0);
    encrypt_field!(new_character_for_db, model_prompt, model_prompt_nonce, &dek.0);
    encrypt_field!(new_character_for_db, user_persona, user_persona_nonce, &dek.0);
    // Note: NewCharacter struct might not have all these _nonce fields yet.
    // This will be addressed by updating NewCharacter definition in models/character_card.rs next.

    info!(?new_character_for_db.name, user_id = %local_user_id, "Attempting to insert character into DB for user");

    let conn_insert_op = state.pool.get().await.map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let returned_id: Uuid = conn_insert_op
        .interact(move |conn_insert_block| {
            diesel::insert_into(characters)
                .values(new_character_for_db)
                .returning(id)
                .get_result::<Uuid>(conn_insert_block)
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Insert interaction error: {}", e)))?
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Insert DB error: {}", e)))?;

    info!(character_id = %returned_id, "Character basic info returned after insert");

    let conn_fetch_op = state.pool.get().await.map_err(|e| AppError::DbPoolError(e.to_string()))?;
    let inserted_character: Character = conn_fetch_op
        .interact(move |conn_select_block| {
            characters
                .find(returned_id)
                .select(Character::as_select())
                .get_result::<Character>(conn_select_block)
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Fetch interaction error: {}", e)))?
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Fetch DB error: {}", e)))?;

    info!(character_id = %inserted_character.id, "Character uploaded and saved (full data fetched)");

    let client_character_data = inserted_character.into_decrypted_for_client(Some(&dek.0)).await?;

    Ok((StatusCode::CREATED, Json(client_character_data)))
}

// GET /api/characters
#[instrument(skip(state, auth_session, dek), err)]
pub async fn list_characters_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    dek: SessionDek, // Added SessionDek extractor
) -> Result<Json<Vec<CharacterDataForClient>>, AppError> { // Return Vec<CharacterDataForClient>
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let local_user_id = user.id;

    info!(%local_user_id, "Listing characters for user");

    let conn = state.pool.get().await.map_err(|e| AppError::DbPoolError(e.to_string()))?;

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
        characters_for_client.push(char_db.into_decrypted_for_client(Some(&dek.0)).await?);
    }

    Ok(Json(characters_for_client))
}

// GET /api/characters/:id
#[instrument(skip(state, auth_session, dek), err)]
pub async fn get_character_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    dek: SessionDek,
    Path(character_id): Path<Uuid>,
) -> Result<Json<CharacterDataForClient>, AppError> {
    trace!(target: "auth_debug", ">>> ENTERING get_character_handler for character_id: {}", character_id);
    
    // --- BEGIN TEST LOGGING for test_delete_character_forbidden ---
    let user_for_get_opt = auth_session.user.clone(); // Clone to log
    if let Some(ref user_for_get) = user_for_get_opt {
        info!(
            target: "test_log",
            handler = "get_character_handler_ENTRY",
            requesting_user_id = %user_for_get.id,
            target_character_id = %character_id,
            dek_present = true, // If this handler is called, DEK was extracted
            "User trying to GET character."
        );
        if let Some(ref dek_inner) = user_for_get.dek {
             info!(
                target: "test_log",
                handler = "get_character_handler_ENTRY",
                requesting_user_id = %user_for_get.id,
                target_character_id = %character_id,
                dek_bytes_len = dek_inner.expose_secret_bytes().len(),
                "DEK details from auth_session.user.dek"
            );
        } else {
            warn!(
                target: "test_log",
                handler = "get_character_handler_ENTRY",
                requesting_user_id = %user_for_get.id,
                target_character_id = %character_id,
                "DEK is NONE in auth_session.user.dek"
            );
        }
    } else {
        warn!(
            target: "test_log",
            handler = "get_character_handler_ENTRY",
            target_character_id = %character_id,
            "No user in auth_session for GET request."
        );
    }
    // --- END TEST LOGGING ---

    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let user_id_val = user.id;

    // Add detailed logging
    info!(target: "test_log", %character_id, %user_id_val, "Fetching character for user");

    // First check if the character exists at all, regardless of user
    let conn = state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let character_exists_at_all = conn
        .interact(move |conn_block| {
            tracing::info!(target: "test_log", %character_id, "Checking if character exists at all");
            
            let exists = characters
                .filter(id.eq(character_id))
                .select(id)  // Just select the ID for efficiency
                .first::<Uuid>(conn_block)
                .optional()
                .map_err(|e| {
                    tracing::error!(target: "test_log", %character_id, error = %e, "Character existence check failed");
                    AppError::DatabaseQueryError(e.to_string())
                });
                
            exists.map(|opt| opt.is_some())
        })
        .await
        .map_err(|e| AppError::DbInteractError(format!("Interact error checking character existence: {}", e)))?;
        
    if !character_exists_at_all? {
        info!(target: "test_log", %character_id, "Character does not exist at all");
        return Err(AppError::NotFound(format!("Character {} not found", character_id)));
    }
    
    info!(target: "test_log", %character_id, "Character exists in database, attempting to fetch for specific user");

    // Now attempt to fetch the character if it's owned by this specific user
    let conn_fetch = state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let character_owned_result = conn_fetch
        .interact(move |conn_block| {
            info!(
                target: "test_log",
                handler = "get_character_handler",
                %character_id,
                %user_id_val,
                "Executing character query (ID and UserID combined using .and()) in interact block"
            );

            characters
                .filter(id.eq(character_id).and(user_id.eq(user_id_val))) // Combined filter
                .select(Character::as_select())
                .first::<Character>(conn_block)
                .optional() // Converts DieselError::NotFound to Ok(None), other errors to Err
                .map_err(|e| {
                    error!(
                        target: "test_log",
                        handler = "get_character_handler",
                        %character_id,
                        %user_id_val,
                        error = %e,
                        "DB error during combined (ID and UserID) character query."
                    );
                    // Ensure we map DieselError to our AppError type
                    match e {
                        DieselError::NotFound => {
                            // This case should ideally be handled by .optional() resulting in Ok(None)
                            // Logging it here if it somehow bypasses .optional() as an Err.
                            warn!(
                                target: "test_log",
                                handler = "get_character_handler",
                                %character_id,
                                %user_id_val,
                                "DieselError::NotFound encountered directly, though .optional() should prevent this."
                            );
                            // This path might not be strictly necessary if .optional() behaves as expected,
                            // but doesn't hurt to map it for completeness if Diesel changes behavior.
                            // However, for AppError::NotFound, we typically want to return Ok(None) from the closure.
                            // The current .optional() should make this arm of the match unreachable for NotFound.
                            // Let's rely on .optional() and map other errors to DatabaseQueryError.
                            // If it's any other error, map it to DatabaseQueryError.
                            AppError::DatabaseQueryError(e.to_string())
                        }
                        _ => AppError::DatabaseQueryError(e.to_string()),
                    }
                })
        })
        .await // For the outer Result from interact (e.g., PoolError)
        .map_err(|interact_err| { // This handles errors from the .interact() call itself
            error!(
                target: "test_log",
                handler = "get_character_handler",
                %character_id,
                %user_id_val,
                error = ?interact_err,
                "Interact error during combined character fetch."
            );
            AppError::DbInteractError(format!("Interact error during combined character fetch: {}", interact_err))
        })?; // For the Result<_, DeadPoolError>

    // character_owned_result is now Result<Option<Character>, AppError> (if interact succeeded)
    // or this point is not reached if interact itself failed (e.g. pool error).
    // The '?' above handles the interact error. So character_owned_result is the Result from the closure.

    match character_owned_result {
        Ok(Some(character)) => { // Character found and owned as per the combined query
            info!(target: "test_log", handler = "get_character_handler", %character_id, %user_id_val, "Character (owned) retrieved via combined query, attempting decryption");
            match character.into_decrypted_for_client(Some(&dek.0)).await {
                Ok(character_for_client) => {
                    info!(target: "test_log", handler = "get_character_handler", %character_id, %user_id_val, "Decryption SUCCESSFUL");
                    Ok(Json(character_for_client))
                }
                Err(e) => { // This is AppError from decryption
                    error!(target: "test_log", handler = "get_character_handler", %character_id, %user_id_val, error = ?e, "Decryption FAILED");
                    Err(e)
                }
            }
        }
        Ok(None) => { // Character not found for this user by the combined query (due to .optional())
            info!(target: "test_log", handler = "get_character_handler", %character_id, %user_id_val, "Character not found for user by combined query (or owner mismatch), returning NotFound");
            Err(AppError::NotFound(format!(
                "Character {} not found or not accessible by user {}", // Clearer message
                character_id, user_id_val
            )))
        }
        Err(app_err) => { // Error from the closure inside interact (e.g., mapped DatabaseQueryError)
            error!(target: "test_log", handler = "get_character_handler", %character_id, %user_id_val, error = ?app_err, "Error from interact block (e.g. DB query error) with combined query, propagating");
            Err(app_err)
        }
    }
}

// POST /api/characters/generate
#[instrument(skip(_app_state, auth_session, payload), err)]
pub async fn generate_character_handler(
    State(_app_state): State<AppState>,
    auth_session: CurrentAuthSession,
    dek: SessionDek, // Added SessionDek extractor
    Json(payload): Json<GenerateCharacterPayload>,
) -> Result<(StatusCode, Json<CharacterDataForClient>), AppError> { // Return CharacterDataForClient
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let user_id_val = user.id;

    info!(%user_id_val, prompt = %payload.prompt, "Generating character requested by user");

    // --- TODO: Implement AI character generation logic ---
    // This will involve creating a NewCharacter, encrypting its description, saving, then fetching and decrypting.

    // Placeholder: Create a dummy Character, encrypt its description, then convert for client.
    let mut dummy_char_for_db = Character { // This is a Character struct, not NewCharacter
        id: Uuid::new_v4(),
        user_id: user_id_val,
        spec: "dummy_spec_placeholder".to_string(),
        spec_version: "dummy_spec_version_placeholder".to_string(),
        name: "Generated Placeholder".to_string(),
        description: None, // Will be set after potential encryption
        description_nonce: None,
        personality: Some("Placeholder".as_bytes().to_vec()),
        personality_nonce: None,
        scenario: Some("Placeholder".as_bytes().to_vec()),
        scenario_nonce: None,
        first_mes: Some("Placeholder".as_bytes().to_vec()),
        first_mes_nonce: None,
        mes_example: Some("Placeholder".as_bytes().to_vec()),
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
    let client_data = dummy_char_for_db.into_decrypted_for_client(Some(&dek.0)).await?;

    // --- TODO: Save the character to DB if this route is meant to persist. ---

    Ok((StatusCode::OK, Json(client_data)))
}

// DELETE /api/characters/:id
#[instrument(skip(state, auth_session), err)]
pub async fn delete_character_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    Path(character_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    trace!(target: "auth_debug", ">>> ENTERING delete_character_handler for character_id: {}", character_id);
    
    // --- BEGIN TEST LOGGING for test_delete_character_forbidden ---
    let user_for_delete_opt = auth_session.user.clone(); // Clone to log
    if let Some(ref user_for_delete) = user_for_delete_opt {
        info!(
            target: "test_log",
            handler = "delete_character_handler_ENTRY",
            requesting_user_id = %user_for_delete.id,
            target_character_id = %character_id,
            "User trying to DELETE character."
        );
    } else {
        warn!(
            target: "test_log",
            handler = "delete_character_handler_ENTRY",
            target_character_id = %character_id,
            "No user in auth_session for DELETE request."
        );
    }
    // --- END TEST LOGGING ---

    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let user_id_val = user.id;

    // Add logging here
    info!(target: "test_log", handler = "delete_character_handler", %character_id, %user_id_val, "Attempting delete query by authenticated user");

    // First, verify the character exists at all
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
        .map_err(|e| AppError::DbInteractError(format!("Interact error checking character: {}", e)))?;
        
    if !character_exists? {
        info!(target: "test_log", %character_id, "Character does not exist at all");
        return Err(AppError::NotFound(format!("Character {} not found", character_id)));
    }
    
    // Character exists, now perform deletion with user_id filter
    info!(%character_id, %user_id_val, "Character exists, performing delete for user");

    let conn = state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?;

    let rows_deleted = conn
        .interact(move |conn_block| { // Renamed conn -> conn_block for clarity
            // Log inside interact block too, just in case
            info!(target: "test_log", handler = "delete_character_handler", character_id = %character_id, user_id = %user_id_val, "Executing delete query in interact block"); // Log values used
            let delete_result = diesel::delete(
                characters
                    .filter(id.eq(character_id))
                    .filter(user_id.eq(user_id_val)), // Ensure this user_id_val is correct
            );
            
            let execution_result = delete_result.execute(conn_block); // Use conn_block
            info!(target: "test_log", handler = "delete_character_handler", character_id = %character_id, user_id = %user_id_val, ?execution_result, "Delete query execution result (inside interact)"); // Log result
            execution_result.map_err(|e| { // Map error after logging
                error!(target: "test_log", handler = "delete_character_handler", character_id = %character_id, user_id = %user_id_val, "Delete query failed: {}", e); // Log DB error
                // Convert DieselError to AppError before returning from interact
                match e {
                    // Note: .execute() returns usize, not typically DieselError::NotFound directly unless the connection fails entirely.
                    // The check for 0 rows deleted later handles the "not found" case for the specific character/user combo.
                    _ => AppError::DatabaseQueryError(e.to_string()),
                }
            })
        })
        .await // First await for interact result
        .map_err(|e| AppError::DbInteractError(format!("Interact error during delete: {}", e)))? // Handle interact error
        ?; // Second await for the Result<usize, AppError> inside interact

    // Log the result (rows_deleted)
    info!(target: "test_log", handler = "delete_character_handler", character_id = %character_id, user_id = %user_id_val, rows_deleted = %rows_deleted, "Delete query completed (outside interact)");

    if rows_deleted == 0 {
        // Log why it's returning NotFound
        // This path should ideally not be hit if the query inside interact already returned AppError::NotFound
        // But keep it as a safeguard / for debugging potential logic flaws.
        info!(target: "test_log", handler = "delete_character_handler", %character_id, %user_id_val, "Delete resulted in 0 rows deleted, returning NotFound (or Forbidden if applicable)");
        Err(AppError::NotFound(format!(
            "Character {} not found or not owned by user {} (rows_deleted was 0)",
            character_id, user_id_val
        )))
    } else {
        Ok(StatusCode::NO_CONTENT)
    }
}

// --- Character Router ---
pub fn characters_router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/upload", post(upload_character_handler))
        .route("/", get(list_characters_handler))
        // Combine GET and DELETE for the same path parameter using method routing
        .route("/{id}", get(get_character_handler).delete(delete_character_handler))
        .route("/generate", post(generate_character_handler))
        .route("/{id}/image", get(get_character_image)) // Add image route
        // Apply LoginRequired middleware to all routes in this router
        // It checks auth_session.user and returns 401 if None.
        .with_state(state)
}

#[debug_handler]
#[instrument(skip(_state, auth_session), err)] // Add instrument macro
pub async fn get_character_image(
    Path(character_id): Path<Uuid>,
    State(_state): State<AppState>,
    auth_session: CurrentAuthSession, // Use AuthSession
) -> Result<Response<Body>, AppError> {
    trace!(target: "auth_debug", ">>> ENTERING get_character_image for character_id: {}", character_id); // ADDED TRACE
    // Get the user from the session
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let local_user_id = user.id; // Get ID from the user struct

    tracing::info!(%character_id, %local_user_id, "Fetching character image for user"); // Update log

    // TODO: Implement actual logic to fetch the image data
    // This would involve querying the database or file storage based on character_id and local_user_id
    // For now, return a placeholder response or error

    Err(AppError::NotImplemented(
        "Character image retrieval not yet implemented".to_string(),
    ))
}
