// backend/src/routes/characters.rs

use crate::auth::session_dek::SessionDek; // Added SessionDek
use crate::crypto;
use crate::errors::AppError;
use crate::models::character_card::NewCharacter;
use crate::models::characters::{Character, CharacterDataForClient}; // Added CharacterDataForClient // Added crypto for encrypt_gcm
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
    routing::{delete, get, post, put}, // ADDED delete here
};
use diesel::prelude::*; // Needed for .filter(), .load(), .first(), etc.
use tracing::{error, info, instrument, trace}; // Use needed tracing macros, ADDED error, warn
use uuid::Uuid;
// use anyhow::anyhow; // Unused import
use crate::auth::user_store::Backend as AuthBackend; // <-- Import the backend type
use crate::schema::chat_sessions;
use crate::services::encryption_service::EncryptionService; // Added import
use axum::body::Bytes;
use axum_login::AuthSession; // <-- Removed login_required import
use diesel::RunQueryDsl;
use diesel::SelectableHelper;
use diesel::result::Error as DieselError; // Add import for DieselError
use secrecy::ExposeSecret; // Added for DEK expose
use secrecy::SecretBox; // <<<<<<< ADDED SecretBox IMPORT HERE
use serde::Deserialize; // Add serde import // Added for querying chat_sessions table
use crate::models::character_dto::{CharacterCreateDto, CharacterUpdateDto}; // Added DTO imports
use diesel_json; // Added import for diesel_json

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
) -> Result<(StatusCode, Json<CharacterDataForClient>), AppError> {
    // Return CharacterDataForClient
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
    // Note: NewCharacter struct might not have all these _nonce fields yet.
    // This will be addressed by updating NewCharacter definition in models/character_card.rs next.

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
            AppError::InternalServerErrorGeneric(format!("Insert interaction error: {}", e))
        })?
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Insert DB error: {}", e)))?;

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
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Fetch interaction error: {}", e))
        })?
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Fetch DB error: {}", e)))?;

    info!(character_id = %inserted_character.id, "Character uploaded and saved (full data fetched)");

    let client_character_data = inserted_character
        .into_decrypted_for_client(Some(&dek.0))
        .await?;

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

    // Validate the DTO
    if let Err(validation_error) = create_dto.validate() {
        return Err(AppError::BadRequest(validation_error));
    }

    // Create EncryptionService for encrypting fields
    let enc_service = EncryptionService::new();

    // Helper function to encrypt a non-empty string field
    async fn encrypt_string_field(
        enc_service: &EncryptionService,
        plaintext: &str,
        dek_key: &SecretBox<Vec<u8>>,
    ) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), AppError> {
        if plaintext.is_empty() {
            Ok((None, None))
        } else {
            let (ciphertext, nonce) = enc_service
                .encrypt(plaintext, dek_key.expose_secret())
                .await
                .map_err(|e| AppError::EncryptionError(format!("Encryption failed: {}", e)))?;
            Ok((Some(ciphertext), Some(nonce)))
        }
    }

    // Encrypt fields from DTO
    let (description_enc, description_nonce_enc) = encrypt_string_field(
        &enc_service, 
        create_dto.description.as_deref().expect("Description guaranteed by validation"), 
        &dek.0
    ).await?;
    let (personality_enc, personality_nonce_enc) = encrypt_string_field(&enc_service, &create_dto.personality, &dek.0).await?;
    let (scenario_enc, scenario_nonce_enc) = encrypt_string_field(&enc_service, &create_dto.scenario, &dek.0).await?;
    let (first_mes_enc, first_mes_nonce_enc) = encrypt_string_field(
        &enc_service, 
        create_dto.first_mes.as_deref().expect("First message guaranteed by validation"), 
        &dek.0
    ).await?;
    let (mes_example_enc, mes_example_nonce_enc) = encrypt_string_field(&enc_service, &create_dto.mes_example, &dek.0).await?;
    let (creator_notes_enc, creator_notes_nonce_enc) = encrypt_string_field(&enc_service, &create_dto.creator_notes, &dek.0).await?;
    let (system_prompt_enc, system_prompt_nonce_enc) = encrypt_string_field(&enc_service, &create_dto.system_prompt, &dek.0).await?;
    let (post_history_instructions_enc, post_history_instructions_nonce_enc) = encrypt_string_field(&enc_service, &create_dto.post_history_instructions, &dek.0).await?;

    // Create a NewCharacter from the DTO
    let new_character = NewCharacter {
        user_id: local_user_id,
        name: create_dto.name.expect("Name should be present after validation"),
        spec: "chara_card_v3".to_string(),
        spec_version: "3.0".to_string(),
        description: description_enc,
        description_nonce: description_nonce_enc,
        personality: personality_enc,
        personality_nonce: personality_nonce_enc,
        scenario: scenario_enc,
        scenario_nonce: scenario_nonce_enc,
        first_mes: first_mes_enc,
        first_mes_nonce: first_mes_nonce_enc,
        mes_example: mes_example_enc,
        mes_example_nonce: mes_example_nonce_enc,
        creator_notes: creator_notes_enc,
        creator_notes_nonce: creator_notes_nonce_enc,
        system_prompt: system_prompt_enc,
        system_prompt_nonce: system_prompt_nonce_enc,
        post_history_instructions: post_history_instructions_enc,
        post_history_instructions_nonce: post_history_instructions_nonce_enc,
        tags: if create_dto.tags.is_empty() { None } else { Some(create_dto.tags.into_iter().map(Some).collect()) },
        creator: if create_dto.creator.is_empty() { None } else { Some(create_dto.creator) },
        character_version: if create_dto.character_version.is_empty() { None } else { Some(create_dto.character_version) },
        alternate_greetings: if create_dto.alternate_greetings.is_empty() { None } else { Some(create_dto.alternate_greetings.into_iter().map(Some).collect()) },
        creator_notes_multilingual: create_dto.creator_notes_multilingual.map(|j| diesel_json::Json(j.0)), // Extract Value and wrap in Json
        nickname: create_dto.nickname,
        source: create_dto.source.and_then(|s| if s.is_empty() { None } else { Some(s.into_iter().map(Some).collect()) }),
        group_only_greetings: if create_dto.group_only_greetings.is_empty() { None } else { Some(create_dto.group_only_greetings.into_iter().map(Some).collect()) },
        creation_date: create_dto.creation_date.and_then(|ts| chrono::DateTime::from_timestamp(ts, 0)),
        modification_date: create_dto.modification_date.and_then(|ts| chrono::DateTime::from_timestamp(ts, 0)), // User can provide, else DB default or updated_at logic might handle
        extensions: create_dto.extensions.map(|j| diesel_json::Json(j.0)).or_else(|| Some(diesel_json::Json(serde_json::json!({})))), // Extract Value and wrap in Json, then ensure it's diesel_json::Json
        // Fields from CharacterCardDataV3 not in CharacterCreateDto default to None or DB defaults
        persona: None,
        persona_nonce: None,
        world_scenario: None,
        world_scenario_nonce: None,
        avatar: None, // Assuming no avatar for manual creation initially
        chat: None, // Placeholder, might be related to specific chat integration
        greeting: None, // first_mes is the primary greeting
        greeting_nonce: None,
        definition: None,
        definition_nonce: None,
        // tavern spec fields / other common fields, defaulting to None
        default_voice: None,
        category: None,
        definition_visibility: None,
        example_dialogue: None,
        example_dialogue_nonce: None,
        favorite: None,
        first_message_visibility: None,
        migrated_from: None,
        model_prompt: None,
        model_prompt_nonce: None,
        model_prompt_visibility: None,
        persona_visibility: None,
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
        world_scenario_visibility: None,
        created_at: Some(chrono::Utc::now()),
        updated_at: Some(chrono::Utc::now()),
    };

    info!(?new_character.name, user_id = %local_user_id, "Attempting to insert manually created character into DB for user");

    // Insert the character into the database
    let conn_insert_op = state.pool.get().await.map_err(|e| AppError::DbPoolError(e.to_string()))?;
    let returned_id: Uuid = conn_insert_op
        .interact(move |conn_insert_block| {
            diesel::insert_into(characters)
                .values(new_character)
                .returning(id)
                .get_result::<Uuid>(conn_insert_block)
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Insert interaction error: {}", e)))?
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Insert DB error: {}", e)))?;

    info!(character_id = %returned_id, "Character basic info returned after manual insertion");

    // Fetch the inserted character to return its full data
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

    info!(character_id = %inserted_character.id, "Character manually created and saved (full data fetched)");

    // Convert to client format with decryption
    let client_character_data = inserted_character.into_decrypted_for_client(Some(&dek.0)).await?;

    Ok((StatusCode::CREATED, Json(client_character_data)))
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
        characters_for_client.push(char_db.into_decrypted_for_client(Some(&dek.0)).await?);
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
                    "Interact error during direct ownership character fetch: {}",
                    interact_err
                ))
            })?;

    match directly_owned_character_result {
        Ok(Some(character)) => {
            info!(target: "test_log", handler = "get_character_handler", %character_id, %user_id_val, "Character directly owned, attempting decryption");
            return match character.into_decrypted_for_client(Some(&dek.0)).await {
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
            .or_else(|e| match e {
                DieselError::NotFound => {
                     error!(
                        target: "test_log",
                        handler = "get_character_handler (session link exists query)",
                        %character_id_for_session_clone,
                        %user_id_for_session_clone,
                        error = %e,
                        "DieselError::NotFound encountered unexpectedly for exists query. Interpreting as false."
                    );
                    Ok(false)
                },
                _ => {
                    error!(
                        target: "test_log",
                        handler = "get_character_handler (session link exists query)",
                        %character_id_for_session_clone,
                        %user_id_for_session_clone,
                        error = %e,
                        "DB error checking session link."
                    );
                    Err(AppError::DatabaseQueryError(format!("DB error checking session link: {}", e)))
                }
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
            AppError::DbInteractError(format!("Interact error checking session link: {}", e))
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
            "Character {} not found or not accessible by user {}",
            character_id, user_id_val
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
                    AppError::DatabaseQueryError(format!(
                        "DB error fetching character by ID: {}",
                        e
                    ))
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
            AppError::DbInteractError(format!("Interact error fetching character by ID: {}", e))
        })??;

    match character_db_result {
        Some(character) => {
            info!(
                target: "test_log",
                handler = "get_character_handler",
                %character_id,
                %user_id_val,
                "Character (via session auth) retrieved, attempting decryption"
            );
            match character.into_decrypted_for_client(Some(&dek.0)).await {
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
        }
        None => {
            error!(
                target: "test_log",
                handler = "get_character_handler",
                %character_id,
                %user_id_val,
                "Character was linked in a session but now not found in characters table. Data inconsistency or deleted character?"
            );
            Err(AppError::NotFound(format!(
                "Character {} was expected (due to session link) but not found",
                character_id
            )))
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
    let client_data = dummy_char_for_db
        .into_decrypted_for_client(Some(&dek.0))
        .await?;

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
        .map_err(|e| AppError::DbInteractError(format!("Interact error checking character: {}", e)))?;

    if !character_exists? {
        info!(target: "test_log", %character_id, "Character does not exist at all");
        return Err(AppError::NotFound(format!(
            "Character {} not found",
            character_id
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
    info!(target: "test_log", handler = "delete_character_handler", character_id = %character_id, user_id = %local_user_id, rows_deleted = %rows_deleted, "Delete query completed (outside interact)");

    if rows_deleted == 0 {
        // Log why it's returning NotFound
        // This path should ideally not be hit if the query inside interact already returned AppError::NotFound
        // But keep it as a safeguard / for debugging potential logic flaws.
        info!(target: "test_log", handler = "delete_character_handler", %character_id, %local_user_id, "Delete resulted in 0 rows deleted, returning NotFound (or Forbidden if applicable)");
        Err(AppError::NotFound(format!(
            "Character {} not found or not owned by user {} (rows_deleted was 0)",
            character_id, local_user_id
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

    info!(character_id = %character_id_to_update, user_id = %local_user_id, "Attempting to update character");

    // Fetch the existing character from the database to verify ownership
    let conn_fetch_op = state.pool.get().await.map_err(|e| AppError::DbPoolError(e.to_string()))?;
    
    // Clone necessary items for the interact closure
    let char_id_for_fetch = character_id_to_update;
    let user_id_for_fetch = local_user_id;

    let mut existing_character: Character = conn_fetch_op
        .interact(move |conn_select_block| {
            characters
                .filter(id.eq(char_id_for_fetch).and(user_id.eq(user_id_for_fetch)))
                .select(Character::as_select())
                .get_result::<Character>(conn_select_block)
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Fetch interaction error: {}", e)))?
        .map_err(|e| match e {
            DieselError::NotFound => AppError::NotFound(format!(
                "Character {} not found or not owned by user {}",
                char_id_for_fetch, user_id_for_fetch
            )),
            _ => AppError::InternalServerErrorGeneric(format!("Fetch DB error: {}", e)),
        })?;

    info!(character_id = %character_id_to_update, "Found character to update, applying changes");

    let enc_service = EncryptionService::new();

    // Helper for updating an encrypted field
    async fn update_encrypted_string_field(
        enc_service: &EncryptionService,
        dto_field_value: &Option<String>,
        dek_key: &SecretBox<Vec<u8>>,
        current_ciphertext: &mut Option<Vec<u8>>,
        current_nonce: &mut Option<Vec<u8>>,
    ) -> Result<(), AppError> {
        if let Some(plaintext) = dto_field_value {
            if plaintext.is_empty() {
                *current_ciphertext = None;
                *current_nonce = None;
            } else {
                let (new_ciphertext, new_nonce) = enc_service
                    .encrypt(plaintext, dek_key.expose_secret())
                    .await
                    .map_err(|e| AppError::EncryptionError(format!("Encryption failed: {}", e)))?;
                *current_ciphertext = Some(new_ciphertext);
                *current_nonce = Some(new_nonce);
            }
        }
        Ok(())
    }

    // Apply updates from DTO
    if let Some(name_val) = update_dto.name {
        existing_character.name = name_val;
    }
    update_encrypted_string_field(&enc_service, &update_dto.description, &dek.0, &mut existing_character.description, &mut existing_character.description_nonce).await?;
    update_encrypted_string_field(&enc_service, &update_dto.personality, &dek.0, &mut existing_character.personality, &mut existing_character.personality_nonce).await?;
    update_encrypted_string_field(&enc_service, &update_dto.scenario, &dek.0, &mut existing_character.scenario, &mut existing_character.scenario_nonce).await?;
    update_encrypted_string_field(&enc_service, &update_dto.first_mes, &dek.0, &mut existing_character.first_mes, &mut existing_character.first_mes_nonce).await?;
    update_encrypted_string_field(&enc_service, &update_dto.mes_example, &dek.0, &mut existing_character.mes_example, &mut existing_character.mes_example_nonce).await?;
    update_encrypted_string_field(&enc_service, &update_dto.creator_notes, &dek.0, &mut existing_character.creator_notes, &mut existing_character.creator_notes_nonce).await?;
    update_encrypted_string_field(&enc_service, &update_dto.system_prompt, &dek.0, &mut existing_character.system_prompt, &mut existing_character.system_prompt_nonce).await?;
    update_encrypted_string_field(&enc_service, &update_dto.post_history_instructions, &dek.0, &mut existing_character.post_history_instructions, &mut existing_character.post_history_instructions_nonce).await?;
    
    if let Some(tags_val) = update_dto.tags {
        existing_character.tags = if tags_val.is_empty() { None } else { Some(tags_val.into_iter().map(Some).collect()) };
    }
    if let Some(creator_val) = update_dto.creator {
        existing_character.creator = if creator_val.is_empty() { None } else { Some(creator_val) };
    }
    if let Some(cv_val) = update_dto.character_version {
        existing_character.character_version = if cv_val.is_empty() { None } else { Some(cv_val) };
    }
    if let Some(ag_val) = update_dto.alternate_greetings {
        existing_character.alternate_greetings = if ag_val.is_empty() { None } else { Some(ag_val.into_iter().map(Some).collect()) };
    }
    if let Some(cnm_val) = update_dto.creator_notes_multilingual {
        existing_character.creator_notes_multilingual = Some(cnm_val.0);
    }
    if let Some(nick_val) = update_dto.nickname { // Nickname is Option<String> in model
        existing_character.nickname = Some(nick_val);
    }
    if let Some(source_val) = update_dto.source {
        existing_character.source = if source_val.is_empty() { None } else { Some(source_val.into_iter().map(Some).collect()) };
    }
    if let Some(gog_val) = update_dto.group_only_greetings {
        existing_character.group_only_greetings = if gog_val.is_empty() { None } else { Some(gog_val.into_iter().map(Some).collect()) };
    }
    if let Some(cd_ts) = update_dto.creation_date {
        existing_character.creation_date = chrono::DateTime::from_timestamp(cd_ts, 0);
    }
     // modification_date is handled by updated_at or explicit DTO field
    if let Some(md_ts) = update_dto.modification_date { // if user explicitly provides it
        existing_character.modification_date = chrono::DateTime::from_timestamp(md_ts, 0);
    }

    if let Some(ext_val) = update_dto.extensions {
        existing_character.extensions = Some(ext_val.0);
    }

    // Always update the 'updated_at' timestamp
    existing_character.updated_at = chrono::Utc::now();
    // Also update modification_date if it's distinct or meant to be the primary user-facing mod date
    // As per plan, "Update the modification_date field". Assuming this is distinct from updated_at for system tracking.
    // If modification_date wasn't set by DTO, set it now.
    if update_dto.modification_date.is_none() {
        existing_character.modification_date = Some(chrono::Utc::now());
    }


    // Save the updated character
    let conn_update_op = state.pool.get().await.map_err(|e| AppError::DbPoolError(e.to_string()))?;
    let char_id_for_update = character_id_to_update; // Use the original Path parameter
    
    let updated_character_db: Character = conn_update_op
        .interact(move |conn_update_block| {
            diesel::update(characters.find(char_id_for_update))
                .set(existing_character.clone()) // Pass the modified existing_character by cloning
                .returning(Character::as_select())
                .get_result::<Character>(conn_update_block)
        })
        .await
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Update interaction error: {}", e)))?
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Update DB error: {}", e)))?;

    info!(character_id = %character_id_to_update, "Character updated successfully");

    // Convert to client format with decryption
    let client_character_data = updated_character_db.into_decrypted_for_client(Some(&dek.0)).await?;

    Ok(Json(client_character_data))
}

// --- Character Router ---
pub fn characters_router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/upload", post(upload_character_handler))
        .route("/", get(list_characters_handler).post(create_character_handler)) // Added POST for manual creation
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
        .route("/:id/image", get(get_character_image)) // This might also need a more distinct path later
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
