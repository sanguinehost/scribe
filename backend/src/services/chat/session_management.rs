use std::sync::Arc;

use diesel::{prelude::*, result::Error as DieselError};
use secrecy::{ExposeSecret, SecretBox};
use tracing::{error, info, instrument, warn};
use uuid::Uuid;

use crate::{
    AppState,
    errors::AppError,
    models::{
        characters::Character,
        chats::{
            Chat,
            ChatMode,
            MessageRole,
            // ChatSessionSettings, // Removed, settings are part of Chat struct
            // HistoryManagementStrategy, // Removed, strategy is a field in Chat struct
        },
    },
    schema::{characters, chat_session_lorebooks, chat_sessions, users::dsl as users_dsl},
    state::DbPool,
};

use super::message_handling::{SaveMessageParams, save_message};

/// Type alias for session creation result
type SessionCreationResult = Result<(Chat, Option<Vec<u8>>, Option<Vec<u8>>), AppError>;

/// Type alias for encrypted session data result
type EncryptedSessionData = ((Vec<u8>, Vec<u8>), (Option<Vec<u8>>, Option<Vec<u8>>));

/// Represents the result of querying for a user's default persona
#[derive(Debug, Clone, Copy)]
enum DefaultPersonaQuery {
    /// User exists and has a default persona
    HasDefault(Uuid),
    /// User exists but has no default persona
    NoDefault,
    /// User was not found
    UserNotFound,
}

// Conversion implementations for DefaultPersonaQuery
impl DefaultPersonaQuery {
    /// Creates a `DefaultPersonaQuery` from a database query result
    /// where Some(uuid) means user has default persona, None means no default persona
    fn from_nullable_uuid(user_exists: bool, persona_id: Option<Uuid>) -> Self {
        if user_exists {
            persona_id.map_or(Self::NoDefault, Self::HasDefault)
        } else {
            Self::UserNotFound
        }
    }
}

/// Handles successful query result cases for default persona ID
fn handle_successful_persona_query(
    user_id: Uuid,
    persona_result: DefaultPersonaQuery,
) -> Option<Uuid> {
    match persona_result {
        DefaultPersonaQuery::HasDefault(default_id) => {
            info!(%user_id, default_persona_id = %default_id, "Found user's default persona. Using it for this session.");
            Some(default_id)
        }
        DefaultPersonaQuery::NoDefault => {
            info!(%user_id, "User has no default persona set.");
            None
        }
        DefaultPersonaQuery::UserNotFound => {
            warn!(%user_id, "User not found when trying to fetch default persona. This should not happen.");
            None
        }
    }
}

/// Handles database query result for default persona ID
fn handle_persona_query_result(
    user_id: Uuid,
    result: Result<DefaultPersonaQuery, diesel::result::Error>,
) -> Option<Uuid> {
    match result {
        Ok(persona_result) => handle_successful_persona_query(user_id, persona_result),
        Err(e) => {
            error!(%user_id, error = ?e, "Error fetching user's default persona. Proceeding without it.");
            None
        }
    }
}

/// Fetches the user's default persona ID from the database
fn get_user_default_persona_id(user_id: Uuid, conn: &mut PgConnection) -> Option<Uuid> {
    let db_result = crate::schema::users::table
        .filter(users_dsl::id.eq(user_id))
        .select(users_dsl::default_persona_id)
        .first::<Option<Uuid>>(conn)
        .optional();

    // Convert the database result to our custom enum
    let enum_result = match db_result {
        Ok(Some(persona_opt)) => Ok(DefaultPersonaQuery::from_nullable_uuid(true, persona_opt)),
        Ok(None) => Ok(DefaultPersonaQuery::UserNotFound),
        Err(e) => Err(e),
    };

    handle_persona_query_result(user_id, enum_result)
}

/// Helper function to determine the effective active persona ID
fn determine_effective_persona_id(
    user_id: Uuid,
    active_custom_persona_id: Option<Uuid>,
    conn: &mut PgConnection,
) -> Option<Uuid> {
    if let Some(persona_id) = active_custom_persona_id {
        return Some(persona_id);
    }

    info!(%user_id, "No active_custom_persona_id provided, checking for user's default persona.");
    get_user_default_persona_id(user_id, conn)
}

/// Helper function to extract system prompt from persona
fn extract_persona_system_prompt(
    persona_id: Uuid,
    user_id: Uuid,
    user_dek: Option<&Arc<SecretBox<Vec<u8>>>>,
    conn: &mut PgConnection,
) -> Option<String> {
    let persona = fetch_user_persona(persona_id, user_id, conn)?;
    let sp_bytes_vec = persona.system_prompt.as_ref()?;

    if let (Some(sp_nonce_vec), Some(dek_arc)) = (&persona.system_prompt_nonce, user_dek) {
        decrypt_persona_system_prompt(persona_id, sp_bytes_vec, sp_nonce_vec, dek_arc)
    } else if persona.system_prompt_nonce.is_none() && user_dek.is_none() {
        extract_plaintext_system_prompt(persona_id, sp_bytes_vec)
    } else {
        info!(%persona_id, nonce_present = persona.system_prompt_nonce.is_some(), dek_present = user_dek.is_some(), "Persona system_prompt could not be used (cannot decrypt or inconsistent state). Skipping.");
        None
    }
}

fn fetch_user_persona(
    persona_id: Uuid,
    user_id: Uuid,
    conn: &mut PgConnection,
) -> Option<crate::models::user_personas::UserPersona> {
    use crate::schema::user_personas;

    match user_personas::table
        .filter(user_personas::id.eq(persona_id))
        .filter(user_personas::user_id.eq(user_id))
        .select(crate::models::user_personas::UserPersona::as_select())
        .first::<crate::models::user_personas::UserPersona>(conn)
        .optional()
    {
        Ok(Some(persona)) => Some(persona),
        Ok(None) => {
            warn!(%persona_id, %user_id, "Active persona not found or not owned by user. Will fall back to character prompt.");
            None
        }
        Err(e) => {
            error!(%persona_id, error = ?e, "Failed to query active persona. Will fall back to character prompt.");
            None
        }
    }
}

fn process_decrypted_bytes(persona_id: Uuid, decrypted_bytes: Vec<u8>) -> Option<String> {
    match String::from_utf8(decrypted_bytes) {
        Ok(decrypted_sp_str) => {
            if decrypted_sp_str.trim().is_empty() {
                info!(%persona_id, "Decrypted persona system_prompt is empty. Skipping.");
                None
            } else {
                info!(%persona_id, "Using DECRYPTED system prompt from active persona.");
                Some(decrypted_sp_str.replace('\0', ""))
            }
        }
        Err(e) => {
            error!(%persona_id, error = ?e, "DECRYPTED Persona system_prompt is not valid UTF-8. Skipping.");
            None
        }
    }
}

fn decrypt_persona_system_prompt(
    persona_id: Uuid,
    sp_bytes_vec: &[u8],
    sp_nonce_vec: &[u8],
    dek_arc: &Arc<SecretBox<Vec<u8>>>,
) -> Option<String> {
    match crate::crypto::decrypt_gcm(sp_bytes_vec, sp_nonce_vec, dek_arc) {
        Ok(decrypted_secret_vec) => {
            process_decrypted_bytes(persona_id, decrypted_secret_vec.expose_secret().clone())
        }
        Err(e) => {
            error!(%persona_id, error = ?e, "Failed to DECRYPT persona system_prompt. Skipping.");
            None
        }
    }
}

fn extract_plaintext_system_prompt(persona_id: Uuid, sp_bytes_vec: &[u8]) -> Option<String> {
    match String::from_utf8(sp_bytes_vec.to_vec()) {
        Ok(plaintext_sp_str) => {
            if plaintext_sp_str.trim().is_empty() {
                info!(%persona_id, "Persona system_prompt (plaintext, no nonce/DEK) is empty. Skipping.");
                None
            } else {
                warn!(%persona_id, "Using persona system_prompt as PLAINTEXT (nonce and DEK were missing).");
                Some(plaintext_sp_str.replace('\0', ""))
            }
        }
        Err(e) => {
            error!(%persona_id, error = ?e, "Persona system_prompt (plaintext, no nonce/DEK) is not valid UTF-8. Skipping.");
            None
        }
    }
}

/// Helper function to determine system prompt from character or persona
fn determine_system_prompt(
    character: &Character,
    persona_id: Option<Uuid>,
    user_id: Uuid,
    user_dek: Option<&Arc<SecretBox<Vec<u8>>>>,
    conn: &mut PgConnection,
) -> Option<String> {
    // Try persona first if available
    if let Some(pid) = persona_id {
        if let Some(persona_prompt) = extract_persona_system_prompt(pid, user_id, user_dek, conn) {
            return Some(persona_prompt);
        }
    }

    // Fall back to character prompts
    info!("No persona system prompt active, deriving from character.");
    character
        .system_prompt
        .as_ref()
        .and_then(|val| {
            if val.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(val).to_string().replace('\0', ""))
            }
        })
        .or_else(|| {
            character.persona.as_ref().and_then(|val| {
                if val.is_empty() {
                    None
                } else {
                    Some(String::from_utf8_lossy(val).to_string().replace('\0', ""))
                }
            })
        })
        .or_else(|| {
            character.description.as_ref().and_then(|val| {
                if val.is_empty() {
                    None
                } else {
                    Some(String::from_utf8_lossy(val).to_string().replace('\0', ""))
                }
            })
        })
}

/// Validates character ownership and retrieves character data
fn validate_and_get_character(
    character_id: Uuid,
    user_id: Uuid,
    transaction_conn: &mut PgConnection,
) -> Result<Character, AppError> {
    info!(%character_id, %user_id, "Verifying character ownership and fetching character details");
    let character: Character = characters::table
        .filter(characters::id.eq(character_id))
        .select(Character::as_select())
        .first::<Character>(transaction_conn)
        .map_err(|e| match e {
            DieselError::NotFound => AppError::NotFound("Character not found".into()),
            _ => AppError::DatabaseQueryError(e.to_string()),
        })?;

    if character.user_id != user_id {
        error!(%character_id, %user_id, owner_id=%character.user_id, "User does not own character");
        return Err(AppError::Forbidden(
            "Access denied to character".to_string(),
        ));
    }

    Ok(character)
}

/// Sanitizes character name and validates it's not empty
fn sanitize_character_name(character: &Character) -> Result<String, AppError> {
    let sanitized_character_name = character.name.replace('\0', "");
    if sanitized_character_name.is_empty() {
        error!(character_id = %character.id, "Character name is empty or consists only of invalid characters after sanitization.");
        return Err(AppError::BadRequest(
            "Character name cannot be empty or consist only of invalid characters.".to_string(),
        ));
    }
    Ok(sanitized_character_name)
}

/// Encrypts session title and system prompt
fn encrypt_session_data(
    sanitized_character_name: &str,
    character: &Character,
    effective_active_persona_id: Option<Uuid>,
    user_id: Uuid,
    user_dek_secret_box: Option<&Arc<SecretBox<Vec<u8>>>>,
    transaction_conn: &mut PgConnection,
) -> Result<EncryptedSessionData, AppError> {
    // Create and encrypt session title
    let session_title_for_encryption = format!("Chat with {sanitized_character_name}");
    let (encrypted_title_bytes, title_nonce_bytes) = crate::crypto::encrypt_gcm(
        session_title_for_encryption.as_bytes(),
        user_dek_secret_box.ok_or_else(|| {
            AppError::BadRequest("User DEK is required to create sessions".to_string())
        })?,
    )
    .map_err(|e| AppError::EncryptionError(format!("Failed to encrypt session title: {e}")))?;

    // Determine and encrypt system prompt
    let system_prompt_for_session = determine_system_prompt(
        character,
        effective_active_persona_id,
        user_id,
        user_dek_secret_box,
        transaction_conn,
    );

    let (encrypted_system_prompt_bytes, sp_nonce_bytes) = if let Some(system_prompt_str) =
        system_prompt_for_session
    {
        let (enc_bytes, nonce_bytes) =
            crate::crypto::encrypt_gcm(system_prompt_str.as_bytes(), user_dek_secret_box.unwrap())
                .map_err(|e| {
                    AppError::EncryptionError(format!("Failed to encrypt system prompt: {e}"))
                })?;
        (Some(enc_bytes), Some(nonce_bytes))
    } else {
        (None, None)
    };

    Ok((
        (encrypted_title_bytes, title_nonce_bytes),
        (encrypted_system_prompt_bytes, sp_nonce_bytes),
    ))
}

/// Encrypts session data for assistant mode
fn encrypt_assistant_session_data(
    session_title: &str,
    _effective_active_persona_id: Option<Uuid>,
    _user_id: Uuid,
    user_dek_secret_box: Option<&Arc<SecretBox<Vec<u8>>>>,
    _transaction_conn: &mut PgConnection,
) -> Result<EncryptedSessionData, AppError> {
    // Encrypt session title
    let (encrypted_title_bytes, title_nonce_bytes) = crate::crypto::encrypt_gcm(
        session_title.as_bytes(),
        user_dek_secret_box.ok_or_else(|| {
            AppError::BadRequest("User DEK is required to create sessions".to_string())
        })?,
    )
    .map_err(|e| AppError::EncryptionError(format!("Failed to encrypt session title: {e}")))?;

    // Create system prompt for assistant mode
    let assistant_system_prompt = "You are Scribe Assistant, a helpful AI designed to assist with character creation, world-building, and narrative development. You can help users create compelling characters, develop rich backstories, design scenarios, and enhance their creative writing projects.";
    
    let (encrypted_system_prompt_bytes, sp_nonce_bytes) = 
        crate::crypto::encrypt_gcm(assistant_system_prompt.as_bytes(), user_dek_secret_box.unwrap())
            .map_err(|e| {
                AppError::EncryptionError(format!("Failed to encrypt system prompt: {e}"))
            })?;

    Ok((
        (encrypted_title_bytes, title_nonce_bytes),
        (Some(encrypted_system_prompt_bytes), Some(sp_nonce_bytes)),
    ))
}

/// Encrypts session data for RPG mode
fn encrypt_rpg_session_data(
    session_title: &str,
    _effective_active_persona_id: Option<Uuid>,
    _user_id: Uuid,
    user_dek_secret_box: Option<&Arc<SecretBox<Vec<u8>>>>,
    _transaction_conn: &mut PgConnection,
) -> Result<EncryptedSessionData, AppError> {
    // Encrypt session title
    let (encrypted_title_bytes, title_nonce_bytes) = crate::crypto::encrypt_gcm(
        session_title.as_bytes(),
        user_dek_secret_box.ok_or_else(|| {
            AppError::BadRequest("User DEK is required to create sessions".to_string())
        })?,
    )
    .map_err(|e| AppError::EncryptionError(format!("Failed to encrypt session title: {e}")))?;

    // Create system prompt for RPG mode
    let rpg_system_prompt = "You are a RPG Game Master, skilled in creating immersive tabletop role-playing experiences. You can manage game mechanics, track character stats, handle dice rolls, and create engaging narratives for players.";
    
    let (encrypted_system_prompt_bytes, sp_nonce_bytes) = 
        crate::crypto::encrypt_gcm(rpg_system_prompt.as_bytes(), user_dek_secret_box.unwrap())
            .map_err(|e| {
                AppError::EncryptionError(format!("Failed to encrypt system prompt: {e}"))
            })?;

    Ok((
        (encrypted_title_bytes, title_nonce_bytes),
        (Some(encrypted_system_prompt_bytes), Some(sp_nonce_bytes)),
    ))
}

/// Parameters for inserting a chat session
struct ChatSessionInsertParams {
    new_session_id: Uuid,
    user_id: Uuid,
    character_id: Option<Uuid>,
    chat_mode: ChatMode,
    encrypted_title_bytes: Vec<u8>,
    title_nonce_bytes: Vec<u8>,
    encrypted_system_prompt_bytes: Option<Vec<u8>>,
    sp_nonce_bytes: Option<Vec<u8>>,
    effective_active_persona_id: Option<Uuid>,
    default_model_name: String,
    default_history_management_strategy: String,
    default_history_management_limit: i32,
}

/// Inserts the chat session into the database
fn insert_chat_session(
    params: ChatSessionInsertParams,
    transaction_conn: &mut PgConnection,
) -> Result<(), AppError> {
    diesel::insert_into(chat_sessions::table)
        .values((
            chat_sessions::id.eq(params.new_session_id),
            chat_sessions::user_id.eq(params.user_id),
            chat_sessions::character_id.eq(params.character_id),
            chat_sessions::chat_mode.eq(params.chat_mode),
            chat_sessions::title_ciphertext.eq(params.encrypted_title_bytes),
            chat_sessions::title_nonce.eq(params.title_nonce_bytes),
            chat_sessions::system_prompt_ciphertext.eq(params.encrypted_system_prompt_bytes),
            chat_sessions::system_prompt_nonce.eq(params.sp_nonce_bytes),
            chat_sessions::active_custom_persona_id.eq(params.effective_active_persona_id),
            chat_sessions::model_name.eq(params.default_model_name),
            chat_sessions::history_management_strategy
                .eq(params.default_history_management_strategy),
            chat_sessions::history_management_limit.eq(params.default_history_management_limit),
        ))
        .returning(Chat::as_returning())
        .get_result(transaction_conn)
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

    Ok(())
}

/// Validates that a lorebook exists and is owned by the specified user
fn validate_lorebook_ownership(
    lorebook_id: Uuid,
    user_id: Uuid,
    transaction_conn: &mut PgConnection,
) -> Result<(), AppError> {
    use crate::schema::lorebooks;

    let lorebook_user_id = lorebooks::table
        .filter(lorebooks::id.eq(lorebook_id))
        .select(lorebooks::user_id)
        .first::<Uuid>(transaction_conn)
        .optional()
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

    lorebook_user_id.map_or_else(
        || Err(AppError::NotFound("Lorebook not found".to_string())),
        |owner_id| {
            if owner_id == user_id {
                Ok(())
            } else {
                Err(AppError::Forbidden("Access denied to lorebook".to_string()))
            }
        },
    )
}

/// Fetches lorebooks associated with a character

/// Associates lorebooks with the chat session
/// Associates explicitly provided lorebooks with the chat session.
/// Character-derived lorebooks are handled implicitly by the frontend/listing logic
/// and should not have explicit entries in `chat_session_lorebooks` unless
/// the user specifically adds them to this chat later.
fn associate_lorebooks(
    new_session_id: Uuid,
    user_id: Uuid,
    _character_id: Uuid, // Not strictly needed if we only handle explicit IDs here
    explicit_lorebook_ids: Option<Vec<Uuid>>,
    transaction_conn: &mut PgConnection,
) -> Result<(), AppError> {
    if let Some(explicit_ids) = explicit_lorebook_ids {
        if !explicit_ids.is_empty() {
            info!(
                session_id = %new_session_id,
                lorebook_count = explicit_ids.len(),
                "Associating EXPLICITLY provided lorebooks with new chat session."
            );

            for lorebook_id in explicit_ids {
                // Validate that the lorebook exists and is owned by the user
                validate_lorebook_ownership(lorebook_id, user_id, transaction_conn)?;

                // Insert the explicit association.
                // If this lorebook also happens to be a character-default lorebook,
                // this explicit chat-level association will take precedence in the UI
                // (showing as source: Chat), which is acceptable if the user explicitly chose it at creation.
                // However, the main goal is that character defaults are NOT auto-added here.
                diesel::insert_into(chat_session_lorebooks::table)
                    .values((
                        chat_session_lorebooks::chat_session_id.eq(new_session_id),
                        chat_session_lorebooks::lorebook_id.eq(lorebook_id),
                        chat_session_lorebooks::user_id.eq(user_id),
                    ))
                    .on_conflict_do_nothing() // Avoid error if for some reason it was already there
                    .execute(transaction_conn)
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
            }
        } else {
            info!(session_id = %new_session_id, "No explicit lorebooks provided for initial association (empty list).");
        }
    } else {
        info!(session_id = %new_session_id, "No explicit lorebooks provided for initial association (option was None).");
    }
    Ok(())
}

/// Fetches the fully created session from the database
fn fetch_created_session(
    new_session_id: Uuid,
    transaction_conn: &mut PgConnection,
) -> Result<Chat, AppError> {
    chat_sessions::table
        .filter(chat_sessions::id.eq(new_session_id))
        .select(Chat::as_select())
        .first(transaction_conn)
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
}

/// Creates a new chat session in the database
fn create_session_in_transaction(
    transaction_conn: &mut PgConnection,
    user_id: Uuid,
    character_id: Option<Uuid>,
    chat_mode: ChatMode,
    active_custom_persona_id: Option<Uuid>,
    lorebook_ids: Option<Vec<Uuid>>,
    user_dek_secret_box: Option<&Arc<SecretBox<Vec<u8>>>>,
    default_model_name: String,
    default_history_management_strategy: String,
    default_history_management_limit: i32,
) -> SessionCreationResult {
    let effective_active_persona_id =
        determine_effective_persona_id(user_id, active_custom_persona_id, transaction_conn);

    // Handle different chat modes
    let (character_opt, _sanitized_name, encrypted_title_bytes, title_nonce_bytes, encrypted_system_prompt_bytes, sp_nonce_bytes) = match chat_mode {
        ChatMode::Character => {
            // Character mode requires a character_id
            let character_id = character_id.ok_or_else(|| {
                AppError::BadRequest("Character mode requires a character_id".to_string())
            })?;
            
            let character = validate_and_get_character(character_id, user_id, transaction_conn)?;
            let sanitized_character_name = sanitize_character_name(&character)?;
            
            info!(?character_id, %user_id, "Inserting new character chat session");
            
            let (
                (encrypted_title_bytes, title_nonce_bytes),
                (encrypted_system_prompt_bytes, sp_nonce_bytes),
            ) = encrypt_session_data(
                &sanitized_character_name,
                &character,
                effective_active_persona_id,
                user_id,
                user_dek_secret_box,
                transaction_conn,
            )?;
            
            (Some(character), sanitized_character_name, encrypted_title_bytes, title_nonce_bytes, encrypted_system_prompt_bytes, sp_nonce_bytes)
        },
        ChatMode::ScribeAssistant => {
            info!(%user_id, "Inserting new Scribe Assistant chat session");
            
            let session_title = "Scribe Assistant";
            let (
                (encrypted_title_bytes, title_nonce_bytes),
                (encrypted_system_prompt_bytes, sp_nonce_bytes),
            ) = encrypt_assistant_session_data(
                session_title,
                effective_active_persona_id,
                user_id,
                user_dek_secret_box,
                transaction_conn,
            )?;
            
            (None, session_title.to_string(), encrypted_title_bytes, title_nonce_bytes, encrypted_system_prompt_bytes, sp_nonce_bytes)
        },
        ChatMode::Rpg => {
            info!(%user_id, "Inserting new RPG chat session");
            
            let session_title = "RPG Session";
            let (
                (encrypted_title_bytes, title_nonce_bytes),
                (encrypted_system_prompt_bytes, sp_nonce_bytes),
            ) = encrypt_rpg_session_data(
                session_title,
                effective_active_persona_id,
                user_id,
                user_dek_secret_box,
                transaction_conn,
            )?;
            
            (None, session_title.to_string(), encrypted_title_bytes, title_nonce_bytes, encrypted_system_prompt_bytes, sp_nonce_bytes)
        },
    };

    let new_session_id = Uuid::new_v4();

    insert_chat_session(
        ChatSessionInsertParams {
            new_session_id,
            user_id,
            character_id,
            chat_mode,
            encrypted_title_bytes,
            title_nonce_bytes,
            encrypted_system_prompt_bytes,
            sp_nonce_bytes,
            effective_active_persona_id,
            default_model_name,
            default_history_management_strategy,
            default_history_management_limit,
        },
        transaction_conn,
    )?;

    // Only associate lorebooks for character mode
    if let ChatMode::Character = chat_mode {
        if let Some(char_id) = character_id {
            associate_lorebooks(
                new_session_id,
                user_id,
                char_id,
                lorebook_ids,
                transaction_conn,
            )?;
        }
    }

    let fully_created_session = fetch_created_session(new_session_id, transaction_conn)?;

    // Extract first message data if character exists
    let (first_mes, first_mes_nonce) = character_opt
        .map(|c| (c.first_mes, c.first_mes_nonce))
        .unwrap_or((None, None));

    Ok((
        fully_created_session,
        first_mes,
        first_mes_nonce,
    ))
}

/// Processes the first message for a newly created session
async fn process_first_message(
    state: Arc<AppState>,
    created_session: &Chat,
    first_mes_ciphertext_opt: Option<Vec<u8>>,
    first_mes_nonce_opt: Option<Vec<u8>>,
    user_dek_secret_box: Option<Arc<SecretBox<Vec<u8>>>>,
) -> Result<(), AppError> {
    if let (Some(first_message_ciphertext), Some(first_message_nonce)) =
        (first_mes_ciphertext_opt, first_mes_nonce_opt)
    {
        if !first_message_ciphertext.is_empty() && !first_message_nonce.is_empty() {
            if let Some(user_dek_arc) = &user_dek_secret_box {
                match crate::crypto::decrypt_gcm(
                    &first_message_ciphertext,
                    &first_message_nonce,
                    user_dek_arc,
                ) {
                    Ok(decrypted_first_mes_secret_vec) => {
                        match String::from_utf8(
                            decrypted_first_mes_secret_vec.expose_secret().clone(),
                        ) {
                            Ok(decrypted_first_mes_str) => {
                                if !decrypted_first_mes_str.trim().is_empty() {
                                    save_message(SaveMessageParams {
                                        state,
                                        session_id: created_session.id,
                                        user_id: created_session.user_id,
                                        message_type_enum: MessageRole::Assistant,
                                        content: &decrypted_first_mes_str,
                                        role_str: Some("assistant".to_string()),
                                        parts: None,
                                        attachments: None,
                                        user_dek_secret_box: user_dek_secret_box.clone(),
                                        model_name: created_session.model_name.clone(),
                                        raw_prompt_debug: None, // First message doesn't need raw prompt debug
                                    })
                                    .await?;
                                    info!(session_id = %created_session.id, "Successfully called save_message for first_mes");
                                }
                            }
                            Err(e) => {
                                error!(session_id = %created_session.id, error = ?e, "Failed to convert decrypted first_mes to UTF-8");
                            }
                        }
                    }
                    Err(e) => {
                        error!(session_id = %created_session.id, error = ?e, "Failed to decrypt character first_mes for new session");
                    }
                }
            } else {
                warn!(session_id = %created_session.id, "Character has encrypted first_mes but no user DEK provided. Skipping first_mes.");
            }
        } else {
            info!(session_id = %created_session.id, "Character first_mes ciphertext or nonce is empty, skipping save.");
        }
    }
    Ok(())
}

/// Creates a new chat session, verifies character ownership, and adds the character's first message if available.
#[instrument(skip(state, user_dek_secret_box), err)]
pub async fn create_session_and_maybe_first_message(
    state: Arc<AppState>,
    user_id: Uuid,
    character_id: Option<Uuid>,
    chat_mode: ChatMode,
    active_custom_persona_id: Option<Uuid>,
    lorebook_ids: Option<Vec<Uuid>>,
    user_dek_secret_box: Option<Arc<SecretBox<Vec<u8>>>>,
) -> Result<Chat, AppError> {
    // Load user settings to get defaults for the new chat session
    // This will auto-create defaults if user has no settings yet
    let user_settings = crate::services::UserSettingsService::get_user_settings(
        &state.pool,
        user_id,
        &state.config,
    ).await.unwrap_or_else(|e| {
        warn!(%user_id, error = ?e, "Failed to load user settings for new chat session, using system defaults");
        // Create fallback defaults using system config values
        crate::models::user_settings::UserSettingsResponse {
            default_model_name: Some(state.config.token_counter_default_model.clone()),
            default_temperature: None,
            default_max_output_tokens: None,
            default_frequency_penalty: None,
            default_presence_penalty: None,
            default_top_p: None,
            default_top_k: None,
            default_seed: None,
            default_gemini_thinking_budget: None,
            default_gemini_enable_code_execution: None,
            default_context_total_token_limit: Some(state.config.context_total_token_limit as i32),
            default_context_recent_history_budget: Some(state.config.context_recent_history_token_budget as i32),
            default_context_rag_budget: Some(state.config.context_rag_token_budget as i32),
            auto_save_chats: Some(true),
            theme: Some("system".to_string()),
            notifications_enabled: Some(true),
            typing_speed: Some(30),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    });

    // Extract defaults with fallbacks to system config
    let default_model_name = user_settings
        .default_model_name
        .unwrap_or_else(|| state.config.token_counter_default_model.clone());
    let default_history_management_strategy = "message_window".to_string(); // Not yet in user settings
    let default_history_management_limit = 20; // Not yet in user settings

    let pool: DbPool = state.pool.clone();
    let conn = pool.get().await?;
    // Clone user_dek_secret_box and lorebook_ids for use inside the 'move' closure
    let user_dek_for_closure = user_dek_secret_box.clone();
    let lorebook_ids_for_closure = lorebook_ids.clone();
    let (created_session, first_mes_ciphertext_opt, first_mes_nonce_opt) = conn
        .interact(move |conn| {
            conn.transaction(|transaction_conn| {
                create_session_in_transaction(
                    transaction_conn,
                    user_id,
                    character_id,
                    chat_mode,
                    active_custom_persona_id,
                    lorebook_ids_for_closure,
                    user_dek_for_closure.as_ref(),
                    default_model_name,
                    default_history_management_strategy,
                    default_history_management_limit,
                )
            })
        })
        .await??;

    // Process first message if available
    process_first_message(
        state,
        &created_session,
        first_mes_ciphertext_opt,
        first_mes_nonce_opt,
        user_dek_secret_box,
    )
    .await?;

    Ok(created_session)
}
/// Lists chat sessions for a given user.
#[instrument(skip(pool), err)]
pub async fn list_sessions_for_user(pool: &DbPool, user_id: Uuid) -> Result<Vec<Chat>, AppError> {
    // ChatSession is aliased as Chat
    let conn = pool.get().await?;
    conn.interact(move |conn| {
        chat_sessions::table
            .filter(chat_sessions::user_id.eq(user_id))
            .select(Chat::as_select()) // ChatSession is aliased as Chat
            .order(chat_sessions::updated_at.desc())
            .load::<Chat>(conn) // ChatSession is aliased as Chat
            .map_err(|e| {
                error!("Failed to load chat sessions for user {}: {}", user_id, e);
                AppError::DatabaseQueryError(e.to_string())
            })
    })
    .await?
}
/// Validates session ownership
fn validate_session_ownership(
    session: Chat,
    user_id: Uuid,
    session_id: Uuid,
) -> Result<Chat, AppError> {
    if session.user_id == user_id {
        info!(%session_id, %user_id, "Session found and ownership verified");
        Ok(session)
    } else {
        warn!(%session_id, %user_id, owner_id=%session.user_id, "User attempted to access session owned by another user");
        Err(AppError::NotFound(
            "Chat session not found or permission denied".into(),
        ))
    }
}

/// Gets a specific chat session by ID, verifying ownership.
#[instrument(skip(pool), err)]
pub async fn get_chat_session_by_id(
    pool: &DbPool,
    user_id: Uuid,
    session_id: Uuid,
) -> Result<Chat, AppError> {
    let conn = pool.get().await?;
    conn.interact(move |conn| {
        info!(%session_id, %user_id, "Attempting to fetch chat session details by ID");
        let session_result = chat_sessions::table
            .filter(chat_sessions::id.eq(session_id))
            .select(Chat::as_select())
            .first::<Chat>(conn)
            .optional()?;

        session_result.map_or_else(
            || {
                warn!(%session_id, %user_id, "Chat session not found by ID");
                Err(AppError::NotFound(
                    "Chat session not found or permission denied".into(),
                ))
            },
            |session| validate_session_ownership(session, user_id, session_id),
        )
    })
    .await?
}

/// Associate a chat session with a chronicle
#[instrument(skip(pool), err)]
pub async fn associate_chat_with_chronicle(
    pool: &DbPool,
    user_id: Uuid,
    session_id: Uuid,
    chronicle_id: Uuid,
) -> Result<(), AppError> {
    info!(
        %session_id, %user_id, %chronicle_id,
        "Associating chat session with chronicle"
    );

    let conn = pool.get().await?;
    conn.interact(move |conn| {
        // First, verify the session belongs to the user
        let session = chat_sessions::table
            .filter(chat_sessions::id.eq(session_id))
            .filter(chat_sessions::user_id.eq(user_id))
            .select(Chat::as_select())
            .first::<Chat>(conn)
            .optional()?;

        match session {
            Some(_) => {
                // Update the session to associate it with the chronicle
                diesel::update(chat_sessions::table.filter(chat_sessions::id.eq(session_id)))
                    .set(chat_sessions::player_chronicle_id.eq(Some(chronicle_id)))
                    .execute(conn)?;
                
                info!(
                    %session_id, %chronicle_id,
                    "Successfully associated chat session with chronicle"
                );
                Ok(())
            }
            None => {
                warn!(%session_id, %user_id, "Chat session not found or permission denied");
                Err(AppError::NotFound(
                    "Chat session not found or permission denied".into(),
                ))
            }
        }
    })
    .await?
}
