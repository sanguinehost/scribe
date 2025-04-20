// backend/src/routes/characters.rs

use crate::errors::AppError;
use crate::models::characters::{Character, NewCharacter};
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

// TODO: Remove this once authentication is integrated
const DUMMY_USER_ID: Uuid = Uuid::nil();

// POST /api/characters/upload
#[instrument(skip(state, multipart), err)]
pub async fn upload_character_handler(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<Character>), AppError> {
    let mut character_card_data: Option<Vec<u8>> = None;
    let mut content_type: Option<String> = None;

    while let Some(field) = multipart.next_field().await? {
        let local_field_name = field.name().unwrap_or("").to_string(); // Renamed variable
        if local_field_name == "character_card" {
            content_type = field.content_type().map(|mime| mime.to_string());
            info!(?content_type, field_name=%local_field_name, "Received character card field"); // Use info, not debug
            let data = field.bytes().await?;
            character_card_data = Some(data.to_vec());
            break;
        }
    }
    let png_data = character_card_data
        .ok_or_else(|| AppError::BadRequest("Missing 'character_card' field in upload".to_string()))?;

    let parsed_card = character_parser::parse_character_card_png(&png_data)?;
    let local_user_id = DUMMY_USER_ID; // Renamed variable
    let new_character = NewCharacter::from_parsed_card(&parsed_card, local_user_id);

    // Log the character data just before insertion
    info!(?new_character, "Attempting to insert character into DB");

    let conn = state.pool.get().await.map_err(AppError::DbPoolError)?;

    let inserted_character = conn
        .interact(move |conn| {
            diesel::insert_into(characters)
                .values(&new_character)
                .returning(Character::as_returning())
                .get_result::<Character>(conn)
        })
        .await
        .map_err(|e| AppError::InternalServerError(anyhow!(e.to_string())))??;

    info!(character_id = %inserted_character.id, "Character uploaded and saved");
    Ok((StatusCode::CREATED, Json(inserted_character)))
}

// GET /api/characters
#[instrument(skip(state), err)]
pub async fn list_characters_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<Character>>, AppError> {
    info!("Listing all characters");
    let local_user_id = DUMMY_USER_ID; // Renamed variable
    let conn = state.pool.get().await.map_err(AppError::DbPoolError)?;

    let characters_vec = conn
        .interact(move |conn| {
            characters
                .filter(user_id.eq(local_user_id))
                .select(Character::as_select())
                .load::<Character>(conn)
        })
        .await
        .map_err(|e| AppError::InternalServerError(anyhow!(e.to_string())))??;

    Ok(Json(characters_vec))
}

// GET /api/characters/:id
#[instrument(skip(state), err)]
pub async fn get_character_handler(
    State(state): State<AppState>,
    Path(character_id): Path<Uuid>,
) -> Result<Json<Character>, AppError> {
    info!(%character_id, "Fetching character details");
    let local_user_id = DUMMY_USER_ID; // Renamed variable
    let conn = state.pool.get().await.map_err(AppError::DbPoolError)?;

    let character_option = conn
        .interact(move |conn| {
            characters
                .filter(id.eq(character_id).and(user_id.eq(local_user_id)))
                .select(Character::as_select())
                .first::<Character>(conn)
                .optional()
        })
        .await
        .map_err(|e| AppError::InternalServerError(anyhow!(e.to_string())))??;

    match character_option {
        Some(character) => Ok(Json(character)),
        None => Err(AppError::NotFound(format!(
            "Character with ID {} not found or access denied",
            character_id
        ))),
    }
}

// --- Character Router ---
pub fn characters_router(state: AppState) -> Router {
    Router::new()
        .route("/upload", post(upload_character_handler))
        .route("/", get(list_characters_handler))
        .route("/:id", get(get_character_handler))
        .with_state(state)
}

// --- Tests ---
#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use axum::body::Body;
    use axum::http::{self, Request, StatusCode};
    use axum::Router;
    use http_body_util::BodyExt; // for `collect`
    use std::sync::Arc;
    use tower::ServiceExt; // for `oneshot`
    use std::env;
    use crc32fast;
    use base64::{Engine as _, engine::general_purpose::STANDARD as base64_standard};
    use deadpool_diesel::{
        postgres::{Manager as DeadpoolManager, Runtime as DeadpoolRuntime},
        Pool as DeadpoolPool,
    };

    // Replaced dummy helper with working version from tests/characters_tests.rs
    fn create_test_png_with_text_chunk(keyword: &[u8], json_payload: &str) -> Vec<u8> {
        let base64_payload = base64_standard.encode(json_payload);
        let chunk_data = base64_payload.as_bytes();

        let mut png_bytes = Vec::new();
        png_bytes.extend_from_slice(&[137, 80, 78, 71, 13, 10, 26, 10]);
        let ihdr_data = &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0];
        let ihdr_len = (ihdr_data.len() as u32).to_be_bytes();
        let chunk_type_ihdr = b"IHDR";
        png_bytes.extend_from_slice(&ihdr_len);
        png_bytes.extend_from_slice(chunk_type_ihdr);
        png_bytes.extend_from_slice(ihdr_data);
        let crc_ihdr = crc32fast::hash(&[&chunk_type_ihdr[..], &ihdr_data[..]].concat());
        png_bytes.extend_from_slice(&crc_ihdr.to_be_bytes());
        let text_chunk_data_internal = [&keyword[..], &[0u8], &chunk_data[..]].concat();
        let text_chunk_len = (text_chunk_data_internal.len() as u32).to_be_bytes();
        let chunk_type_text = b"tEXt";
        png_bytes.extend_from_slice(&text_chunk_len);
        png_bytes.extend_from_slice(chunk_type_text);
        png_bytes.extend_from_slice(&text_chunk_data_internal);
        let crc_text = crc32fast::hash(&[&chunk_type_text[..], &text_chunk_data_internal[..]].concat());
        png_bytes.extend_from_slice(&crc_text.to_be_bytes());
        let idat_data = &[8, 29, 99, 96, 0, 0, 0, 3, 0, 1];
        let idat_len = (idat_data.len() as u32).to_be_bytes();
        let chunk_type_idat = b"IDAT";
        png_bytes.extend_from_slice(&idat_len);
        png_bytes.extend_from_slice(chunk_type_idat);
        png_bytes.extend_from_slice(idat_data);
        let crc_idat = crc32fast::hash(&[&chunk_type_idat[..], &idat_data[..]].concat());
        png_bytes.extend_from_slice(&crc_idat.to_be_bytes());
        png_bytes.extend_from_slice(&[0, 0, 0, 0]);
        png_bytes.extend_from_slice(b"IEND");
        png_bytes.extend_from_slice(&[174, 66, 96, 130]);
        png_bytes
    }

    // No-op setup/teardown for now
    async fn setup_test_db(_db_name: &str) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
    async fn teardown_test_db(_db_name: &str) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }

    // Function to create the AppState with a real test pool
    async fn create_test_state_arc(_db_name: &str) -> Result<Arc<AppState>, Box<dyn std::error::Error>> {
        dotenvy::dotenv().ok();
        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");
        let manager = DeadpoolManager::new(database_url, DeadpoolRuntime::Tokio1);
        let pool = DeadpoolPool::builder(manager)
            .build()
            .expect("Failed to create test DB pool.");

        let app_state = AppState { pool };
        Ok(Arc::new(app_state))
    }

    async fn test_upload_character(app: Router) -> Result<(), Box<dyn std::error::Error>> {
        // Use the real helper and provide a keyword
        let png_data = create_test_png_with_text_chunk(
            b"ccv3", // Use ccv3 keyword to match payload format
            r#"{
                "spec": "character_card_v3",
                "spec_version": "1.0",
                "data": {
                    "name": "Test Character",
                    "description": "A test description."
                }
            }"#
        );

        // Simplified multipart body construction
        let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
        let mut body_vec = Vec::new();
        body_vec.extend_from_slice(b"--");
        body_vec.extend_from_slice(boundary.as_bytes());
        body_vec.extend_from_slice(b"\r\n");
        body_vec.extend_from_slice(b"Content-Disposition: form-data; name=\"character_card\"; filename=\"test.png\"\r\n");
        body_vec.extend_from_slice(b"Content-Type: image/png\r\n\r\n");
        body_vec.extend_from_slice(&png_data);
        body_vec.extend_from_slice(b"\r\n");
        body_vec.extend_from_slice(b"--");
        body_vec.extend_from_slice(boundary.as_bytes());
        body_vec.extend_from_slice(b"--\r\n");

        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/upload")
            .header(
                http::header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={}", boundary),
            )
            .body(Body::from(body_vec)) // Use Vec<u8> directly
            .unwrap();

        let response = app.oneshot(request).await?;

        assert_eq!(response.status(), StatusCode::CREATED); // Expect 201

        let body = response.into_body().collect().await?.to_bytes();
        let character: Character = serde_json::from_slice(&body)?;
        assert_eq!(character.name, "Test Character");

        Ok(())
    }

    // Add more tests for list, get, error cases etc.

    #[tokio::test]
    async fn characters_integration_tests() -> Result<(), Box<dyn std::error::Error>> {
        let db_name = "test_db_characters";
        setup_test_db(db_name).await?; // Calls dummy function
        let state = create_test_state_arc(db_name).await?;
        let app = characters_router((*state).clone()); // Clone AppState from Arc

        // Insert the dummy user required by the handler
        let pool = state.pool.clone();
        let dummy_username = format!("dummy_{}", DUMMY_USER_ID);
        let dummy_hash = "dummy_hash_for_nil_user";
        let dummy_username_clone_for_delete = dummy_username.clone(); // Clone for delete op
        let dummy_username_clone_for_insert = dummy_username.clone(); // Clone for insert op

        let conn = pool.get().await.map_err(|e| anyhow!(e.to_string()))?;
        conn.interact(move |conn| {
            // 1. Delete any user that might conflict by username
            let _ = diesel::delete(
                crate::schema::users::table
                    .filter(crate::schema::users::username.eq(dummy_username_clone_for_delete))
            )
            .execute(conn); // Ignore result (ok if user doesn't exist)

            // 2. Insert the required user with the specific NIL ID
            diesel::insert_into(crate::schema::users::table)
                .values((
                    crate::schema::users::id.eq(DUMMY_USER_ID),
                    crate::schema::users::username.eq(dummy_username_clone_for_insert),
                    crate::schema::users::password_hash.eq(dummy_hash),
                ))
                // No ON CONFLICT needed now, as we deleted potential conflicts
                .execute(conn)

        }).await.map_err(|e| anyhow!(e.to_string()))??; // Propagate errors from delete/insert

        info!(user_id = %DUMMY_USER_ID, "Ensured dummy test user with specific ID exists (deleted conflicting username first)");

        // Run tests
        test_upload_character(app.clone()).await?;
        // Add calls to list/get tests here

        teardown_test_db(db_name).await?; // Calls dummy function
        Ok(())
    }
}