#![cfg(test)]

// Local helper functions
use anyhow::Context;
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
    Router,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as base64_standard};
use deadpool_diesel::postgres::Pool;
use diesel::{PgConnection, RunQueryDsl, prelude::*};
use http_body_util::BodyExt;
use mime;
use reqwest::Client;
use reqwest::StatusCode as ReqwestStatusCode;
use scribe_backend::auth::session_dek::SessionDek;
use scribe_backend::{
    crypto,
    models::{
        users::{AccountStatus, NewUser, User, UserDbQuery, UserRole},
    },
    schema::users,
};
use scribe_backend::test_helpers::{TestDataGuard, ensure_tracing_initialized};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower::ServiceExt; // For oneshot
use uuid::Uuid;
use bcrypt;
use crc32fast;

/// Helper to hash a password for tests
fn hash_test_password(password: &str) -> String {
    bcrypt::hash(password, bcrypt::DEFAULT_COST).expect("Failed to hash test password with bcrypt")
}

/// Helper to insert a unique test user with a known password hash
fn insert_test_user_with_password(
    conn: &mut PgConnection,
    username: &str,
    password: &str,
) -> Result<(User, SessionDek), diesel::result::Error> {
    let hashed_password = hash_test_password(password);
    let email = format!("{username}@example.com");

    let kek_salt = crypto::generate_salt().expect("Failed to generate KEK salt for test user");
    let dek = crypto::generate_dek().expect("Failed to generate DEK for test user");

    let secret_password = SecretString::new(password.to_string().into());
    let kek = crypto::derive_kek(&secret_password, &kek_salt)
        .expect("Failed to derive KEK for test user");

    let (encrypted_dek, dek_nonce) = crypto::encrypt_gcm(dek.expose_secret(), &kek)
        .expect("Failed to encrypt DEK for test user");

    let new_user = NewUser {
        username: username.to_string(),
        password_hash: hashed_password,
        email,
        kek_salt,
        encrypted_dek,
        encrypted_dek_by_recovery: None,
        role: UserRole::User,
        recovery_kek_salt: None,
        dek_nonce,
        recovery_dek_nonce: None,
        account_status: AccountStatus::Active,
    };
    diesel::insert_into(users::table)
        .values(&new_user)
        .returning(UserDbQuery::as_returning())
        .get_result::<UserDbQuery>(conn)
        .map(|user_db| (User::from(user_db), SessionDek(dek)))
}

/// Helper function to run DB operations via pool interact
async fn run_db_op<F, T>(pool: &Pool, op: F) -> Result<T, anyhow::Error>
where
    F: FnOnce(&mut PgConnection) -> Result<T, diesel::result::Error> + Send + 'static,
    T: Send + 'static,
{
    let obj = pool
        .get()
        .await
        .context("Failed to get DB conn from pool")?;
    match obj.interact(op).await {
        Ok(Ok(data)) => Ok(data),
        Ok(Err(db_err)) => Err(anyhow::Error::new(db_err).context("DB interact error")),
        Err(interact_err) => Err(anyhow::anyhow!(
            "Deadpool interact error: {:?}",
            interact_err
        )),
    }
}

/// Helper to extract plain text body
async fn get_text_body(
    response: axum::http::Response<Body>,
) -> Result<(StatusCode, String), anyhow::Error> {
    let status = response.status();
    let body_bytes = response.into_body().collect().await?.to_bytes();
    let body_text = String::from_utf8(body_bytes.to_vec())?;
    Ok((status, body_text))
}

/// Helper to create a multipart form request using write! macro for reliability
pub fn create_multipart_request(
    uri: &str,
    filename: &str,
    content_type: &str,
    body_bytes: &[u8],
    extra_fields: Option<Vec<(&str, &str)>>,
    session_cookie: Option<&str>, // Changed from _auth_token to session_cookie
) -> Request<Body> {
    let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    let mut body = Vec::new();

    // Add file part
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"character_card\"; filename=\"{filename}\"\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(format!("Content-Type: {content_type}\r\n\r\n").as_bytes());
    body.extend_from_slice(body_bytes);
    body.extend_from_slice(b"\r\n");

    // Add extra fields if any
    if let Some(fields) = extra_fields {
        for (name, value) in fields {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(value.as_bytes());
            body.extend_from_slice(b"\r\n");
        }
    }

    // Final boundary
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    let mut request_builder = Request::builder().method(Method::POST).uri(uri).header(
        header::CONTENT_TYPE,
        format!("multipart/form-data; boundary={boundary}"),
    );

    // Add cookie header if provided
    if let Some(cookie) = session_cookie {
        request_builder = request_builder.header(header::COOKIE, cookie);
    }

    request_builder.body(Body::from(body)).unwrap()
}

/// Helper to create a test PNG with a valid character card chunk
#[must_use]
pub fn create_test_character_png(version: &str) -> Vec<u8> {
    use image::{RgbaImage, ImageFormat};
    use std::io::Cursor;

    let (chunk_keyword, json_payload) = match version {
        "v2" => (
            "chara",
            r#"{
                    "name": "Test V2 Character",
                    "description": "A test character for v2",
                    "personality": "Friendly and helpful",
                    "first_mes": "Hello, I'm a test character!",
                    "mes_example": "User: Hi\nCharacter: Hello!",
                    "scenario": "In a test environment",
                    "creator_notes": "Created for testing",
                    "system_prompt": "You are a test character.",
                    "post_history_instructions": "Continue being helpful.",
                    "tags": ["test", "v2"],
                    "creator": "Test Author",
                    "character_version": "1.0",
                    "alternate_greetings": ["Hey there!", "Hi!"]
                }"#,
        ),
        "v3" => (
            "ccv3",
            r#"{
                    "spec": "chara_card_v3",
                    "spec_version": "3.0",
                    "data": {
                        "name": "Test V3 Character",
                        "description": "A test character for v3",
                        "personality": "Friendly and helpful",
                        "first_mes": "Hello, I'm a V3 test character!",
                        "mes_example": "User: Hi\nCharacter: Hello from V3!",
                        "scenario": "In a test environment",
                        "creator_notes": "Created for V3 testing",
                        "system_prompt": "You are a test V3 character.",
                        "post_history_instructions": "Continue being helpful in V3.",
                        "tags": ["test", "v3"],
                        "creator": "Test Author",
                        "character_version": "1.0",
                        "alternate_greetings": ["Hey there from V3!", "Hi from V3!"]
                    }
                }"#,
        ),
        _ => panic!("Unsupported version: {version}"),
    };

    // Create a valid 1x1 white PNG using the image crate
    let img = RgbaImage::from_pixel(1, 1, image::Rgba([255, 255, 255, 255]));
    let mut png_buffer = Vec::new();
    {
        let mut cursor = Cursor::new(&mut png_buffer);
        img.write_to(&mut cursor, ImageFormat::Png).expect("Failed to write PNG");
    }

    // Now we need to insert the character data tEXt chunk before the IEND chunk
    // Find the IEND chunk position (should be at the end: 4 bytes length + "IEND" + 4 bytes CRC = 12 bytes from end)
    let iend_pos = png_buffer.len() - 12;
    
    // Create the character data tEXt chunk
    let base64_payload = base64_standard.encode(json_payload);
    let text_chunk_data = [chunk_keyword.as_bytes(), &[0u8], base64_payload.as_bytes()].concat();
    let text_chunk_len = u32::try_from(text_chunk_data.len())
        .expect("Text chunk too large")
        .to_be_bytes();
    
    let mut text_chunk = Vec::new();
    text_chunk.extend_from_slice(&text_chunk_len);
    text_chunk.extend_from_slice(b"tEXt");
    text_chunk.extend_from_slice(&text_chunk_data);
    
    // Calculate CRC for tEXt
    let mut crc_text_data = Vec::new();
    crc_text_data.extend_from_slice(b"tEXt");
    crc_text_data.extend_from_slice(&text_chunk_data);
    let crc_text = crc32fast::hash(&crc_text_data);
    text_chunk.extend_from_slice(&crc_text.to_be_bytes());

    // Insert the tEXt chunk before IEND
    let mut final_png = Vec::new();
    final_png.extend_from_slice(&png_buffer[..iend_pos]);
    final_png.extend_from_slice(&text_chunk);
    final_png.extend_from_slice(&png_buffer[iend_pos..]);

    final_png
}

/// Helper to spawn the app in the background
async fn spawn_app(app: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind random port for test server");
    let addr = listener
        .local_addr()
        .expect("Failed to get local address for test server");
    tracing::debug!(address = %addr, "Character test server listening on");

    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .expect("Test server failed to run");
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    addr
}

#[tokio::test]
async fn test_upload_valid_v3_card() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    // --- Setup Test User ---
    let test_password = "testpassword123";
    let test_username = format!("upload_v3_user_{}", Uuid::new_v4());
    let username_for_insert = test_username.clone();
    let user_result = run_db_op(&pool, move |conn| {
        insert_test_user_with_password(conn, &username_for_insert, test_password)
    })
    .await?;
    let (user, _) = user_result; // Destructure the tuple, ignore dek
    guard.add_user(user.id);

    // --- Setup App using Helper ---
    // The router is already part of test_app, no need to build another one
    // let _app = build_test_app_for_characters(pool.clone()).await;

    // -- Simulate Login ---
    let login_body = json!({
        "identifier": test_username.clone(),
        "password": test_password
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_body)?))?;

    let login_response = test_app.router.clone().oneshot(login_request).await?;
    assert_eq!(login_response.status(), StatusCode::OK, "Login failed");

    let session_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or_else(|| anyhow::anyhow!("Login response missing Set-Cookie header"))?
        .to_str()?
        .split(';')
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid Set-Cookie format"))?
        .to_string();

    // --- Simulate Upload ---
    let upload_request = create_multipart_request(
        "/api/characters/upload",
        "test_card.png",
        mime::IMAGE_PNG.as_ref(),
        &create_test_character_png("v3"), // Use our helper to create a valid V3 card
        Some(vec![("name", "Test Character")]),
        Some(&session_cookie),
    );

    let upload_response = test_app.router.clone().oneshot(upload_request).await?;
    assert_eq!(
        upload_response.status(),
        StatusCode::CREATED,
        "Upload failed"
    );

    // --- Cleanup ---
    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_upload_valid_v2_card_fallback() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    // --- Setup Test User ---
    let test_password = "testpassword123";
    let test_username = format!("upload_v2_user_{}", Uuid::new_v4());
    let username_for_insert = test_username.clone();
    let user_result = run_db_op(&pool, move |conn| {
        insert_test_user_with_password(conn, &username_for_insert, test_password)
    })
    .await?;
    let (user, _) = user_result; // Destructure the tuple, ignore dek
    guard.add_user(user.id);

    // --- Setup App using Helper ---
    // let _app = build_test_app_for_characters(pool.clone()).await;

    // -- Simulate Login ---
    let login_body = json!({
        "identifier": test_username.clone(),
        "password": test_password
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_body)?))?;

    let login_response = test_app.router.clone().oneshot(login_request).await?;
    assert_eq!(login_response.status(), StatusCode::OK, "Login failed");

    let session_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or_else(|| anyhow::anyhow!("Login response missing Set-Cookie header"))?
        .to_str()?
        .split(';')
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid Set-Cookie format"))?
        .to_string();

    // --- Simulate Upload ---
    let upload_request = create_multipart_request(
        "/api/characters/upload",
        "test_card_v2.png",
        mime::IMAGE_PNG.as_ref(),
        &create_test_character_png("v2"), // Use our helper to create a valid V2 card
        Some(vec![("name", "Test V2 Character")]),
        Some(&session_cookie),
    );

    let upload_response = test_app.router.clone().oneshot(upload_request).await?;
    assert_eq!(
        upload_response.status(),
        StatusCode::CREATED,
        "Upload failed"
    );

    // --- Cleanup ---
    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_upload_real_card_file() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    // --- Setup Test User ---
    let test_password = "testpassword123";
    let test_username = format!("upload_real_card_user_{}", Uuid::new_v4());
    let username_for_insert = test_username.clone();
    let user_result = run_db_op(&pool, move |conn| {
        insert_test_user_with_password(conn, &username_for_insert, test_password)
    })
    .await?;
    let (user, _) = user_result; // Destructure the tuple, ignore dek
    guard.add_user(user.id);

    // -- Simulate Login ---
    let login_body = json!({
        "identifier": test_username.clone(),
        "password": test_password
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_body)?))?;

    let login_response = test_app.router.clone().oneshot(login_request).await?;
    assert_eq!(login_response.status(), StatusCode::OK, "Login failed");

    let session_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or_else(|| anyhow::anyhow!("Login response missing Set-Cookie header"))?
        .to_str()?
        .split(';')
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid Set-Cookie format"))?
        .to_string();

    // --- Simulate Upload with a generated V3 card ---
    let upload_request = create_multipart_request(
        "/api/characters/upload",
        "test_card.png",
        mime::IMAGE_PNG.as_ref(),
        &create_test_character_png("v3"), // Use our helper to create a valid V3 card
        Some(vec![("name", "Real Test Character")]),
        Some(&session_cookie),
    );

    let upload_response = test_app.router.clone().oneshot(upload_request).await?;

    // Log response for debugging
    let (status, body_text): (StatusCode, String) = get_text_body(upload_response).await?;
    tracing::info!("Response status: {}, body: {}", status, body_text);

    assert_eq!(
        status,
        StatusCode::CREATED,
        "Upload failed with unexpected status/error: {status} - {body_text}"
    );

    // --- Cleanup ---
    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
// #[ignore] // Added ignore for CI
async fn test_upload_not_png() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    let test_password = "testpassword123";
    let test_username = format!("upload_not_png_user_{}", Uuid::new_v4());
    let username_for_insert = test_username.clone();
    let user_result = run_db_op(&pool, move |conn| {
        insert_test_user_with_password(conn, &username_for_insert, test_password)
    })
    .await?;
    let (user, _) = user_result;
    guard.add_user(user.id);

    let login_body = json!({
        "identifier": test_username.clone(),
        "password": test_password
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_body)?))?;

    let login_response = test_app.router.clone().oneshot(login_request).await?;
    assert_eq!(login_response.status(), StatusCode::OK, "Login failed");

    let session_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or_else(|| anyhow::anyhow!("Login response missing Set-Cookie header"))?
        .to_str()?
        .split(';')
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid Set-Cookie format"))?
        .to_string();

    let upload_request = create_multipart_request(
        "/api/characters/upload",
        "test_card.txt", // Incorrect extension
        "text/plain",    // Incorrect mime type
        b"This is not a PNG",
        Some(vec![("name", "Not PNG Character")]),
        Some(&session_cookie),
    );

    let upload_response = test_app.router.clone().oneshot(upload_request).await?;
    let (status, body_text): (StatusCode, String) = get_text_body(upload_response).await?;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body_text.contains("{\"error\":\"Failed to parse character data\"}"));

    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
// #[ignore] // Added ignore for CI - Removing ignore to run test by default
async fn test_upload_png_no_data_chunk() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    let test_password = "testpassword123";
    let test_username = format!("upload_no_chunk_user_{}", Uuid::new_v4());
    let username_for_insert = test_username.clone();
    let user_result = run_db_op(&pool, move |conn| {
        insert_test_user_with_password(conn, &username_for_insert, test_password)
    })
    .await?;
    let (user, _) = user_result;
    guard.add_user(user.id);

    let login_body = json!({
        "identifier": test_username.clone(),
        "password": test_password
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_body)?))?;

    let login_response = test_app.router.clone().oneshot(login_request).await?;
    assert_eq!(login_response.status(), StatusCode::OK, "Login failed");

    let session_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or_else(|| anyhow::anyhow!("Login response missing Set-Cookie header"))?
        .to_str()?
        .split(';')
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid Set-Cookie format"))?
        .to_string();

    // Create a valid PNG *without* the character data chunk using the image crate
    use image::{RgbaImage, ImageFormat};
    use std::io::Cursor;
    
    let img = RgbaImage::from_pixel(1, 1, image::Rgba([255, 255, 255, 255]));
    let mut png_bytes = Vec::new();
    {
        let mut cursor = Cursor::new(&mut png_bytes);
        img.write_to(&mut cursor, ImageFormat::Png).expect("Failed to write PNG");
    }

    let upload_request = create_multipart_request(
        "/api/characters/upload",
        "no_chunk.png",
        mime::IMAGE_PNG.as_ref(),
        &png_bytes,
        Some(vec![("name", "No Chunk Character")]),
        Some(&session_cookie),
    );

    let upload_response = test_app.router.clone().oneshot(upload_request).await?;
    let (status, body_text): (StatusCode, String) = get_text_body(upload_response).await?;

    tracing::error!(target: "test_debug", "test_upload_png_no_data_chunk: Actual response body: {}", body_text);

    assert_eq!(status, StatusCode::BAD_REQUEST, "Status should be BAD_REQUEST");
    assert!(
        body_text.contains("Failed to parse character data"),
        "Expected character parsing error, got: {}", body_text
    );

    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_upload_with_extra_field() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    let test_password = "testpassword123";
    let test_username = format!("upload_extra_field_user_{}", Uuid::new_v4());
    let username_for_insert = test_username.clone();
    let user_result = run_db_op(&pool, move |conn| {
        insert_test_user_with_password(conn, &username_for_insert, test_password)
    })
    .await?;
    let (user, _) = user_result;
    guard.add_user(user.id);

    let login_body = json!({
        "identifier": test_username.clone(),
        "password": test_password
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_body)?))?;

    let login_response = test_app.router.clone().oneshot(login_request).await?;
    assert_eq!(login_response.status(), StatusCode::OK, "Login failed");

    let session_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or_else(|| anyhow::anyhow!("Login response missing Set-Cookie header"))?
        .to_str()?
        .split(';')
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid Set-Cookie format"))?
        .to_string();

    let upload_request = create_multipart_request(
        "/api/characters/upload",
        "test_card_v3_extra.png",
        mime::IMAGE_PNG.as_ref(),
        &create_test_character_png("v3"),
        Some(vec![
            ("name", "Test Character With Extra"),
            ("extra_field", "extra_value"), // The extra field
        ]),
        Some(&session_cookie),
    );

    let upload_response = test_app.router.clone().oneshot(upload_request).await?;
    // The handler should ignore extra fields and still succeed if the card is valid.
    assert_eq!(upload_response.status(), StatusCode::CREATED);

    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_upload_invalid_json_in_png() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    let test_password = "testpassword123";
    let test_username = format!("upload_invalid_json_user_{}", Uuid::new_v4());
    let username_for_insert = test_username.clone();
    let user_result = run_db_op(&pool, move |conn| {
        insert_test_user_with_password(conn, &username_for_insert, test_password)
    })
    .await?;
    let (user, _) = user_result;
    guard.add_user(user.id);

    let login_body = json!({
        "identifier": test_username.clone(),
        "password": test_password
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_body)?))?;

    let login_response = test_app.router.clone().oneshot(login_request).await?;
    assert_eq!(login_response.status(), StatusCode::OK, "Login failed");

    let session_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or_else(|| anyhow::anyhow!("Login response missing Set-Cookie header"))?
        .to_str()?
        .split(';')
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid Set-Cookie format"))?
        .to_string();

    // Create PNG with invalid JSON payload using the helper function
    let invalid_json_payload = "this is not valid json";
    
    // Create a valid 1x1 white PNG using the image crate
    use image::{RgbaImage, ImageFormat};
    use std::io::Cursor;
    
    let img = RgbaImage::from_pixel(1, 1, image::Rgba([255, 255, 255, 255]));
    let mut png_buffer = Vec::new();
    {
        let mut cursor = Cursor::new(&mut png_buffer);
        img.write_to(&mut cursor, ImageFormat::Png).expect("Failed to write PNG");
    }

    // Find the IEND chunk position and insert the invalid ccv3 chunk before it
    let iend_pos = png_buffer.len() - 12;
    
    // Create the character data tEXt chunk with invalid JSON
    let base64_payload = base64_standard.encode(invalid_json_payload);
    let text_chunk_data = [b"ccv3".as_ref(), &[0u8], base64_payload.as_bytes()].concat();
    let text_chunk_len = u32::try_from(text_chunk_data.len())
        .expect("Text chunk too large")
        .to_be_bytes();
    
    let mut text_chunk = Vec::new();
    text_chunk.extend_from_slice(&text_chunk_len);
    text_chunk.extend_from_slice(b"tEXt");
    text_chunk.extend_from_slice(&text_chunk_data);
    
    // Calculate CRC for tEXt
    let mut crc_text_data = Vec::new();
    crc_text_data.extend_from_slice(b"tEXt");
    crc_text_data.extend_from_slice(&text_chunk_data);
    let crc_text = crc32fast::hash(&crc_text_data);
    text_chunk.extend_from_slice(&crc_text.to_be_bytes());

    // Insert the tEXt chunk before IEND
    let mut png_bytes = Vec::new();
    png_bytes.extend_from_slice(&png_buffer[..iend_pos]);
    png_bytes.extend_from_slice(&text_chunk);
    png_bytes.extend_from_slice(&png_buffer[iend_pos..]);

    let upload_request = create_multipart_request(
        "/api/characters/upload",
        "invalid_json.png",
        mime::IMAGE_PNG.as_ref(),
        &png_bytes,
        Some(vec![("name", "Invalid JSON Character")]),
        Some(&session_cookie),
    );

    let upload_response = test_app.router.clone().oneshot(upload_request).await?;
    let (status, body_text): (StatusCode, String) = get_text_body(upload_response).await?;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body_text.contains("{\"error\":\"Failed to parse character data\"}"));

    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_upload_unauthorized() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app_state = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app_state.db_pool.clone();
    let _ = TestDataGuard::new(pool.clone()); // Guard is for cleanup, not directly used here
    // Use the router from spawn_app directly, no need for build_test_app_for_characters
    let app_router = test_app_state.router;
    let server_addr = spawn_app(app_router).await; // spawn_app now takes the router
    let client = Client::new();

    let upload_url = format!("http://{server_addr}/api/characters/upload");

    let body_bytes = create_test_character_png("v3");
    let boundary = "----WebKitFormBoundaryTest123";
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"character_card\"; filename=\"test.png\"\r\n",
    );
    body.extend_from_slice(b"Content-Type: image/png\r\n\r\n");
    body.extend_from_slice(&body_bytes);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    let response = client
        .post(&upload_url)
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body)
        .send()
        .await?;

    assert_eq!(response.status(), ReqwestStatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn test_upload_missing_file_field() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    let username = format!("upload_missing_field_user_{}", Uuid::new_v4());
    let password = "testpassword";
    let username_for_closure = username.clone();
    let (user, _) = run_db_op(&pool, move |conn| {
        insert_test_user_with_password(conn, &username_for_closure, password)
    })
    .await?;
    guard.add_user(user.id);
    tracing::info!(user_id = %user.id, username = %username, "Test user created for upload_missing_field_test");

    let boundary = "----WebKitFormBoundaryTest456";

    // Login to get session cookie
    let login_body = json!({
        "identifier": username.clone(),
        "password": password
    });
    let login_request_built = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_body)?))?;

    let login_response = test_app.router.clone().oneshot(login_request_built).await?;
    assert_eq!(
        login_response.status(),
        StatusCode::OK,
        "Login failed for missing field test"
    );

    let session_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or_else(|| {
            anyhow::anyhow!("Login response missing Set-Cookie header for missing field test")
        })?
        .to_str()?
        .split(';')
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid Set-Cookie format for missing field test"))?
        .to_string();

    // Rebuild request with cookie
    let request_with_auth = Request::builder()
        .method(Method::POST)
        .uri("/api/characters/upload")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header(header::COOKIE, session_cookie) // Add authentication cookie
        .body(Body::from(
            // Re-create body as it might have been consumed
            {
                let mut body_content_clone = Vec::new();
                body_content_clone.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
                body_content_clone.extend_from_slice(
                    b"Content-Disposition: form-data; name=\"other_field\"\r\n\r\n",
                );
                body_content_clone.extend_from_slice(b"some_value");
                body_content_clone.extend_from_slice(b"\r\n");
                body_content_clone.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
                body_content_clone
            },
        ))?;

    let response = test_app.router.clone().oneshot(request_with_auth).await?;
    let status = response.status();
    let body_bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let body_text = String::from_utf8(body_bytes.to_vec())?;

    tracing::info!(status = %status, body = %body_text, "Received response for missing field");

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Expected Bad Request for missing 'character_card' field"
    );
    assert!(
        body_text.contains("Missing 'character_card' field"),
        "Response body should indicate missing field"
    );

    guard.cleanup().await?;
    Ok(())
}
