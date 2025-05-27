#![cfg(test)]
use anyhow::Context;
use axum::{
    Router,
    body::Body,
    http::{Method, Request, Response as AxumResponse, StatusCode, header},
    middleware::Next,
    response::IntoResponse,
};
use axum_login::AuthSession;
use base64::{Engine as _, engine::general_purpose::STANDARD as base64_standard};
use bcrypt;
use crc32fast;
use deadpool_diesel::postgres::Pool;
use diesel::{PgConnection, RunQueryDsl, prelude::*};
use http_body_util::BodyExt;
use scribe_backend::auth::session_dek::SessionDek;
use scribe_backend::{
    auth::user_store::Backend as AuthBackend,
    crypto,
    models::{
        characters::Character as DbCharacter,
        users::{AccountStatus, NewUser, User, UserDbQuery, UserRole},
    },
    schema, // For characters::table
    schema::users,
};
use secrecy::{ExposeSecret, SecretString};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::instrument;
use uuid::Uuid;

// Helper function to insert a test character (returns Result<(), ...>)
pub fn insert_test_character(
    conn: &mut PgConnection,
    user_uuid: Uuid,
    name: &str,
    dek: &SessionDek, // Add DEK parameter
) -> Result<DbCharacter, diesel::result::Error> {
    use schema::characters; // Specific import for the table

    // Define a local struct for insertion
    #[derive(Insertable)]
    #[diesel(table_name = characters)]
    struct NewDbCharacter<'a> {
        user_id: Uuid,
        name: &'a str,
        description: Option<Vec<u8>>,
        personality: Option<Vec<u8>>,
        spec: &'a str,
        spec_version: &'a str,
        description_nonce: Option<Vec<u8>>,
        personality_nonce: Option<Vec<u8>>,
    }

    // Encrypt description and personality
    let default_description = "Default test description";
    let (encrypted_description, description_nonce) =
        crypto::encrypt_gcm(default_description.as_bytes(), &dek.0)
            .expect("Failed to encrypt test description");

    let default_personality = "Default test personality";
    let (encrypted_personality, personality_nonce) =
        crypto::encrypt_gcm(default_personality.as_bytes(), &dek.0)
            .expect("Failed to encrypt test personality");

    let new_character_for_insert = NewDbCharacter {
        user_id: user_uuid,
        name: name,
        description: Some(encrypted_description),
        personality: Some(encrypted_personality),
        spec: "chara_card_v3",
        spec_version: "1.0", // Assuming a default, adjust if necessary
        description_nonce: Some(description_nonce),
        personality_nonce: Some(personality_nonce),
    };

    diesel::insert_into(characters::table)
        .values(&new_character_for_insert)
        .returning(DbCharacter::as_returning())
        .get_result(conn)
}

// Helper to create a multipart form request using write! macro for reliability
// Updated to accept a session cookie header instead of a token
pub fn create_multipart_request(
    uri: &str,
    filename: &str,
    content_type: &str,
    body_bytes: Vec<u8>,
    extra_fields: Option<Vec<(&str, &str)>>,
    session_cookie: Option<&str>, // Changed from _auth_token to session_cookie
) -> Request<Body> {
    let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    let mut body = Vec::new();

    // Add file part
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"character_card\"; filename=\"{}\"\r\n",
            filename
        )
        .as_bytes(),
    );
    body.extend_from_slice(format!("Content-Type: {}\r\n\r\n", content_type).as_bytes());
    body.extend_from_slice(&body_bytes);
    body.extend_from_slice(b"\r\n");

    // Add extra fields if any
    if let Some(fields) = extra_fields {
        for (name, value) in fields {
            body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
            body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{}\"\r\n\r\n", name).as_bytes(),
            );
            body.extend_from_slice(value.as_bytes());
            body.extend_from_slice(b"\r\n");
        }
    }

    // Final boundary
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

    let mut request_builder = Request::builder().method(Method::POST).uri(uri).header(
        header::CONTENT_TYPE,
        format!("multipart/form-data; boundary={}", boundary),
    );

    // Add cookie header if provided
    if let Some(cookie) = session_cookie {
        request_builder = request_builder.header(header::COOKIE, cookie);
    }

    request_builder.body(Body::from(body)).unwrap()
}

// Helper to create a test PNG with a valid character card chunk
pub fn create_test_character_png(version: &str) -> Vec<u8> {
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
        _ => panic!("Unsupported version: {}", version),
    };

    // Create a minimal valid PNG with the character chunk
    let mut png_bytes = Vec::new();

    // PNG signature
    png_bytes.extend_from_slice(&[137, 80, 78, 71, 13, 10, 26, 10]);

    // IHDR chunk (required)
    let ihdr_data = &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0];
    let ihdr_len = (ihdr_data.len() as u32).to_be_bytes();
    png_bytes.extend_from_slice(&ihdr_len);
    png_bytes.extend_from_slice(b"IHDR");
    png_bytes.extend_from_slice(ihdr_data);

    // Calculate CRC for IHDR
    let mut crc_data = Vec::new();
    crc_data.extend_from_slice(b"IHDR");
    crc_data.extend_from_slice(ihdr_data);
    let crc_ihdr = crc32fast::hash(&crc_data);
    png_bytes.extend_from_slice(&crc_ihdr.to_be_bytes());

    // tEXt chunk with character data
    let base64_payload = base64_standard.encode(json_payload);
    let text_chunk_data = [chunk_keyword.as_bytes(), &[0u8], base64_payload.as_bytes()].concat();
    let text_chunk_len = (text_chunk_data.len() as u32).to_be_bytes();
    png_bytes.extend_from_slice(&text_chunk_len);
    png_bytes.extend_from_slice(b"tEXt");
    png_bytes.extend_from_slice(&text_chunk_data);

    // Calculate CRC for tEXt
    let mut crc_text_data = Vec::new();
    crc_text_data.extend_from_slice(b"tEXt");
    crc_text_data.extend_from_slice(&text_chunk_data);
    let crc_text = crc32fast::hash(&crc_text_data);
    png_bytes.extend_from_slice(&crc_text.to_be_bytes());

    // IDAT chunk (minimal required data)
    let idat_data = &[8, 29, 99, 96, 0, 0, 0, 3, 0, 1];
    let idat_len = (idat_data.len() as u32).to_be_bytes();
    png_bytes.extend_from_slice(&idat_len);
    png_bytes.extend_from_slice(b"IDAT");
    png_bytes.extend_from_slice(idat_data);

    // Calculate CRC for IDAT
    let mut crc_idat_data = Vec::new();
    crc_idat_data.extend_from_slice(b"IDAT");
    crc_idat_data.extend_from_slice(idat_data);
    let crc_idat = crc32fast::hash(&crc_idat_data);
    png_bytes.extend_from_slice(&crc_idat.to_be_bytes());

    // IEND chunk
    png_bytes.extend_from_slice(&[0, 0, 0, 0]);
    png_bytes.extend_from_slice(b"IEND");
    png_bytes.extend_from_slice(&[174, 66, 96, 130]);

    png_bytes
}

// Helper to hash a password for tests
pub fn hash_test_password(password: &str) -> String {
    bcrypt::hash(password, bcrypt::DEFAULT_COST).expect("Failed to hash test password with bcrypt")
}

// Helper to insert a unique test user with a known password hash
pub fn insert_test_user_with_password(
    conn: &mut PgConnection,
    username: &str,
    password: &str,
) -> Result<(User, SessionDek), diesel::result::Error> {
    let hashed_password = hash_test_password(password);
    let email = format!("{}@example.com", username);

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

// Middleware to log request details for debugging routing
#[allow(dead_code)]
pub async fn log_requests_middleware(req: Request<Body>, next: Next) -> impl IntoResponse {
    tracing::info!(target: "LOG_REQ_MIDDLEWARE", "Received request: {} {}", req.method(), req.uri().path());
    next.run(req).await
}

// Auth middleware for debugging auth-related issues
#[instrument(skip_all, fields(uri = %req.uri()))]
pub async fn auth_log_wrapper(
    auth_session: AuthSession<AuthBackend>,
    req: Request<Body>,
    next: Next,
) -> AxumResponse<Body> {
    let user_present = auth_session.user.is_some();
    let original_uri = req.uri().clone();
    tracing::warn!(
        target: "auth_middleware_debug",
        uri = %original_uri,
        user_in_session = user_present,
        "ENTERING auth_log_wrapper for protected routes"
    );
    let res = next.run(req).await;
    tracing::warn!(
        target: "auth_middleware_debug",
        uri = %original_uri,
        status = %res.status(),
        user_in_session_after_next = user_present,
        "EXITING auth_log_wrapper for protected routes"
    );
    res
}

// Helper to Build Test App (Similar to auth_tests)
pub async fn build_test_app_for_characters(_pool: Pool) -> Router {
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    test_app.router
}

// Helper to spawn the app in the background
pub async fn spawn_app(app: Router) -> SocketAddr {
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

// Helper function to run DB operations via pool interact
pub async fn run_db_op<F, T>(pool: &Pool, op: F) -> Result<T, anyhow::Error>
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

// Helper to extract plain text body
pub async fn get_text_body(
    response: AxumResponse<Body>,
) -> Result<(StatusCode, String), anyhow::Error> {
    let status = response.status();
    let body_bytes = response.into_body().collect().await?.to_bytes();
    let body_text = String::from_utf8(body_bytes.to_vec())?;
    Ok((status, body_text))
}
