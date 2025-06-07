#![cfg(test)]
#![allow(clippy::too_many_lines)]

// Remove helpers import - we'll define locally
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use diesel_json::Json as DieselJson; // Added for explicit Json wrapping
use scribe_backend::models::characters::CharacterDataForClient; // Updated import
use scribe_backend::test_helpers::{TestDataGuard, ensure_tracing_initialized}; // Removed TestUser as it's not a struct here
use serde_json::{Value as JsonValue, json}; // Added JsonValue
use tower::ServiceExt; // For oneshot
use uuid::Uuid;

// Local helper functions
use anyhow::Context;
use deadpool_diesel::postgres::Pool;
use diesel::{PgConnection, RunQueryDsl, prelude::*};
use scribe_backend::auth::session_dek::SessionDek;
use scribe_backend::{
    crypto,
    models::{
        users::{AccountStatus, NewUser, User, UserDbQuery, UserRole},
    },
    schema::users,
};
use secrecy::{ExposeSecret, SecretString};
use axum::http::Response as AxumResponse;
use http_body_util::BodyExt;
use bcrypt;

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
    response: AxumResponse<Body>,
) -> Result<(StatusCode, String), anyhow::Error> {
    let status = response.status();
    let body_bytes = response.into_body().collect().await?.to_bytes();
    let body_text = String::from_utf8(body_bytes.to_vec())?;
    Ok((status, body_text))
}

#[tokio::test]
async fn test_create_character_minimal_fields() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    // --- Setup Test User ---
    let test_password = "testpassword123";
    let test_username = format!("create_char_user_{}", Uuid::new_v4());
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

    // --- Simulate Character Creation with Minimal Fields ---
    let create_body = json!({
        "name": "Test Manual Character",
        "name": "Test Manual Character",
        "description": "A test character created manually",
        "first_mes": "Hello, I'm a manually created test character!",
        // Optional fields are not provided, relying on DTO defaults (empty strings/vecs)
        // and service layer defaults (e.g. for extensions)
    });

    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/api/characters")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, &session_cookie)
        .body(Body::from(serde_json::to_vec(&create_body)?))?;

    let create_response = test_app.router.clone().oneshot(create_request).await?;

    let (status, body_text): (StatusCode, String) = get_text_body(create_response).await?;
    tracing::info!(
        "Minimal Fields - Response status: {}, body: {}",
        status,
        body_text
    );

    assert_eq!(
        status,
        StatusCode::CREATED,
        "Character creation with minimal fields failed. Body: {body_text}"
    );

    let created_char: CharacterDataForClient = serde_json::from_str(&body_text)
        .expect("Failed to deserialize response into CharacterDataForClient");

    assert_eq!(created_char.name, "Test Manual Character");
    assert_eq!(
        created_char.description.as_deref(),
        Some("A test character created manually")
    );
    assert_eq!(
        created_char.first_mes.as_deref(),
        Some("Hello, I'm a manually created test character!")
    );

    assert_eq!(created_char.spec, "chara_card_v3");
    assert_eq!(created_char.spec_version, "3.0");

    // Check default values for optional fields
    // Assuming empty strings from DTO become Some("") after encryption/decryption
    assert_eq!(
        created_char.personality.as_deref(),
        Some(""),
        "Personality should default to Some(\"\")"
    );
    assert_eq!(
        created_char.scenario.as_deref(),
        Some(""),
        "Scenario should default to Some(\"\")"
    );
    assert_eq!(
        created_char.mes_example.as_deref(),
        Some(""),
        "MesExample should default to Some(\"\")"
    );
    assert_eq!(
        created_char.creator_notes.as_deref(),
        Some(""),
        "CreatorNotes should default to Some(\"\")"
    );
    assert_eq!(
        created_char.system_prompt.as_deref(),
        Some(""),
        "SystemPrompt should default to Some(\"\")"
    );
    assert_eq!(
        created_char.post_history_instructions.as_deref(),
        Some(""),
        "PostHistoryInstructions should default to Some(\"\")"
    );

    assert_eq!(
        created_char.tags,
        Some(vec![]),
        "Tags should default to Some(vec![])"
    );
    assert_eq!(
        created_char.alternate_greetings,
        Some(vec![]),
        "AlternateGreetings should default to Some(vec![])"
    );

    // Assert extensions default
    assert_eq!(
        created_char.extensions,
        Some(DieselJson(JsonValue::Object(serde_json::Map::new()))),
        "Extensions should default to an empty JSON object"
    );

    assert_eq!(created_char.user_id, user.id);
    assert!(
        !created_char.id.is_nil(),
        "Character ID should be a valid UUID"
    );

    let now = chrono::Utc::now();
    assert!(
        created_char.created_at <= now
            && created_char.created_at > now - chrono::Duration::seconds(5),
        "created_at is not recent"
    );
    assert!(
        created_char.updated_at <= now
            && created_char.updated_at > now - chrono::Duration::seconds(5),
        "updated_at is not recent"
    );

    // Encryption verification is implicitly done by successful decryption into CharacterDataForClient fields.

    // --- Cleanup ---
    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_create_character_unauthorized() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;

    // --- Attempt to Create Character Without Authentication ---
    let create_body = json!({
        "name": "Test Unauthorized Character",
        "description": "This creation attempt should fail",
        "first_mes": "Hello, I shouldn't exist!"
    });

    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/api/characters")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&create_body)?))?;

    let create_response = test_app.router.clone().oneshot(create_request).await?;

    assert_eq!(
        create_response.status(),
        StatusCode::UNAUTHORIZED,
        "Unauthenticated character creation should return 401"
    );

    Ok(())
}

#[tokio::test]
async fn test_create_character_all_fields() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    // --- Setup Test User ---
    let test_password = "testpassword123";
    let test_username = format!("create_char_all_fields_user_{}", Uuid::new_v4());
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

    // --- Simulate Character Creation with All Fields ---
    let create_body = json!({
        "name": "Complete Test Character",
        "description": "A test character with all fields populated",
        "first_mes": "Hello, I'm a complete test character with all fields!",
        "personality": "Friendly, helpful, and detailed",
        "scenario": "In a test environment responding to API requests",
        "mes_example": "User: How are you?\nCharacter: I'm doing great, thanks for asking!",
        "creator_notes": "This character was created for testing the manual creation API",
        "system_prompt": "You are a test character created via the API",
        "post_history_instructions": "Continue being helpful in your responses",
        "tags": ["test", "api", "manual_creation"],
        "creator": "API Tester",
        "character_version": "1.0.0",
        "alternate_greetings": ["Hey there!", "Greetings, tester!"],
        "extensions": json!({"custom_field": "custom_value", "nested": {"value": 123}})
    });

    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/api/characters")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, &session_cookie)
        .body(Body::from(serde_json::to_vec(&create_body)?))?;

    let create_response = test_app.router.clone().oneshot(create_request).await?;

    let (status, body_text): (StatusCode, String) = get_text_body(create_response).await?;
    tracing::info!(
        "All Fields - Response status: {}, body: {}",
        status,
        body_text
    );

    assert_eq!(
        status,
        StatusCode::CREATED,
        "Character creation with all fields failed. Body: {body_text}"
    );

    let created_char: CharacterDataForClient = serde_json::from_str(&body_text)
        .expect("Failed to deserialize response into CharacterDataForClient");

    assert_eq!(created_char.name, "Complete Test Character");
    assert_eq!(
        created_char.description.as_deref(),
        Some("A test character with all fields populated")
    );
    assert_eq!(
        created_char.first_mes.as_deref(),
        Some("Hello, I'm a complete test character with all fields!")
    );
    assert_eq!(
        created_char.personality.as_deref(),
        Some("Friendly, helpful, and detailed")
    );
    assert_eq!(
        created_char.scenario.as_deref(),
        Some("In a test environment responding to API requests")
    );
    assert_eq!(
        created_char.mes_example.as_deref(),
        Some("User: How are you?\nCharacter: I'm doing great, thanks for asking!")
    );
    assert_eq!(
        created_char.creator_notes.as_deref(),
        Some("This character was created for testing the manual creation API")
    );
    assert_eq!(
        created_char.system_prompt.as_deref(),
        Some("You are a test character created via the API")
    );
    assert_eq!(
        created_char.post_history_instructions.as_deref(),
        Some("Continue being helpful in your responses")
    );

    assert_eq!(
        created_char.tags,
        Some(vec![
            Some("test".to_string()),
            Some("api".to_string()),
            Some("manual_creation".to_string())
        ])
    );
    assert_eq!(created_char.creator.as_deref(), Some("API Tester"));
    assert_eq!(created_char.character_version.as_deref(), Some("1.0.0"));
    assert_eq!(
        created_char.alternate_greetings,
        Some(vec![
            "Hey there!".to_string(),
            "Greetings, tester!".to_string()
        ])
    );

    assert_eq!(created_char.spec, "chara_card_v3");
    assert_eq!(created_char.spec_version, "3.0");

    let expected_extensions_json_value =
        json!({"custom_field": "custom_value", "nested": {"value": 123}});
    assert_eq!(
        created_char.extensions,
        Some(DieselJson(expected_extensions_json_value))
    );

    assert_eq!(created_char.user_id, user.id);
    assert!(!created_char.id.is_nil());

    // --- Cleanup ---
    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_create_character_missing_required_fields() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    // --- Setup Test User ---
    let test_password = "testpassword123";
    let test_username = format!("create_char_missing_fields_user_{}", Uuid::new_v4());
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

    // Test cases for missing required fields
    let test_cases = vec![
        // Missing name
        (
            json!({
                "description": "A test character missing the name",
                "first_mes": "Hello, I have no name!"
            }),
            "name is required",
        ),
        // Empty name
        (
            json!({
                "name": "",
                "description": "A test character with empty name",
                "first_mes": "Hello, I have an empty name!"
            }),
            "name cannot be empty if provided",
        ),
        // Missing description
        (
            json!({
                "name": "No Description Character",
                "first_mes": "Hello, I have no description!"
            }),
            "description is required",
        ),
        // Empty description
        (
            json!({
                "name": "Empty Description Character",
                "description": " ", // Whitespace only
                "first_mes": "Hello, I have an empty description!"
            }),
            "description cannot be empty if provided",
        ),
        // Missing first_mes
        (
            json!({
                "name": "No First Message Character",
                "description": "A test character missing the first message"
            }),
            "first_mes is required",
        ),
        // Empty first_mes
        (
            json!({
                "name": "Empty First Message Character",
                "description": "A test character with empty first message",
                "first_mes": "\t" // Whitespace only
            }),
            "first_mes cannot be empty if provided",
        ),
        // Empty object (all missing)
        (
            json!({}),
            "name is required, description is required, first_mes is required",
        ),
    ];

    for (i, (test_case_json, expected_error_substring)) in test_cases.iter().enumerate() {
        let create_request = Request::builder()
            .method(Method::POST)
            .uri("/api/characters")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, &session_cookie)
            .body(Body::from(serde_json::to_vec(test_case_json)?))?;

        let create_response = test_app.router.clone().oneshot(create_request).await?;

        let (status, body_text): (StatusCode, String) = get_text_body(create_response).await?;
        tracing::info!(
            "Missing Fields Test Case {}: Response status: {}, body: {}",
            i,
            status,
            body_text
        );

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "Character creation with missing/empty required fields (case {i}) should fail with 400 Bad Request. Body: {body_text}"
        );

        // Check that the error message contains the specific validation error
        // The error message from CharacterCreateDto::validate() is "Validation errors: <field specific error>"
        // or multiple errors joined by ", "
        assert!(
            body_text.contains(expected_error_substring),
            "Error message for case {i} did not contain expected substring '{expected_error_substring}'. Full error: {body_text}"
        );
    }

    // --- Cleanup ---
    guard.cleanup().await?;
    Ok(())
}
