#![cfg(test)]

// Local helper functions
use anyhow::Context;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use bcrypt;
use deadpool_diesel::postgres::Pool;
use diesel::{PgConnection, RunQueryDsl, prelude::*};
use reqwest::Client;
use reqwest::StatusCode as ReqwestStatusCode;
use scribe_backend::auth::session_dek::SessionDek;
use scribe_backend::test_helpers::{TestDataGuard, ensure_tracing_initialized};
use scribe_backend::{
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
use tower::ServiceExt; // For oneshot
use uuid::Uuid;

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

/// Insert a test character into the database
fn insert_test_character(
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
        name,
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
async fn test_get_character_image_not_implemented() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    let username = format!("get_image_user_{}", Uuid::new_v4());
    let password = "testpassword";
    let (user, dek) = run_db_op(&pool, {
        let username = username.clone();
        let password = password.to_string();
        move |conn| insert_test_user_with_password(conn, &username, &password)
    })
    .await?;
    guard.add_user(user.id);

    let user_id_for_char = user.id;
    let dek_clone = dek.clone();
    let character = run_db_op(&pool, move |conn| {
        insert_test_character(conn, user_id_for_char, "Character For Image", &dek_clone)
    })
    .await?;
    guard.add_character(character.id);

    let request = Request::builder()
        .method("GET")
        .uri(format!("/api/characters/{}/image", character.id)) // This was the original path in the test
        .body(Body::empty())?;

    let response = test_app.router.clone().oneshot(request).await?;
    let status = response.status();
    let body_bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let body_text = String::from_utf8(body_bytes.to_vec())?;

    tracing::info!(status = %status, body = %body_text, "Received response from image endpoint");

    // The original test accepted UNAUTHORIZED, NOT_IMPLEMENTED, or NOT_FOUND.
    // Given the path, UNAUTHORIZED or NOT_FOUND (if auth is strict before hitting handler) are most likely.
    // If the route /api/characters/:id/image truly doesn't exist or isn't fully wired, NOT_FOUND is expected.
    // If it exists but is behind auth, UNAUTHORIZED is expected if not logged in.
    // NOT_IMPLEMENTED would imply the handler is hit and explicitly returns that.
    assert!(
        status == StatusCode::UNAUTHORIZED
            || status == StatusCode::NOT_FOUND
            || status == StatusCode::NOT_IMPLEMENTED,
        "Expected Unauthorized, Not Found, or Not Implemented, got: {status} - {body_text}"
    );
    Ok(())
}

#[tokio::test]
async fn test_get_character_image_unauthorized() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app_state = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app_state.db_pool.clone();
    let _guard = TestDataGuard::new(pool.clone());
    let app_router = test_app_state.router;
    let server_addr = spawn_app(app_router).await;
    let client = Client::new();

    let character_id = Uuid::new_v4();
    // This path was `/api/characters/fetch/:id/image` in the original test,
    // which implies a different routing structure than the `not_implemented` test above.
    // We'll keep it as is from the original test.
    let image_url = format!("http://{server_addr}/api/characters/fetch/{character_id}/image");

    let response = client.get(&image_url).send().await?;
    tracing::info!("Test request to URL: {}", image_url);
    tracing::info!("Response status: {}", response.status());

    // Original test expected NOT_FOUND for unauthenticated requests to this specific path.
    assert_eq!(response.status(), ReqwestStatusCode::NOT_FOUND);
    Ok(())
}
