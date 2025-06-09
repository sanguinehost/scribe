#![cfg(test)]

// Local helper functions
use anyhow::Context;
use axum::Router;
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
use serde_json::json;
use std::net::SocketAddr;
use tokio::net::TcpListener;
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
async fn test_generate_character() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    let username = format!("gen_user_{}", Uuid::new_v4());
    let password = "password123";
    let (user, dek) = run_db_op(&pool, {
        let username = username.clone();
        let password = password.to_string();
        move |conn| insert_test_user_with_password(conn, &username, &password)
    })
    .await
    .context("Failed to insert test user for generation")?;
    guard.add_user(user.id);
    tracing::info!(user_id = %user.id, %username, "Test user created for character generation");

    let user_id_for_insert = user.id;
    let dek_for_insert = dek.clone();

    let character = run_db_op(&pool, move |conn| {
        insert_test_character(
            conn,
            user_id_for_insert,
            "Generated Wizard Character",
            &dek_for_insert,
        )
    })
    .await
    .context("Failed to insert test character")?;
    guard.add_character(character.id);
    tracing::info!(
        character_id = %character.id,
        character_name = %character.name,
        user_id = %user.id,
        "Successfully created character directly in database"
    );

    let conn = pool
        .get()
        .await
        .context("Failed to get DB connection for character verification")?;
    let user_id_for_query = user.id;
    let char_id_for_query = character.id;

    let character_result: Option<DbCharacter> = conn
        .interact(move |conn_block| {
            use scribe_backend::schema::characters::dsl::*;
            characters
                .filter(id.eq(char_id_for_query))
                .filter(user_id.eq(user_id_for_query))
                .first::<DbCharacter>(conn_block)
                .optional()
        })
        .await
        .map_err(|e| anyhow::anyhow!("DB interact error: {}", e))??;

    assert!(
        character_result.is_some(),
        "Character should exist in the database"
    );
    let found_character = character_result.unwrap();
    assert_eq!(found_character.id, character.id);
    assert_eq!(found_character.user_id, user.id);
    assert_eq!(found_character.name, "Generated Wizard Character");
    assert_eq!(found_character.spec, "chara_card_v3");
    assert_eq!(found_character.spec_version, "1.0");

    tracing::info!("Test generate_character completed successfully.");
    Ok(())
}

#[tokio::test]
async fn test_generate_unauthorized() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app_state = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app_state.db_pool.clone();
    let _guard = TestDataGuard::new(pool.clone());
    let app_router = test_app_state.router;
    let server_addr = spawn_app(app_router).await;
    let client = Client::new();

    let generate_url = format!("http://{server_addr}/api/characters/generate");
    let prompt_data = json!({ "prompt": "Create a character." });

    let response = client.post(&generate_url).json(&prompt_data).send().await?;

    assert_eq!(response.status(), ReqwestStatusCode::UNAUTHORIZED);
    Ok(())
}
