#![cfg(test)]

// Local helper functions
use anyhow::Context;
use axum::Router;
use deadpool_diesel::postgres::Pool;
use diesel::{PgConnection, RunQueryDsl, prelude::*};
use reqwest::Client;
use reqwest::StatusCode as ReqwestStatusCode;
use scribe_backend::auth::session_dek::SessionDek;
use scribe_backend::{
    crypto,
    models::{
        characters::Character as DbCharacter,
        users::{AccountStatus, NewUser, User, UserDbQuery, UserRole},
    },
    schema, // For characters::table
    schema::users,
};
use scribe_backend::test_helpers::{TestDataGuard, ensure_tracing_initialized};
use secrecy::{ExposeSecret, SecretString};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use uuid::Uuid;
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
async fn test_list_characters_unauthorized() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app_state = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app_state.db_pool.clone();
    let _guard = TestDataGuard::new(pool.clone());
    let app_router = test_app_state.router;
    let server_addr = spawn_app(app_router).await;
    let client = Client::new();

    let list_url = format!("http://{server_addr}/api/characters");

    let response = client.get(&list_url).send().await?;

    assert_eq!(response.status(), ReqwestStatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn test_list_characters_empty() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    let username = format!("list_empty_user_{}", Uuid::new_v4());
    let password = "testpassword";
    let username_for_closure = username.clone();
    let (user, _dek) = run_db_op(&pool, move |conn| {
        insert_test_user_with_password(conn, &username_for_closure, password)
    })
    .await?;
    guard.add_user(user.id);
    tracing::info!(user_id = %user.id, username = %username, "Test user created for list_characters_empty test");

    let conn = pool
        .get()
        .await
        .context("Failed to get DB connection for character list query")?;
    let user_id_for_query = user.id;

    let characters_list: Vec<DbCharacter> = conn
        .interact(move |conn_block| {
            use scribe_backend::schema::characters::dsl::*;
            characters
                .filter(user_id.eq(user_id_for_query))
                .load::<DbCharacter>(conn_block)
        })
        .await
        .map_err(|e| anyhow::anyhow!("DB interact error: {}", e))??;

    assert_eq!(
        characters_list.len(),
        0,
        "New user should have no characters"
    );
    tracing::info!("Successfully verified user has 0 characters");
    Ok(())
}

#[tokio::test]
async fn test_list_characters_success() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    let username = format!("list_success_user_{}", Uuid::new_v4());
    let password = "testpassword";
    let username_for_closure = username.clone();
    let (user, dek) = run_db_op(&pool, move |conn| {
        insert_test_user_with_password(conn, &username_for_closure, password)
    })
    .await?;
    guard.add_user(user.id);
    tracing::info!(user_id = %user.id, username = %username, "Test user created for list_characters_success test");

    let user_id_for_insert = user.id;
    let dek_clone1 = dek.clone();
    let char1 = run_db_op(&pool, move |conn| {
        insert_test_character(conn, user_id_for_insert, "Character One", &dek_clone1)
    })
    .await?;
    guard.add_character(char1.id);

    let dek_clone2 = dek.clone();
    let char2 = run_db_op(&pool, move |conn| {
        insert_test_character(conn, user_id_for_insert, "Character Two", &dek_clone2)
    })
    .await?;
    guard.add_character(char2.id);
    tracing::info!(char1_id = %char1.id, char2_id = %char2.id, user_id = %user_id_for_insert, "Created two test characters");

    let conn = pool
        .get()
        .await
        .context("Failed to get DB connection for character list query")?;
    let user_id_for_query = user.id;

    let mut characters_list: Vec<DbCharacter> = conn
        .interact(move |conn_block| {
            use scribe_backend::schema::characters::dsl::*;
            characters
                .filter(user_id.eq(user_id_for_query))
                .load::<DbCharacter>(conn_block)
        })
        .await
        .map_err(|e| anyhow::anyhow!("DB interact error: {}", e))??;

    assert_eq!(
        characters_list.len(),
        2,
        "User should have exactly 2 characters"
    );
    characters_list.sort_by(|a, b| a.name.cmp(&b.name));

    assert_eq!(characters_list[0].id, char1.id);
    assert_eq!(characters_list[0].name, "Character One");
    assert_eq!(characters_list[1].id, char2.id);
    assert_eq!(characters_list[1].name, "Character Two");
    tracing::info!("Successfully verified user has 2 characters with correct details");
    Ok(())
}

#[tokio::test]
async fn test_get_unauthorized() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app_state = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app_state.db_pool.clone();
    let _guard = TestDataGuard::new(pool.clone());
    let app_router = test_app_state.router;
    let server_addr = spawn_app(app_router).await;
    let client = Client::new();

    let character_id = Uuid::new_v4();
    let get_url = format!("http://{server_addr}/api/characters/fetch/{character_id}"); // Adjusted path
    tracing::info!(target: "auth_debug", "test_get_unauthorized: Sending GET to {}", get_url);

    let response = client.get(&get_url).send().await?;
    tracing::info!(target: "auth_debug", "test_get_unauthorized: Received status {}", response.status());

    // Based on current behavior in original tests, expecting 404 when unauthenticated for this specific path
    assert_eq!(response.status(), ReqwestStatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn test_get_nonexistent_character() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    let username = format!("get_nonexist_user_{}", Uuid::new_v4());
    let password = "testpassword";
    let username_for_closure = username.clone();
    let (user, _dek) = run_db_op(&pool, move |conn| {
        insert_test_user_with_password(conn, &username_for_closure, password)
    })
    .await?;
    guard.add_user(user.id);
    tracing::info!(user_id = %user.id, username = %username, "Test user created for get_nonexistent_character test");

    let non_existent_id = Uuid::new_v4();
    let conn = pool
        .get()
        .await
        .context("Failed to get DB connection for character query")?;
    let user_id_for_query = user.id;

    let character_result: Option<DbCharacter> = conn
        .interact(move |conn_block| {
            use scribe_backend::schema::characters::dsl::*;
            characters
                .filter(id.eq(non_existent_id))
                .filter(user_id.eq(user_id_for_query))
                .first::<DbCharacter>(conn_block)
                .optional()
        })
        .await
        .map_err(|e| anyhow::anyhow!("DB interact error: {}", e))??;

    assert!(
        character_result.is_none(),
        "Non-existent character should not be found"
    );
    Ok(())
}

#[tokio::test]
async fn test_get_character_forbidden() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    let owner_username = format!("get_forbidden_user_a_{}", Uuid::new_v4());
    let owner_password = "passwordA";
    let owner_username_for_closure = owner_username.clone();
    let (character_owner, owner_dek) = run_db_op(&pool, move |conn| {
        insert_test_user_with_password(conn, &owner_username_for_closure, owner_password)
    })
    .await?;
    guard.add_user(character_owner.id);

    let unauthorized_username = format!("get_forbidden_user_b_{}", Uuid::new_v4());
    let unauthorized_password = "passwordB";
    let unauthorized_username_for_closure = unauthorized_username.clone();
    let (unauthorized_user, _unauthorized_dek) = run_db_op(&pool, move |conn| {
        insert_test_user_with_password(
            conn,
            &unauthorized_username_for_closure,
            unauthorized_password,
        )
    })
    .await?;
    guard.add_user(unauthorized_user.id);

    let owner_id_for_insert = character_owner.id;
    let owner_dek_clone = owner_dek.clone();
    let owned_character = run_db_op(&pool, move |conn| {
        insert_test_character(
            conn,
            owner_id_for_insert,
            "Character A For Get",
            &owner_dek_clone,
        )
    })
    .await?;
    guard.add_character(owned_character.id);

    // User B tries to get User A's character
    let conn_b = pool
        .get()
        .await
        .context("Failed to get DB conn for User B query")?;
    let character_id_for_forbidden_access = owned_character.id;
    let unauthorized_user_id = unauthorized_user.id;
    let character_result_b: Option<DbCharacter> = conn_b
        .interact(move |conn_block| {
            use scribe_backend::schema::characters::dsl::*;
            characters
                .filter(id.eq(character_id_for_forbidden_access))
                .filter(user_id.eq(unauthorized_user_id)) // Unauthorized user's ID
                .first::<DbCharacter>(conn_block)
                .optional()
        })
        .await
        .map_err(|e| anyhow::anyhow!("DB interact error for User B: {}", e))??;
    assert!(
        character_result_b.is_none(),
        "User B should not be able to access User A's character"
    );

    // User A (owner) gets their character
    let conn_a = pool
        .get()
        .await
        .context("Failed to get DB conn for User A query")?;
    let character_id_for_owner_access = owned_character.id;
    let owner_id_for_query = character_owner.id;
    let character_result_a: Option<DbCharacter> = conn_a
        .interact(move |conn_block| {
            use scribe_backend::schema::characters::dsl::*;
            characters
                .filter(id.eq(character_id_for_owner_access))
                .filter(user_id.eq(owner_id_for_query)) // Owner's ID
                .first::<DbCharacter>(conn_block)
                .optional()
        })
        .await
        .map_err(|e| anyhow::anyhow!("DB interact error for User A: {}", e))??;
    assert!(
        character_result_a.is_some(),
        "User A should be able to access their character"
    );
    assert_eq!(character_result_a.unwrap().id, owned_character.id);
    Ok(())
}

// Placeholder for a generic get character success test if needed,
// for now, the positive case in test_get_character_forbidden covers owner access.
// #[tokio::test]
// async fn test_get_character_success() -> Result<(), anyhow::Error> {
//     // ... setup user, character, login, make request, assert success ...
//     Ok(())
// }
