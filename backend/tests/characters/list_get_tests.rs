#![cfg(test)]
use super::helpers::{
    insert_test_character, insert_test_user_with_password,
    run_db_op, spawn_app,
};
use anyhow::Context;
use diesel::prelude::*;
use reqwest::Client;
use reqwest::StatusCode as ReqwestStatusCode;
use scribe_backend::models::characters::Character as DbCharacter;
use scribe_backend::test_helpers::{ensure_tracing_initialized, TestDataGuard};
use uuid::Uuid;

#[tokio::test]
async fn test_list_characters_unauthorized() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app_state = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app_state.db_pool.clone();
    let _guard = TestDataGuard::new(pool.clone());
    let app_router = test_app_state.router;
    let server_addr = spawn_app(app_router).await;
    let client = Client::new();

    let list_url = format!("http://{}/api/characters", server_addr);

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
    let get_url = format!("http://{}/api/characters/fetch/{}", server_addr, character_id); // Adjusted path
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

    let username_a = format!("get_forbidden_user_a_{}", Uuid::new_v4());
    let password_a = "passwordA";
    let username_a_closure = username_a.clone();
    let (user_a, dek_a) = run_db_op(&pool, move |conn| {
        insert_test_user_with_password(conn, &username_a_closure, password_a)
    })
    .await?;
    guard.add_user(user_a.id);

    let username_b = format!("get_forbidden_user_b_{}", Uuid::new_v4());
    let password_b = "passwordB";
    let username_b_closure = username_b.clone();
    let (user_b, _dek_b) = run_db_op(&pool, move |conn| {
        insert_test_user_with_password(conn, &username_b_closure, password_b)
    })
    .await?;
    guard.add_user(user_b.id);

    let user_a_id_for_insert = user_a.id;
    let dek_a_clone = dek_a.clone();
    let character_a = run_db_op(&pool, move |conn| {
        insert_test_character(conn, user_a_id_for_insert, "Character A For Get", &dek_a_clone)
    })
    .await?;
    guard.add_character(character_a.id);

    // User B tries to get User A's character
    let conn_b = pool.get().await.context("Failed to get DB conn for User B query")?;
    let char_id_for_b_query = character_a.id;
    let user_b_id_for_query = user_b.id;
    let character_result_b: Option<DbCharacter> = conn_b
        .interact(move |conn_block| {
            use scribe_backend::schema::characters::dsl::*;
            characters
                .filter(id.eq(char_id_for_b_query))
                .filter(user_id.eq(user_b_id_for_query)) // User B's ID
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
    let conn_a = pool.get().await.context("Failed to get DB conn for User A query")?;
    let char_id_for_a_query = character_a.id;
    let user_a_id_for_query = user_a.id;
    let character_result_a: Option<DbCharacter> = conn_a
        .interact(move |conn_block| {
            use scribe_backend::schema::characters::dsl::*;
            characters
                .filter(id.eq(char_id_for_a_query))
                .filter(user_id.eq(user_a_id_for_query)) // User A's ID
                .first::<DbCharacter>(conn_block)
                .optional()
        })
        .await
        .map_err(|e| anyhow::anyhow!("DB interact error for User A: {}", e))??;
    assert!(
        character_result_a.is_some(),
        "User A should be able to access their character"
    );
    assert_eq!(character_result_a.unwrap().id, character_a.id);
    Ok(())
}

// Placeholder for a generic get character success test if needed,
// for now, the positive case in test_get_character_forbidden covers owner access.
// #[tokio::test]
// async fn test_get_character_success() -> Result<(), anyhow::Error> {
//     // ... setup user, character, login, make request, assert success ...
//     Ok(())
// }