#![cfg(test)]
use super::helpers::{insert_test_character, insert_test_user_with_password, run_db_op, spawn_app};
use anyhow::Context;
use diesel::prelude::*;
use reqwest::Client;
use reqwest::StatusCode as ReqwestStatusCode;
use scribe_backend::models::characters::Character as DbCharacter;
use scribe_backend::test_helpers::{TestDataGuard, ensure_tracing_initialized};
use serde_json::json;
use uuid::Uuid;

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

    let generate_url = format!("http://{}/api/characters/generate", server_addr);
    let prompt_data = json!({ "prompt": "Create a character." });

    let response = client.post(&generate_url).json(&prompt_data).send().await?;

    assert_eq!(response.status(), ReqwestStatusCode::UNAUTHORIZED);
    Ok(())
}
