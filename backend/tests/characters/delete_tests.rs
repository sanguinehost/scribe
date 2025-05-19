#![cfg(test)]
use super::helpers::{
    insert_test_character, insert_test_user_with_password,
    run_db_op,
};
use anyhow::Context;
use axum::http::{header, Method, Request, StatusCode as AxumStatusCode}; // Renamed
use axum::body::Body;
use diesel::prelude::*;
use reqwest::Client;
use reqwest::StatusCode as ReqwestStatusCode;
use scribe_backend::test_helpers::{ensure_tracing_initialized, TestDataGuard};
use serde_json::json;
use tower::ServiceExt; // For oneshot
use uuid::Uuid;

#[tokio::test]
async fn test_delete_character_success() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone()); // Guard for cleanup

    let username = format!("delete_user_{}", Uuid::new_v4());
    let password = "password123".to_string();

    let (user_in_db, dek) = run_db_op(&pool, {
        let username = username.clone();
        let password = password.clone();
        move |conn| insert_test_user_with_password(conn, &username, &password)
    })
    .await
    .context("Failed to create test user with DEK")?;
    guard.add_user(user_in_db.id);


    let character_name = format!("CharacterToDelete_{}", Uuid::new_v4());
    let user_id_for_char = user_in_db.id;
    let character = run_db_op(&pool, {
        let character_name = character_name.clone();
        let dek_clone = dek.clone();
         move |conn| insert_test_character(conn, user_id_for_char, &character_name, &dek_clone)
    }).await.context("Failed to create test character with DEK")?;
    guard.add_character(character.id);


    tracing::info!(user_id = %user_in_db.id, character_id = %character.id, character_name = %character_name, "Test data created for direct DB delete test");

    // Perform direct DB deletion
    let db_pool_clone = pool.clone();
    let character_id_to_delete = character.id;
    let user_id_owner = user_in_db.id;

    let rows_affected = db_pool_clone
        .get()
        .await
        .context("Failed to get DB connection for delete operation")?
        .interact(move |conn| {
            use scribe_backend::schema::characters::dsl::*;
            diesel::delete(
                characters
                    .filter(id.eq(character_id_to_delete))
                    .filter(user_id.eq(user_id_owner)),
            )
            .execute(conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("InteractError during DB delete operation: {:?}", e))?
        .context("Diesel error during DB delete operation")?;

    assert_eq!(rows_affected, 1, "Expected 1 row to be affected by delete, found {}", rows_affected);
    tracing::info!(character_id = %character_id_to_delete, %rows_affected, "Character directly deleted from DB");
    
    let verify_pool_clone = pool.clone();
    let still_exists: bool = verify_pool_clone
        .get()
        .await
        .context("Failed to get DB conn for verify")?
        .interact(move |conn_block| {
            use scribe_backend::schema::characters::dsl::*;
            diesel::select(diesel::dsl::exists(
                characters.filter(id.eq(character_id_to_delete)),
            ))
            .get_result::<bool>(conn_block)
        })
        .await
        .map_err(|e| anyhow::anyhow!("InteractError during DB verification: {:?}", e))? 
        .context("Diesel error during DB verification")?;

    assert!(!still_exists, "Character was not deleted, it still exists in the DB.");
    
    Ok(())
}


#[tokio::test]
async fn test_delete_character_unauthenticated() -> Result<(), anyhow::Error> { // Renamed
    ensure_tracing_initialized();
    // Use reqwest::Client for this test as it's simpler for unauthenticated requests
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let client = Client::new();

    let character_id = Uuid::new_v4(); // Non-existent, but doesn't matter as auth fails first
    let delete_url = format!("{}/api/characters/remove/{}", test_app.address, character_id);

    let response = client.delete(&delete_url).send().await?;
    // Expecting 401 Unauthorized due to login_required
    assert_eq!(response.status(), ReqwestStatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn test_delete_character_not_found_when_authenticated() -> Result<(), anyhow::Error> { // Renamed
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    let username = format!("del_notfound_user_{}", Uuid::new_v4());
    let password = "testpassword";
    let (user, _dek) = run_db_op(&pool, {
        let username = username.clone();
        let password_clone = password.to_string();
        move |conn| insert_test_user_with_password(conn, &username, &password_clone)
    })
    .await?;
    guard.add_user(user.id);

    // Login
    let login_body = json!({ "identifier": username, "password": password });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login") // Relative path for router.oneshot()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_body)?))?;
    
    let app_router = test_app.router.clone(); // Clone router for oneshot
    let login_response = app_router.oneshot(login_request).await?;
    assert_eq!(login_response.status(), AxumStatusCode::OK, "Login failed");
    let session_cookie = login_response.headers().get(header::SET_COOKIE).unwrap().to_str()?.to_string();

    let non_existent_id = Uuid::new_v4();
    let delete_request = Request::builder()
        .method(Method::DELETE)
        .uri(format!("/api/characters/remove/{}", non_existent_id)) // Relative path
        .header(header::COOKIE, session_cookie)
        .body(Body::empty())?;
    
    let response = test_app.router.clone().oneshot(delete_request).await?;
    assert_eq!(response.status(), AxumStatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn test_delete_character_forbidden_for_another_user() -> Result<(), anyhow::Error> { // Renamed
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    // User A and their character
    let username_a = format!("del_forbidden_a_{}", Uuid::new_v4());
    let password_a = "passwordA";
    let (user_a, dek_a) = run_db_op(&pool, {
        let username_a = username_a.clone();
        let password_a = password_a.to_string();
        move |conn| insert_test_user_with_password(conn, &username_a, &password_a)
    }).await?;
    guard.add_user(user_a.id);

    let user_a_id_char = user_a.id;
    let dek_a_clone = dek_a.clone();
    let character_a = run_db_op(&pool, move |conn| {
        insert_test_character(conn, user_a_id_char, "CharA_DelForbidden", &dek_a_clone)
    }).await?;
    guard.add_character(character_a.id);

    // User B
    let username_b = format!("del_forbidden_b_{}", Uuid::new_v4());
    let password_b = "passwordB";
    let (user_b, _dek_b) = run_db_op(&pool, {
        let username_b = username_b.clone();
        let password_b = password_b.to_string();
        move |conn| insert_test_user_with_password(conn, &username_b, &password_b)
    }).await?;
    guard.add_user(user_b.id);

    // User B logs in
    let login_body_b = json!({ "identifier": username_b, "password": password_b });
    let login_request_b = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login") // Relative path
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_body_b)?))?;
    
    let app_router_b = test_app.router.clone(); // Clone router
    let login_response_b = app_router_b.oneshot(login_request_b).await?;
    assert_eq!(login_response_b.status(), AxumStatusCode::OK, "User B login failed");
    let session_cookie_b = login_response_b.headers().get(header::SET_COOKIE).unwrap().to_str()?.to_string();

    // User B tries to delete User A's character
    let delete_request_b = Request::builder()
        .method(Method::DELETE)
        .uri(format!("/api/characters/remove/{}", character_a.id)) // Relative path
        .header(header::COOKIE, session_cookie_b)
        .body(Body::empty())?;
    
    let response_b = test_app.router.clone().oneshot(delete_request_b).await?;
    // Expect 404 Not Found as User B does not own Character A, and the handler returns 404 if 0 rows affected by delete.
    assert_eq!(response_b.status(), AxumStatusCode::NOT_FOUND, "User B should get 404 Not Found for a character they don't own");

    // Verify Character A still exists
    let conn_verify = pool.get().await?;
    let char_a_id_verify = character_a.id;
    let still_exists: bool = conn_verify.interact(move |conn_block| {
        use scribe_backend::schema::characters::dsl::*;
        diesel::select(diesel::dsl::exists(characters.filter(id.eq(char_a_id_verify)))).get_result(conn_block)
    }).await
    .map_err(|e| anyhow::anyhow!("InteractError during DB operation: {:?}", e))?
    .context("Diesel error during DB operation")?;
    assert!(still_exists, "Character A should still exist after forbidden delete attempt");

    Ok(())
}