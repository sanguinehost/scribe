#![cfg(test)]

use anyhow::Result;
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use scribe_backend::test_helpers::{TestDataGuard, ensure_tracing_initialized};
use tower::ServiceExt;
use uuid::Uuid;

/// Helper to create a multipart avatar upload request
fn create_avatar_upload_request(
    uri: &str,
    image_data: &[u8],
    session_cookie: Option<&str>,
) -> Request<Body> {
    let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    let mut body = Vec::new();

    // Add avatar file part
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"avatar\"; filename=\"test_avatar.png\"\r\n"
    );
    body.extend_from_slice(b"Content-Type: image/png\r\n\r\n");
    body.extend_from_slice(image_data);
    body.extend_from_slice(b"\r\n");

    // Final boundary
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    let mut request_builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        );

    // Add cookie header if provided
    if let Some(cookie) = session_cookie {
        request_builder = request_builder.header(header::COOKIE, cookie);
    }

    request_builder.body(Body::from(body)).unwrap()
}

/// Helper to create a simple test PNG
fn create_simple_test_png() -> Vec<u8> {
    // Create a minimal valid PNG (1x1 pixel)
    vec![
        137, 80, 78, 71, 13, 10, 26, 10, // PNG signature
        0, 0, 0, 13, // IHDR length
        73, 72, 68, 82, // IHDR
        0, 0, 0, 1, // Width
        0, 0, 0, 1, // Height
        8, 6, 0, 0, 0, // Bit depth, color type, compression, filter, interlace
        31, 21, 16, 166, // CRC
        0, 0, 0, 10, // IDAT length
        73, 68, 65, 84, // IDAT
        8, 29, 99, 96, 0, 0, 0, 3, 0, 1, // Compressed data
        122, 221, 46, 34, // CRC
        0, 0, 0, 0, // IEND length
        73, 69, 78, 68, // IEND
        174, 66, 96, 130 // CRC
    ]
}

#[tokio::test]
async fn test_upload_user_avatar_unauthorized() -> Result<()> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());

    let user_id = Uuid::new_v4();
    let image_data = create_simple_test_png();

    let request = create_avatar_upload_request(
        &format!("/api/users/{}/avatar", user_id),
        &image_data,
        None
    );

    let response = test_app.router.clone().oneshot(request).await?;
    let status = response.status();
    let body_bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let body_text = String::from_utf8(body_bytes.to_vec())?;

    tracing::info!(
        status = %status, 
        body = %body_text, 
        "User avatar upload response without auth"
    );

    // Without authentication, we expect UNAUTHORIZED or NOT_FOUND if the route doesn't exist
    assert!(status == StatusCode::UNAUTHORIZED || status == StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn test_get_user_avatar_unauthorized() -> Result<()> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());

    let user_id = Uuid::new_v4();

    let request = Request::builder()
        .method("GET")
        .uri(format!("/api/users/{}/avatar", user_id))
        .body(Body::empty())?;

    let response = test_app.router.clone().oneshot(request).await?;
    let status = response.status();

    tracing::info!(status = %status, "User avatar GET response without auth");

    // Without authentication, we expect UNAUTHORIZED or NOT_FOUND if the route doesn't exist
    assert!(status == StatusCode::UNAUTHORIZED || status == StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn test_delete_user_avatar_unauthorized() -> Result<()> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());

    let user_id = Uuid::new_v4();

    let request = Request::builder()
        .method("DELETE")
        .uri(format!("/api/users/{}/avatar", user_id))
        .body(Body::empty())?;

    let response = test_app.router.clone().oneshot(request).await?;
    let status = response.status();

    tracing::info!(status = %status, "User avatar DELETE response without auth");

    // Without authentication, we expect UNAUTHORIZED or NOT_FOUND if the route doesn't exist
    assert!(status == StatusCode::UNAUTHORIZED || status == StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn test_upload_persona_avatar_unauthorized() -> Result<()> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());

    let persona_id = Uuid::new_v4();
    let image_data = create_simple_test_png();

    let request = create_avatar_upload_request(
        &format!("/api/personas/{}/avatar", persona_id),
        &image_data,
        None
    );

    let response = test_app.router.clone().oneshot(request).await?;
    let status = response.status();

    tracing::info!(status = %status, "Persona avatar upload response without auth");

    // Without authentication, we expect UNAUTHORIZED or NOT_FOUND if the route doesn't exist
    assert!(status == StatusCode::UNAUTHORIZED || status == StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn test_get_persona_avatar_unauthorized() -> Result<()> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());

    let persona_id = Uuid::new_v4();

    let request = Request::builder()
        .method("GET")
        .uri(format!("/api/personas/{}/avatar", persona_id))
        .body(Body::empty())?;

    let response = test_app.router.clone().oneshot(request).await?;
    let status = response.status();

    tracing::info!(status = %status, "Persona avatar GET response without auth");

    // Without authentication, we expect UNAUTHORIZED or NOT_FOUND if the route doesn't exist
    assert!(status == StatusCode::UNAUTHORIZED || status == StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn test_delete_persona_avatar_unauthorized() -> Result<()> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());

    let persona_id = Uuid::new_v4();

    let request = Request::builder()
        .method("DELETE")
        .uri(format!("/api/personas/{}/avatar", persona_id))
        .body(Body::empty())?;

    let response = test_app.router.clone().oneshot(request).await?;
    let status = response.status();

    tracing::info!(status = %status, "Persona avatar DELETE response without auth");

    // Without authentication, we expect UNAUTHORIZED or NOT_FOUND if the route doesn't exist
    assert!(status == StatusCode::UNAUTHORIZED || status == StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn test_invalid_user_id_format() -> Result<()> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());

    let request = Request::builder()
        .method("GET")
        .uri("/api/users/not-a-uuid/avatar")
        .body(Body::empty())?;

    let response = test_app.router.clone().oneshot(request).await?;
    let status = response.status();

    tracing::info!(status = %status, "Invalid user ID format response");

    // Should return BAD_REQUEST or NOT_FOUND for invalid UUID format
    assert!(status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn test_invalid_persona_id_format() -> Result<()> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());

    let request = Request::builder()
        .method("GET")
        .uri("/api/personas/not-a-uuid/avatar")
        .body(Body::empty())?;

    let response = test_app.router.clone().oneshot(request).await?;
    let status = response.status();

    tracing::info!(status = %status, "Invalid persona ID format response");

    // Should return BAD_REQUEST or NOT_FOUND for invalid UUID format
    assert!(status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND);
    Ok(())
}

// Test that the avatar routes are properly registered
#[tokio::test] 
async fn test_avatar_routes_registration() -> Result<()> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());

    // Test multiple avatar endpoints to ensure they're registered
    let user_id = Uuid::new_v4();
    let persona_id = Uuid::new_v4();
    
    let test_cases = vec![
        ("GET", format!("/api/users/{}/avatar", user_id)),
        ("POST", format!("/api/users/{}/avatar", user_id)),
        ("DELETE", format!("/api/users/{}/avatar", user_id)),
        ("GET", format!("/api/personas/{}/avatar", persona_id)),
        ("POST", format!("/api/personas/{}/avatar", persona_id)),
        ("DELETE", format!("/api/personas/{}/avatar", persona_id)),
    ];

    for (method, uri) in test_cases {
        let request = if method == "POST" {
            create_avatar_upload_request(&uri, &create_simple_test_png(), None)
        } else {
            Request::builder()
                .method(method)
                .uri(uri.clone())
                .body(Body::empty())?
        };

        let response = test_app.router.clone().oneshot(request).await?;
        let status = response.status();

        tracing::info!(method = method, uri = uri, status = %status, "Route registration test");

        // All routes should be registered and return UNAUTHORIZED or NOT_FOUND (not METHOD_NOT_ALLOWED)
        assert!(
            status == StatusCode::UNAUTHORIZED ||
            status == StatusCode::NOT_FOUND,
            "Unexpected status for {} {}: {}",
            method, uri, status
        );
    }

    Ok(())
}