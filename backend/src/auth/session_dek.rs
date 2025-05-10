use secrecy::{ExposeSecret, SecretBox};
use axum::Extension;
use axum::{
    extract::FromRequestParts,
    // extract::TypedHeader, // Not strictly needed for this extractor if Session is used directly
    // headers::Cookie, // Not strictly needed
    http::request::Parts,
    RequestPartsExt,
};
use tower_sessions::Session;
use crate::errors::AppError;
use base64::Engine as _;
use tracing::{debug, error}; // Added warn
use async_trait::async_trait;
use std::fmt; // ADDED FOR MANUAL DEBUG IMPL

pub const SESSION_DEK_KEY: &str = "session_dek";

/// Represents the session's Data Encryption Key (DEK).
/// This struct is intended to be used as an Axum request extractor.
pub struct SessionDek(pub SecretBox<Vec<u8>>);

// MANUAL IMPLEMENTATION OF DEBUG
impl fmt::Debug for SessionDek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SessionDek").field(&"<REDACTED>").finish()
    }
}

// MANUAL IMPLEMENTATION OF CLONE
impl Clone for SessionDek {
    fn clone(&self) -> Self {
        let exposed_inner_vector: &Vec<u8> = self.0.expose_secret();
        let cloned_vector: Vec<u8> = exposed_inner_vector.clone();
        SessionDek(SecretBox::new(Box::new(cloned_vector)))
    }
}

impl SessionDek {
    /// Exposes the inner DEK bytes. Use with extreme caution.
    pub fn expose_dek(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

#[async_trait]
impl<'a, S> FromRequestParts<S> for SessionDek
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let session_extension = parts.extract::<Extension<Session>>()
            .await
            .map_err(|err| {
                error!("Failed to extract session: {}", err.to_string());
                AppError::SessionError("Failed to extract session".to_string())
            })?;

        // Attempt to retrieve the DEK from the session.
        match session_extension.get::<String>(SESSION_DEK_KEY).await {
            Ok(Some(dek_base64)) => {
                debug!("Successfully retrieved DEK from session.");
                // Decode the base64 string back into bytes.
                let dek_bytes = base64::engine::general_purpose::STANDARD.decode(&dek_base64)
                    .map_err(|e| {
                        error!(error = ?e, "Failed to base64 decode DEK from session. Value was: '{}'", dek_base64);
                        // This indicates corruption or an invalid format if the key exists but is not valid base64.
                        AppError::InternalServerErrorGeneric("Corrupted DEK in session".to_string())
                    })?;
                Ok(SessionDek(SecretBox::new(Box::new(dek_bytes))))
            }
            Ok(None) => {
                debug!("Session DEK ('{}') not found in session.", SESSION_DEK_KEY);
                // If the DEK is not found, it's a form of "Not Found" or "Unauthorized" depending on context.
                // For a direct `SessionDek` extractor, this means the required data is missing.
                Err(AppError::Unauthorized(
                    "Session DEK not available. User may not be logged in or DEK was not set.".to_string(),
                ))
            }
            Err(e) => {
                // This error occurs if there's an issue with the session backend itself (e.g., deserialization error from store).
                error!(error = ?e, "Error retrieving DEK string from session store via session.get()");
                Err(AppError::InternalServerErrorGeneric(
                    "Failed to read DEK from session store".to_string(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
use http::StatusCode;
    use axum::extract::Request;
    use http::Request as HttpRequest;
    use tower_sessions::{MemoryStore, SessionManagerLayer};
    use secrecy::SecretString;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt; // for `oneshot`

    // Helper to create a request with a session
    async fn request_with_session_dek(dek_value: Option<&str>) -> Request {
        let session_store = MemoryStore::default();
        let session_manager = SessionManagerLayer::new(session_store)
            .with_secure(false); // For testing ease

        let mut req = HttpRequest::builder().uri("/test_dek").body(axum::body::Body::empty()).unwrap();
        
        // Create a session and insert the DEK if provided
        let mut session = Session::new(None, std::sync::Arc::new(MemoryStore::default()), None); // Added None for expiry
        if let Some(val) = dek_value {
            session.insert(SESSION_DEK_KEY, val.to_string()).await.expect("Failed to insert DEK into test session"); // Added .await
        }
        
        // Apply session to request extensions (simulating middleware)
        // This is a bit simplified; real middleware would handle cookie setting etc.
        // For extractor testing, we need the Session in extensions.
        req.extensions_mut().insert(session);


        Request::from_parts(req.into_parts().0, axum::body::Body::empty()) // Reconstruct axum::extract::Request
    }
    
    #[axum::debug_handler]
    async fn test_handler_direct(dek: SessionDek) -> StatusCode {
        if dek.expose_dek() == b"test_dek_bytes" {
            StatusCode::OK
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }

    #[axum::debug_handler]
    async fn test_handler_option(dek: Option<SessionDek>) -> StatusCode {
        match dek {
            Some(d) if d.expose_dek() == b"test_dek_bytes" => StatusCode::OK,
            None => StatusCode::NO_CONTENT, // Expected if DEK is not set
            _ => StatusCode::INTERNAL_SERVER_ERROR, // Unexpected DEK value
        }
    }
    
    // Note: These tests are challenging to set up perfectly without a full app context
    // or more direct control over how Session is populated by tower-sessions middleware.
    // The `request_with_session_dek` helper tries to simulate this.

    #[tokio::test]
    async fn extracts_session_dek_when_present() {
        let dek_bytes = b"test_dek_bytes";
        let dek_base64 = base64::engine::general_purpose::STANDARD.encode(dek_bytes);

        let app = Router::new().route("/test_dek", get(test_handler_direct))
            .layer(
                SessionManagerLayer::new(MemoryStore::default()).with_secure(false)
            );

        let mut request = HttpRequest::builder().uri("/test_dek").body(axum::body::Body::empty()).unwrap();
        let session = Session::new(None, std::sync::Arc::new(MemoryStore::default()), None); // Added None for expiry
        session.insert(SESSION_DEK_KEY, dek_base64).await.unwrap(); // Added .await
        request.extensions_mut().insert(session); // Manually insert session for test

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rejects_when_session_dek_not_present_direct() {
        // For SessionDek (direct), not finding the key is a rejection.
        let app = Router::new().route("/test_dek", get(test_handler_direct))
            .layer(
                SessionManagerLayer::new(MemoryStore::default()).with_secure(false)
            );
        
        let mut request = HttpRequest::builder().uri("/test_dek").body(axum::body::Body::empty()).unwrap();
        let session = Session::new(None, std::sync::Arc::new(MemoryStore::default()), None); // Added None for expiry
        // No DEK inserted
        request.extensions_mut().insert(session);

        let response = app.oneshot(request).await.unwrap();
        // The rejection is AppError::Unauthorized, which typically maps to 401/403.
        // Here we check if the handler was even called (it shouldn't be if rejection happens).
        // The default response for AppError::Unauthorized is 401.
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn extracts_option_session_dek_as_some_when_present() {
        let dek_bytes = b"test_dek_bytes";
        let dek_base64 = base64::engine::general_purpose::STANDARD.encode(dek_bytes);

        let app = Router::new().route("/test_dek_opt", get(test_handler_option))
            .layer(
                SessionManagerLayer::new(MemoryStore::default()).with_secure(false)
            );

        let mut request = HttpRequest::builder().uri("/test_dek_opt").body(axum::body::Body::empty()).unwrap();
        let session = Session::new(None, std::sync::Arc::new(MemoryStore::default()), None); // Added None for expiry
        session.insert(SESSION_DEK_KEY, dek_base64).await.unwrap(); // Added .await
        request.extensions_mut().insert(session);

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn extracts_option_session_dek_as_none_when_not_present() {
        let app = Router::new().route("/test_dek_opt", get(test_handler_option))
            .layer(
                SessionManagerLayer::new(MemoryStore::default()).with_secure(false)
            );

        let mut request = HttpRequest::builder().uri("/test_dek_opt").body(axum::body::Body::empty()).unwrap();
        let session = Session::new(None, std::sync::Arc::new(MemoryStore::default()), None); // Added None for expiry
        // No DEK inserted
        request.extensions_mut().insert(session);

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT); // Handler should return this for None
    }

    #[tokio::test]
    async fn rejects_when_dek_is_corrupted_direct() {
        let app = Router::new().route("/test_dek", get(test_handler_direct))
            .layer(
                SessionManagerLayer::new(MemoryStore::default()).with_secure(false)
            );

        let mut request = HttpRequest::builder().uri("/test_dek").body(axum::body::Body::empty()).unwrap();
        let session = Session::new(None, std::sync::Arc::new(MemoryStore::default()), None); // Added None for expiry
        session.insert(SESSION_DEK_KEY, "this is not valid base64!!!".to_string()).await.unwrap(); // Added .await
        request.extensions_mut().insert(session);
        
        let response = app.oneshot(request).await.unwrap();
        // AppError::InternalServerErrorGeneric("Corrupted DEK in session") maps to 500
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn rejects_when_dek_is_corrupted_option() {
        // Even for Option<SessionDek>, a corrupted DEK (if present) is an error, not Ok(None)
        let app = Router::new().route("/test_dek_opt", get(test_handler_option))
            .layer(
                SessionManagerLayer::new(MemoryStore::default()).with_secure(false)
            );

        let mut request = HttpRequest::builder().uri("/test_dek_opt").body(axum::body::Body::empty()).unwrap();
        let session = Session::new(None, std::sync::Arc::new(MemoryStore::default()), None); // Added None for expiry
        session.insert(SESSION_DEK_KEY, "this is not valid base64!!!".to_string()).await.unwrap(); // Added .await
        request.extensions_mut().insert(session);
        
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}