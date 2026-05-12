use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use axum_login::AuthSession;
use tracing::Span;

use crate::auth::AuthBackend;
use crate::privacy::logging::loggable_user_id;

/// Middleware to capture the authenticated User ID and attach it to the current tracing span
/// in a privacy-safe (obfuscated) format.
#[derive(Clone, Debug)]
pub struct PrivacySafeUserId(pub String);

pub async fn capture_user_id_middleware(
    auth_session: AuthSession<AuthBackend>,
    request: Request,
    next: Next,
) -> Response {
    let mut safe_user_id_str = None;

    // Check if a user is authenticated in the session
    if let Some(user) = auth_session.user {
        // Obfuscate the user ID using our privacy module
        let safe_user_id = loggable_user_id(user.id);

        // Record the user ID to the current tracing span for OTLP
        Span::current().record("user_id", safe_user_id.to_string());

        safe_user_id_str = Some(safe_user_id.to_string());
    }

    // Continue the request chain
    let mut response = next.run(request).await;

    // Attach user_id to response extensions for the main logger
    if let Some(uid) = safe_user_id_str {
        response.extensions_mut().insert(PrivacySafeUserId(uid));
    }

    response
}
