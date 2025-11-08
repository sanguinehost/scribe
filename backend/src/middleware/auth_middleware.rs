// backend/src/middleware/auth_middleware.rs
// Authentication middleware that supports both JWT (desktop) and cookie (web) authentication

use axum::{
    extract::{FromRequestParts, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use tracing::{debug, info};

use crate::auth::token_auth::UnifiedAuth;
use crate::state::AppState;

/// Middleware that requires authentication via UnifiedAuth (supports both JWT and cookies)
/// This replaces axum_login's login_required! which only supports cookies
pub async fn unified_login_required(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    // Extract UnifiedAuth from the request
    let (mut parts, body) = request.into_parts();

    // Extract UnifiedAuth using the FromRequestParts trait
    let auth = match UnifiedAuth::from_request_parts(&mut parts, &state).await {
        Ok(auth) => auth,
        Err(response) => {
            debug!("unified_login_required: Failed to extract UnifiedAuth");
            return Err(response);
        }
    };

    // Check if user is authenticated
    if !auth.is_authenticated() {
        info!("unified_login_required: No authenticated user found - returning 401");
        return Err((StatusCode::UNAUTHORIZED, "Authentication required").into_response());
    }

    let auth_type = if auth.is_token_auth { "JWT" } else { "cookie" };
    if let Some(user) = auth.user() {
        debug!(
            user_id = %user.id,
            username = %user.username,
            auth_type = auth_type,
            "unified_login_required: User authenticated successfully"
        );
    }

    // Reconstruct the request and continue
    let request = Request::from_parts(parts, body);
    Ok(next.run(request).await)
}
