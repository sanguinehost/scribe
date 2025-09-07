use crate::auth::session_dek::SessionDek;
use crate::auth::user_store::Backend as AuthBackend;
use crate::errors::AppError;
use crate::middleware::{template_rate_limit_middleware, rate_limit_logger, security_headers};
use crate::prompt_templates::{TemplateInfo, TEMPLATE_MANAGER};
use axum::{
    extract::Path,
    middleware,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use axum_login::AuthSession;
use regex::Regex;
use serde::Serialize;
use std::sync::LazyLock;
use tracing::{info, warn};

/// Shorthand for auth session
type CurrentAuthSession = AuthSession<AuthBackend>;

/// Regex for validating template IDs - alphanumeric and underscore only
static TEMPLATE_ID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9_]+$").expect("Failed to compile template ID regex")
});

/// Response for template listing
#[derive(Debug, Serialize)]
pub struct TemplateListResponse {
    pub templates: Vec<TemplateInfo>,
}

/// Validates a template ID to prevent injection attacks
fn validate_template_id(template_id: &str) -> Result<(), AppError> {
    if template_id.is_empty() {
        return Err(AppError::BadRequest("Template ID cannot be empty".to_string()));
    }
    
    if template_id.len() > 50 {
        return Err(AppError::BadRequest("Template ID too long (max 50 characters)".to_string()));
    }
    
    if !TEMPLATE_ID_REGEX.is_match(template_id) {
        return Err(AppError::BadRequest(
            "Template ID must contain only alphanumeric characters and underscores".to_string()
        ));
    }
    
    Ok(())
}

/// Lists all available prompt templates
/// 
/// # Security
/// - Requires authentication
/// - Returns only template metadata, not content
/// - Rate limited (handled by middleware)
pub async fn list_templates_handler(
    auth_session: CurrentAuthSession,
    _dek: SessionDek, // Require authentication but don't need DEK
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    
    info!(user_id = %user.id, "Listing available templates");
    
    let templates = TEMPLATE_MANAGER.list_templates();
    
    Ok(Json(TemplateListResponse { templates }))
}

/// Gets information for a specific template
/// 
/// # Security
/// - Requires authentication
/// - Validates template_id format to prevent path traversal
/// - Returns 404 for non-existent templates
pub async fn get_template_info_handler(
    auth_session: CurrentAuthSession,
    _dek: SessionDek, // Require authentication but don't need DEK
    Path(template_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;
    
    // Validate template ID format for security
    validate_template_id(&template_id)?;
    
    info!(user_id = %user.id, template_id = %template_id, "Getting template info");
    
    match TEMPLATE_MANAGER.get_template_info(&template_id) {
        Some(info) => Ok(Json(info)),
        None => {
            warn!(template_id = %template_id, "Template not found");
            Err(AppError::NotFound(format!("Template '{}' not found", template_id)))
        }
    }
}

/// Creates the router for template-related endpoints with security hardening
/// 
/// Security measures applied:
/// - Rate limiting: 30 requests/minute with burst of 5
/// - Request logging with IP tracking
/// - Security headers (CSP, HSTS, etc.)
/// - Input validation in handlers
/// - Authentication required
pub fn create_router() -> Router<crate::state::AppState> {
    Router::new()
        .route("/", get(list_templates_handler))
        .route("/:template_id", get(get_template_info_handler))
        // Apply security hardening middleware
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn(rate_limit_logger))
        .layer(middleware::from_fn(template_rate_limit_middleware))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_template_id_valid() {
        assert!(validate_template_id("neutral_roleplay").is_ok());
        assert!(validate_template_id("chatbot_dialogue").is_ok());
        assert!(validate_template_id("test123").is_ok());
        assert!(validate_template_id("a").is_ok());
    }

    #[test]
    fn test_validate_template_id_invalid() {
        // Empty string
        assert!(validate_template_id("").is_err());
        
        // Too long
        let long_id = "a".repeat(51);
        assert!(validate_template_id(&long_id).is_err());
        
        // Invalid characters
        assert!(validate_template_id("template-name").is_err()); // dash
        assert!(validate_template_id("template.name").is_err()); // dot
        assert!(validate_template_id("template name").is_err()); // space
        assert!(validate_template_id("template/name").is_err()); // slash
        assert!(validate_template_id("../template").is_err()); // path traversal
        assert!(validate_template_id("template;DROP TABLE").is_err()); // SQL injection attempt
    }

    #[test]
    fn test_template_id_regex() {
        assert!(TEMPLATE_ID_REGEX.is_match("valid_template123"));
        assert!(!TEMPLATE_ID_REGEX.is_match("invalid-template"));
        assert!(!TEMPLATE_ID_REGEX.is_match("invalid.template"));
        assert!(!TEMPLATE_ID_REGEX.is_match("invalid template"));
    }
}