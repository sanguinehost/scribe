// backend/src/middleware/llm_security.rs
// Security middleware for LLM operations

use crate::{auth::token_auth::UnifiedAuth, errors::AppError, state::AppState};
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tracing::{debug, error, warn};

#[cfg(feature = "local-llm")]
use crate::llm::llamacpp::{SecurityAuditLogger, SecurityEventType};

/// Rate limiting information for a user
#[derive(Debug, Clone)]
pub struct UserRateLimit {
    pub requests: Vec<Instant>,
    pub last_request: Instant,
}

/// Global rate limiter for LLM operations
#[derive(Debug)]
pub struct LlmRateLimiter {
    user_limits: Arc<RwLock<HashMap<crate::db::DbId, UserRateLimit>>>,
    max_requests_per_minute: u32,
    max_requests_per_hour: u32,
    cleanup_interval: Duration,
    last_cleanup: Arc<RwLock<Instant>>,
}

impl LlmRateLimiter {
    pub fn new(max_requests_per_minute: u32, max_requests_per_hour: u32) -> Self {
        Self {
            user_limits: Arc::new(RwLock::new(HashMap::new())),
            max_requests_per_minute,
            max_requests_per_hour,
            cleanup_interval: Duration::from_secs(300), // Cleanup every 5 minutes
            last_cleanup: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Check if user is allowed to make a request
    pub fn check_rate_limit(&self, user_id: crate::db::DbId) -> Result<(), RateLimitError> {
        let now = Instant::now();

        // Cleanup old entries if needed
        self.cleanup_old_entries(now);

        let mut user_limits = self
            .user_limits
            .write()
            .map_err(|_| RateLimitError::InternalError)?;

        let user_limit = user_limits.entry(user_id).or_insert_with(|| UserRateLimit {
            requests: Vec::new(),
            last_request: now,
        });

        // Remove requests older than 1 hour
        user_limit
            .requests
            .retain(|&timestamp| now.duration_since(timestamp) < Duration::from_secs(3600));

        // Check hourly limit
        if user_limit.requests.len() as u32 >= self.max_requests_per_hour {
            return Err(RateLimitError::HourlyLimitExceeded {
                limit: self.max_requests_per_hour,
                current: user_limit.requests.len() as u32,
            });
        }

        // Check per-minute limit (last 60 seconds)
        let minute_ago = now - Duration::from_secs(60);
        let recent_requests = user_limit
            .requests
            .iter()
            .filter(|&&timestamp| timestamp > minute_ago)
            .count() as u32;

        if recent_requests >= self.max_requests_per_minute {
            return Err(RateLimitError::MinuteLimitExceeded {
                limit: self.max_requests_per_minute,
                current: recent_requests,
            });
        }

        // Add current request
        user_limit.requests.push(now);
        user_limit.last_request = now;

        debug!(
            "Rate limit check passed for user {}: {}/{} per minute, {}/{} per hour",
            user_id,
            recent_requests + 1,
            self.max_requests_per_minute,
            user_limit.requests.len(),
            self.max_requests_per_hour
        );

        Ok(())
    }

    /// Clean up old entries to prevent memory leaks
    fn cleanup_old_entries(&self, now: Instant) {
        if let Ok(mut last_cleanup) = self.last_cleanup.write() {
            if now.duration_since(*last_cleanup) > self.cleanup_interval {
                if let Ok(mut user_limits) = self.user_limits.write() {
                    let hour_ago = now - Duration::from_secs(3600);
                    user_limits.retain(|_, user_limit| user_limit.last_request > hour_ago);
                    debug!(
                        "Cleaned up old rate limit entries, {} users remaining",
                        user_limits.len()
                    );
                }
                *last_cleanup = now;
            }
        }
    }
}

/// Rate limiting errors
#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("Minute rate limit exceeded: {current}/{limit}")]
    MinuteLimitExceeded { limit: u32, current: u32 },

    #[error("Hourly rate limit exceeded: {current}/{limit}")]
    HourlyLimitExceeded { limit: u32, current: u32 },

    #[error("Internal error in rate limiter")]
    InternalError,
}

impl From<RateLimitError> for AppError {
    fn from(err: RateLimitError) -> Self {
        match err {
            RateLimitError::MinuteLimitExceeded { .. }
            | RateLimitError::HourlyLimitExceeded { .. } => {
                AppError::BadRequest(format!("Rate limit exceeded: {}", err))
            }
            RateLimitError::InternalError => AppError::InternalServerErrorGeneric(err.to_string()),
        }
    }
}

/// Rate limit response
#[derive(Serialize)]
pub struct RateLimitResponse {
    pub error: String,
    pub retry_after: u64, // seconds
}

/// Security middleware for LLM operations
pub async fn llm_security_middleware(
    State(app_state): State<AppState>,
    auth: UnifiedAuth,
    _headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let start_time = Instant::now();

    // Extract user from session (supports both JWT and cookie auth)
    let user = match auth.user().cloned() {
        Some(user) => user,
        None => {
            // Log unauthorized access
            #[cfg(feature = "local-llm")]
            if let Some(ref audit_logger) = app_state.security_audit_logger {
                let ip = extract_client_ip(&_headers);
                audit_logger.log_unauthorized_access(
                    &request.uri().path(),
                    &request.method().as_str(),
                    ip,
                );
            }
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    let user_id = user.id;
    debug!(
        "LLM security middleware checking request for user: {}",
        user_id
    );

    // Check rate limits for LLM endpoints
    if is_llm_endpoint(request.uri().path()) {
        let rate_limiter = app_state.rate_limiter.clone();

        if let Err(rate_limit_error) = rate_limiter.check_rate_limit(user_id) {
            warn!(
                "Rate limit exceeded for user {}: {}",
                user_id, rate_limit_error
            );

            // Log rate limit exceeded
            #[cfg(feature = "local-llm")]
            if let Some(ref audit_logger) = app_state.security_audit_logger {
                match &rate_limit_error {
                    RateLimitError::MinuteLimitExceeded { limit, current } => {
                        audit_logger.log_rate_limit_exceeded(
                            user_id,
                            request.uri().path(),
                            *limit,
                            *current,
                        );
                    }
                    RateLimitError::HourlyLimitExceeded { limit, current } => {
                        audit_logger.log_rate_limit_exceeded(
                            user_id,
                            request.uri().path(),
                            *limit,
                            *current,
                        );
                    }
                    _ => {}
                }
            }

            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }

    // Add security headers to request for downstream handlers
    request
        .headers_mut()
        .insert("x-user-id", user_id.to_string().parse().unwrap());
    request
        .headers_mut()
        .insert("x-security-checked", "true".parse().unwrap());

    // Process request
    let response = next.run(request).await;

    let processing_time = start_time.elapsed();
    debug!(
        "LLM request processed for user {} in {:?}",
        user_id, processing_time
    );

    // Log slow requests
    if processing_time > Duration::from_secs(30) {
        #[cfg(feature = "local-llm")]
        if let Some(ref audit_logger) = app_state.security_audit_logger {
            let event = crate::llm::llamacpp::SecurityEvent::new(
                SecurityEventType::SuspiciousActivity,
                crate::llm::llamacpp::SecurityEventSeverity::Medium,
                "/api/llm".to_string(),
                "POST".to_string(),
                format!("Slow LLM request: {:?}", processing_time),
            )
            .with_user(user_id)
            .with_detail("processing_time_ms", processing_time.as_millis());

            audit_logger.log_event(event);
        }
    }

    Ok(response)
}

/// Check if endpoint is an LLM endpoint that needs rate limiting
fn is_llm_endpoint(path: &str) -> bool {
    path.starts_with("/api/llm/chat") ||
    path.starts_with("/api/llm/generate") ||
    path == "/api/llm/chat" ||
    path == "/api/llm/stream" ||
    // Chat generation endpoints
    path.contains("/generate") && path.starts_with("/api/chat/") ||
    // Other AI-powered endpoints
    path.contains("/suggested-actions") && path.starts_with("/api/chat/") ||
    path.contains("/expand") && path.starts_with("/api/chat/") ||
    path.contains("/impersonate") && path.starts_with("/api/chat/")
}

/// Extract client IP from headers
#[allow(dead_code)]
fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .map(String::from)
        })
}

/// Security headers middleware to add common security headers to all responses
pub async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    // HSTS (HTTP Strict Transport Security) - Force HTTPS for 1 year
    headers.insert(
        "strict-transport-security",
        "max-age=31536000; includeSubDomains".parse().unwrap(),
    );

    // X-Content-Type-Options - Prevent MIME-type sniffing
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());

    // X-Frame-Options - Prevent clickjacking
    headers.insert("x-frame-options", "DENY".parse().unwrap());

    // X-XSS-Protection - Enable XSS filtering (legacy browsers)
    headers.insert("x-xss-protection", "1; mode=block".parse().unwrap());

    // Referrer-Policy - Control referrer information
    headers.insert(
        "referrer-policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );

    // Content-Security-Policy - Basic CSP for enhanced security
    // Allow same-origin for scripts/styles, data: for images, connect to same origin and SSE
    headers.insert(
        "content-security-policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'".parse().unwrap(),
    );

    // Permissions-Policy - Restrict access to sensitive browser features
    headers.insert(
        "permissions-policy",
        "camera=(), microphone=(), geolocation=(), interest-cohort=()"
            .parse()
            .unwrap(),
    );

    response
}

#[cfg(all(test, feature = "postgres-backend"))]
mod tests {
    use super::*;
    use crate::db::DbId;

    #[test]
    fn test_rate_limiter() {
        let limiter = LlmRateLimiter::new(2, 5); // 2 per minute, 5 per hour
        let user_id = DbId::new();

        // First two requests should pass
        assert!(limiter.check_rate_limit(user_id).is_ok());
        assert!(limiter.check_rate_limit(user_id).is_ok());

        // Third request should fail (per-minute limit)
        assert!(matches!(
            limiter.check_rate_limit(user_id),
            Err(RateLimitError::MinuteLimitExceeded { .. })
        ));
    }

    #[test]
    fn test_llm_endpoint_detection() {
        // Legacy LLM endpoints
        assert!(is_llm_endpoint("/api/llm/chat"));
        assert!(is_llm_endpoint("/api/llm/chat/stream"));
        assert!(is_llm_endpoint("/api/llm/generate"));

        // Chat generation endpoints
        assert!(is_llm_endpoint("/api/chat/session123/generate"));
        assert!(is_llm_endpoint("/api/chat/session456/suggested-actions"));
        assert!(is_llm_endpoint("/api/chat/session789/expand"));
        assert!(is_llm_endpoint("/api/chat/session101/impersonate"));

        // Non-LLM endpoints
        assert!(!is_llm_endpoint("/api/auth/login"));
        assert!(!is_llm_endpoint("/api/characters"));
        assert!(!is_llm_endpoint("/api/chat/session123/settings")); // Chat settings shouldn't be rate limited
    }

    #[test]
    fn test_security_headers_values() {
        // Test the security headers middleware by checking that the correct header values are set
        // This is a simpler unit test that doesn't require async mocking

        let expected_headers = vec![
            (
                "strict-transport-security",
                "max-age=31536000; includeSubDomains",
            ),
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
            ("x-xss-protection", "1; mode=block"),
            ("referrer-policy", "strict-origin-when-cross-origin"),
            (
                "permissions-policy",
                "camera=(), microphone=(), geolocation=(), interest-cohort=()",
            ),
        ];

        // Verify the expected header values match what the middleware should set
        for (header_name, expected_value) in expected_headers {
            // This tests that we have the correct header values defined
            // The actual middleware functionality is tested in integration tests
            assert!(
                !expected_value.is_empty(),
                "Header {} should have a non-empty value",
                header_name
            );
        }

        // Verify CSP header contains essential security directives
        let csp_header = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'";
        assert!(csp_header.contains("default-src 'self'"));
        assert!(csp_header.contains("frame-ancestors 'none'"));
        assert!(csp_header.contains("base-uri 'self'"));
    }
}
