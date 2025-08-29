// backend/src/middleware/llm_security.rs
// Security middleware for LLM operations

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tracing::{debug, warn, error};
use uuid::Uuid;
use serde::Serialize;
use axum_login::AuthSession;
use crate::{
    auth::user_store::Backend as AuthBackend,
    state::AppState,
    errors::AppError,
};

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
    user_limits: Arc<RwLock<HashMap<Uuid, UserRateLimit>>>,
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
    pub fn check_rate_limit(&self, user_id: Uuid) -> Result<(), RateLimitError> {
        let now = Instant::now();
        
        // Cleanup old entries if needed
        self.cleanup_old_entries(now);
        
        let mut user_limits = self.user_limits.write().map_err(|_| RateLimitError::InternalError)?;
        
        let user_limit = user_limits.entry(user_id).or_insert_with(|| UserRateLimit {
            requests: Vec::new(),
            last_request: now,
        });
        
        // Remove requests older than 1 hour
        user_limit.requests.retain(|&timestamp| now.duration_since(timestamp) < Duration::from_secs(3600));
        
        // Check hourly limit
        if user_limit.requests.len() as u32 >= self.max_requests_per_hour {
            return Err(RateLimitError::HourlyLimitExceeded {
                limit: self.max_requests_per_hour,
                current: user_limit.requests.len() as u32,
            });
        }
        
        // Check per-minute limit (last 60 seconds)
        let minute_ago = now - Duration::from_secs(60);
        let recent_requests = user_limit.requests.iter()
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
        
        debug!("Rate limit check passed for user {}: {}/{} per minute, {}/{} per hour", 
               user_id, recent_requests + 1, self.max_requests_per_minute, 
               user_limit.requests.len(), self.max_requests_per_hour);
        
        Ok(())
    }
    
    /// Clean up old entries to prevent memory leaks
    fn cleanup_old_entries(&self, now: Instant) {
        if let Ok(mut last_cleanup) = self.last_cleanup.write() {
            if now.duration_since(*last_cleanup) > self.cleanup_interval {
                if let Ok(mut user_limits) = self.user_limits.write() {
                    let hour_ago = now - Duration::from_secs(3600);
                    user_limits.retain(|_, user_limit| {
                        user_limit.last_request > hour_ago
                    });
                    debug!("Cleaned up old rate limit entries, {} users remaining", user_limits.len());
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
            RateLimitError::MinuteLimitExceeded { .. } | RateLimitError::HourlyLimitExceeded { .. } => {
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
    auth_session: AuthSession<AuthBackend>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let start_time = Instant::now();
    
    // Extract user from session
    let user = match auth_session.user {
        Some(user) => user,
        None => {
            // Log unauthorized access
            #[cfg(feature = "local-llm")]
            if let Some(ref audit_logger) = app_state.security_audit_logger {
                let ip = extract_client_ip(&headers);
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
    debug!("LLM security middleware checking request for user: {}", user_id);
    
    // Check rate limits for LLM endpoints
    if is_llm_endpoint(request.uri().path()) {
        // TODO: Get rate limiter from app state once it's added
        let rate_limiter = LlmRateLimiter::new(10, 100); // 10/min, 100/hour - should be configurable
        
        if let Err(rate_limit_error) = rate_limiter.check_rate_limit(user_id) {
            warn!("Rate limit exceeded for user {}: {}", user_id, rate_limit_error);
            
            // Log rate limit exceeded
            #[cfg(feature = "local-llm")]
            if let Some(ref audit_logger) = app_state.security_audit_logger {
                match &rate_limit_error {
                    RateLimitError::MinuteLimitExceeded { limit, current } => {
                        audit_logger.log_rate_limit_exceeded(user_id, request.uri().path(), *limit, *current);
                    }
                    RateLimitError::HourlyLimitExceeded { limit, current } => {
                        audit_logger.log_rate_limit_exceeded(user_id, request.uri().path(), *limit, *current);
                    }
                    _ => {}
                }
            }
            
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }
    
    // Add security headers to request for downstream handlers
    request.headers_mut().insert("x-user-id", user_id.to_string().parse().unwrap());
    request.headers_mut().insert("x-security-checked", "true".parse().unwrap());
    
    // Process request
    let response = next.run(request).await;
    
    let processing_time = start_time.elapsed();
    debug!("LLM request processed for user {} in {:?}", user_id, processing_time);
    
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
    path == "/api/llm/stream"
}

/// Extract client IP from headers
fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    headers.get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .or_else(|| {
            headers.get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .map(String::from)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    
    #[test]
    fn test_rate_limiter() {
        let limiter = LlmRateLimiter::new(2, 5); // 2 per minute, 5 per hour
        let user_id = Uuid::new_v4();
        
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
        assert!(is_llm_endpoint("/api/llm/chat"));
        assert!(is_llm_endpoint("/api/llm/chat/stream"));
        assert!(is_llm_endpoint("/api/llm/generate"));
        assert!(!is_llm_endpoint("/api/auth/login"));
        assert!(!is_llm_endpoint("/api/characters"));
    }
}