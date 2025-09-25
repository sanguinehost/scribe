use crate::errors::AppError;
use axum::{extract::Request, middleware::Next, response::Response};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Simple in-memory rate limiter for template endpoints
///
/// This implements a basic rate limiter that's simpler than tower_governor
/// but provides the security we need for template endpoints.
#[derive(Debug, Clone)]
pub struct SimpleRateLimiter {
    requests: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    max_requests: usize,
    window_duration: Duration,
}

impl SimpleRateLimiter {
    pub fn new(max_requests: usize, window_duration: Duration) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window_duration,
        }
    }

    pub fn is_allowed(&self, client_id: &str) -> bool {
        let mut requests = self.requests.lock().unwrap();
        let now = Instant::now();

        // Clean old entries
        let cutoff = now - self.window_duration;

        // Get or create entry for this client
        let client_requests = requests
            .entry(client_id.to_string())
            .or_insert_with(Vec::new);

        // Remove old requests
        client_requests.retain(|&time| time > cutoff);

        // Check if we're under the limit
        if client_requests.len() < self.max_requests {
            client_requests.push(now);
            true
        } else {
            false
        }
    }
}

/// Rate limiter for template endpoints (restrictive)
pub fn create_template_rate_limiter() -> SimpleRateLimiter {
    SimpleRateLimiter::new(30, Duration::from_secs(60)) // 30 requests per minute
}

/// Rate limiter for credit purchase endpoints (very restrictive)
pub fn create_credit_purchase_rate_limiter() -> SimpleRateLimiter {
    SimpleRateLimiter::new(5, Duration::from_secs(3600)) // 5 purchases per hour
}

/// Rate limiter for subscription management endpoints (restrictive)
pub fn create_subscription_rate_limiter() -> SimpleRateLimiter {
    SimpleRateLimiter::new(3, Duration::from_secs(3600)) // 3 operations per hour
}

/// Rate limiter for webhook endpoints (allow more for reliability)
pub fn create_webhook_rate_limiter() -> SimpleRateLimiter {
    SimpleRateLimiter::new(100, Duration::from_secs(60)) // 100 webhooks per minute
}

/// Rate limiter middleware for template endpoints
pub async fn template_rate_limit_middleware(request: Request, next: Next) -> Response {
    // Create a static rate limiter instance
    static RATE_LIMITER: std::sync::OnceLock<SimpleRateLimiter> = std::sync::OnceLock::new();
    let limiter = RATE_LIMITER.get_or_init(|| create_template_rate_limiter());

    // Extract client identifier
    let client_ip = if let Some(forwarded) = request.headers().get("x-forwarded-for") {
        forwarded.to_str().unwrap_or("unknown").to_string()
    } else if let Some(socket_addr) = request.extensions().get::<SocketAddr>() {
        socket_addr.ip().to_string()
    } else {
        "unknown".to_string()
    };

    // Check rate limit
    if !limiter.is_allowed(&client_ip) {
        warn!(client_ip = %client_ip, "Template rate limit exceeded");

        let mut response = Response::new("Too Many Requests - Template rate limit exceeded".into());
        *response.status_mut() = axum::http::StatusCode::TOO_MANY_REQUESTS;

        // Add rate limit headers
        response
            .headers_mut()
            .insert("X-RateLimit-Limit", "30".parse().unwrap());
        response
            .headers_mut()
            .insert("X-RateLimit-Window", "60".parse().unwrap());
        response
            .headers_mut()
            .insert("Retry-After", "60".parse().unwrap());

        return response;
    }

    // Continue with request
    next.run(request).await
}

/// Rate limiter middleware for credit purchase endpoints
pub async fn credit_purchase_rate_limit_middleware(request: Request, next: Next) -> Response {
    static RATE_LIMITER: std::sync::OnceLock<SimpleRateLimiter> = std::sync::OnceLock::new();
    let limiter = RATE_LIMITER.get_or_init(|| create_credit_purchase_rate_limiter());

    // Extract client identifier
    let client_ip = if let Some(forwarded) = request.headers().get("x-forwarded-for") {
        forwarded.to_str().unwrap_or("unknown").to_string()
    } else if let Some(socket_addr) = request.extensions().get::<SocketAddr>() {
        socket_addr.ip().to_string()
    } else {
        "unknown".to_string()
    };

    // Check rate limit
    if !limiter.is_allowed(&client_ip) {
        warn!(client_ip = %client_ip, "Credit purchase rate limit exceeded");

        let mut response =
            Response::new("Too Many Requests - Please wait before purchasing more credits".into());
        *response.status_mut() = axum::http::StatusCode::TOO_MANY_REQUESTS;

        response
            .headers_mut()
            .insert("X-RateLimit-Limit", "5".parse().unwrap());
        response
            .headers_mut()
            .insert("X-RateLimit-Window", "3600".parse().unwrap());
        response
            .headers_mut()
            .insert("Retry-After", "3600".parse().unwrap());

        return response;
    }

    next.run(request).await
}

/// Rate limiter middleware for subscription management endpoints
pub async fn subscription_rate_limit_middleware(request: Request, next: Next) -> Response {
    static RATE_LIMITER: std::sync::OnceLock<SimpleRateLimiter> = std::sync::OnceLock::new();
    let limiter = RATE_LIMITER.get_or_init(|| create_subscription_rate_limiter());

    // Extract client identifier
    let client_ip = if let Some(forwarded) = request.headers().get("x-forwarded-for") {
        forwarded.to_str().unwrap_or("unknown").to_string()
    } else if let Some(socket_addr) = request.extensions().get::<SocketAddr>() {
        socket_addr.ip().to_string()
    } else {
        "unknown".to_string()
    };

    // Check rate limit
    if !limiter.is_allowed(&client_ip) {
        warn!(client_ip = %client_ip, "Subscription management rate limit exceeded");

        let mut response =
            Response::new("Too Many Requests - Please wait before modifying subscription".into());
        *response.status_mut() = axum::http::StatusCode::TOO_MANY_REQUESTS;

        response
            .headers_mut()
            .insert("X-RateLimit-Limit", "3".parse().unwrap());
        response
            .headers_mut()
            .insert("X-RateLimit-Window", "3600".parse().unwrap());
        response
            .headers_mut()
            .insert("Retry-After", "3600".parse().unwrap());

        return response;
    }

    next.run(request).await
}

/// Rate limiter middleware for webhook endpoints
pub async fn webhook_rate_limit_middleware(request: Request, next: Next) -> Response {
    static RATE_LIMITER: std::sync::OnceLock<SimpleRateLimiter> = std::sync::OnceLock::new();
    let limiter = RATE_LIMITER.get_or_init(|| create_webhook_rate_limiter());

    // Extract client identifier (for webhooks, use signature or user-agent)
    let client_id = if let Some(signature) = request.headers().get("paddle-signature") {
        // Use first 16 chars of signature as identifier
        signature
            .to_str()
            .unwrap_or("unknown")
            .chars()
            .take(16)
            .collect::<String>()
    } else if let Some(forwarded) = request.headers().get("x-forwarded-for") {
        forwarded.to_str().unwrap_or("unknown").to_string()
    } else if let Some(socket_addr) = request.extensions().get::<SocketAddr>() {
        socket_addr.ip().to_string()
    } else {
        "unknown".to_string()
    };

    // Check rate limit
    if !limiter.is_allowed(&client_id) {
        warn!(client_id = %client_id, "Webhook rate limit exceeded");

        let mut response = Response::new("Too Many Requests - Webhook rate limit exceeded".into());
        *response.status_mut() = axum::http::StatusCode::TOO_MANY_REQUESTS;

        response
            .headers_mut()
            .insert("X-RateLimit-Limit", "100".parse().unwrap());
        response
            .headers_mut()
            .insert("X-RateLimit-Window", "60".parse().unwrap());
        response
            .headers_mut()
            .insert("Retry-After", "60".parse().unwrap());

        return response;
    }

    next.run(request).await
}

/// Credit checking middleware for chat generation endpoints
/// This middleware checks if the user has sufficient credits for Pro model usage
pub async fn credit_check_middleware(request: Request, next: Next) -> Response {
    // Only apply credit checking to the generate endpoint
    let uri_path = request.uri().path();
    if !uri_path.contains("/generate") {
        return next.run(request).await;
    }

    // Check if payment feature is enabled
    #[cfg(not(feature = "payment"))]
    {
        return next.run(request).await;
    }

    #[cfg(feature = "payment")]
    {
        use crate::AppState;
        use crate::auth::user_store::Backend as AuthBackend;
        use crate::services::payment::SoftLimitService;
        use axum::Json;
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        use axum_login::AuthSession;
        use serde_json::json;
        use std::sync::Arc;

        // Extract app state from request extensions
        let Some(state) = request.extensions().get::<Arc<AppState>>().cloned() else {
            // If we can't get state, continue without checking
            return next.run(request).await;
        };

        // Extract auth session to get user ID
        let Some(auth_session) = request
            .extensions()
            .get::<AuthSession<AuthBackend>>()
            .cloned()
        else {
            // No auth session, continue (will be rejected by auth middleware anyway)
            return next.run(request).await;
        };

        // Get user ID from session
        let Some(user) = auth_session.user else {
            // Not logged in, continue (will be rejected by auth middleware)
            return next.run(request).await;
        };

        // Check soft limits if enabled
        let soft_limit_service = SoftLimitService::new(state.config.clone());
        if soft_limit_service.is_enabled() {
            // Get database connection
            let Ok(conn) = state.pool.get().await else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "Database connection error"
                    })),
                )
                    .into_response();
            };

            // Check soft limit status
            let user_id = user.id;
            let check_result = conn
                .interact(move |conn| {
                    // Get or create daily usage
                    let usage = soft_limit_service.get_or_create_daily_usage(conn, user_id)?;

                    // Get user's subscription tier (default to "free" if not found)
                    let tier = "free"; // TODO: Get actual tier from subscription service

                    // Get daily limit for tier
                    let daily_limit = soft_limit_service.get_daily_limit(tier);

                    // Calculate usage percentage
                    let usage_percentage =
                        (usage.message_count as f32 / daily_limit as f32 * 100.0) as i32;

                    // Check if soft limit is exceeded
                    if usage.message_count >= daily_limit {
                        // Check if hard limit grace period has passed
                        if usage.soft_limit_triggered_at.is_some() {
                            // For now, we'll allow with warning (could enforce hard stop here)
                            Ok::<_, AppError>((true, usage_percentage, true)) // (has_limit, percentage, is_over_limit)
                        } else {
                            // First time hitting limit
                            Ok::<_, AppError>((true, usage_percentage, true))
                        }
                    } else {
                        Ok::<_, AppError>((true, usage_percentage, false))
                    }
                })
                .await;

            match check_result {
                Ok(Ok((_has_limit, usage_percentage, is_over_limit))) => {
                    if is_over_limit {
                        // Add warning header but continue (soft limit, not hard limit)
                        warn!(
                            user_id = %user.id,
                            usage_percentage = usage_percentage,
                            "User exceeded daily soft limit"
                        );
                        // Could return 429 Too Many Requests here for hard enforcement
                        // For now, we'll continue and let the handler decide
                    }
                }
                Ok(Err(e)) => {
                    warn!("Failed to check soft limits: {}", e);
                    // Continue on error - don't block the request
                }
                Err(e) => {
                    warn!("Database interaction error checking soft limits: {}", e);
                    // Continue on error - don't block the request
                }
            }
        }

        // Continue with request - actual credit checking happens in generate_chat_response
        next.run(request).await
    }
}

/// Soft limit enforcement middleware for daily usage limits
#[cfg(feature = "payment")]
pub async fn soft_limit_enforcement_middleware(request: Request, next: Next) -> Response {
    use crate::AppState;
    use crate::auth::user_store::Backend as AuthBackend;
    use crate::services::payment::SoftLimitService;
    use axum::Json;
    use axum::http::{HeaderValue, StatusCode};
    use axum::response::IntoResponse;
    use axum_login::AuthSession;
    use serde_json::json;
    use std::sync::Arc;

    // Only apply to generate endpoints
    let uri_path = request.uri().path();
    if !uri_path.contains("/generate") {
        return next.run(request).await;
    }

    // Extract app state
    let Some(state) = request.extensions().get::<Arc<AppState>>().cloned() else {
        return next.run(request).await;
    };

    // Extract auth session
    let Some(auth_session) = request
        .extensions()
        .get::<AuthSession<AuthBackend>>()
        .cloned()
    else {
        return next.run(request).await;
    };

    // Get user
    let Some(user) = auth_session.user else {
        return next.run(request).await;
    };

    let soft_limit_service = SoftLimitService::new(state.config.clone());
    if !soft_limit_service.is_enabled() {
        return next.run(request).await;
    }

    // Check soft limits
    let Ok(conn) = state.pool.get().await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "Service temporarily unavailable"
            })),
        )
            .into_response();
    };

    let user_id = user.id;
    let _state_clone = state.clone();

    let check_result = conn
        .interact(move |conn| {
            // Get daily usage
            let usage = soft_limit_service.get_or_create_daily_usage(conn, user_id)?;

            // Get user's subscription tier (simplified for now)
            // TODO: Integrate with actual subscription service when encryption service is available
            let tier = "free".to_string();

            // Get daily limit
            let daily_limit = soft_limit_service.get_daily_limit(&tier);

            // Calculate throttle delay based on usage
            let usage_percentage = (usage.message_count as f32 / daily_limit as f32 * 100.0) as u32;
            let throttle_delay = if usage_percentage > 100 {
                // Progressive throttling after limit
                let over_percentage = usage_percentage - 100;
                Some(std::time::Duration::from_millis(
                    (over_percentage * 100) as u64,
                ))
            } else if usage_percentage > 80 {
                // Mild throttling near limit
                Some(std::time::Duration::from_millis(100))
            } else {
                None
            };

            Ok::<_, AppError>((usage.message_count, daily_limit, throttle_delay, tier))
        })
        .await;

    match check_result {
        Ok(Ok((current_usage, limit, throttle_info, tier))) => {
            // Add headers with usage info
            let mut response = next.run(request).await;
            let headers = response.headers_mut();

            if let Ok(limit_value) = HeaderValue::from_str(&limit.to_string()) {
                headers.insert("X-Daily-Limit", limit_value);
            }
            if let Ok(usage_value) = HeaderValue::from_str(&current_usage.to_string()) {
                headers.insert("X-Daily-Usage", usage_value);
            }
            if let Ok(tier_value) = HeaderValue::from_str(&tier) {
                headers.insert("X-Subscription-Tier", tier_value);
            }

            if let Some(delay) = throttle_info {
                // Apply throttle delay
                if delay.as_secs() > 0 {
                    tokio::time::sleep(delay).await;
                }

                if let Ok(throttle_value) =
                    HeaderValue::from_str(&format!("{}ms", delay.as_millis()))
                {
                    headers.insert("X-Throttle-Applied", throttle_value);
                }

                // If significantly over limit, return 429
                if current_usage > limit * 2 {
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        Json(json!({
                            "error": "Daily message limit exceeded",
                            "limit": limit,
                            "current": current_usage,
                            "tier": tier,
                            "reset_time": "00:00 UTC"
                        })),
                    )
                        .into_response();
                }
            }

            response
        }
        Ok(Err(e)) => {
            warn!("Soft limit check failed: {}", e);
            next.run(request).await
        }
        Err(e) => {
            warn!("Database error during soft limit check: {}", e);
            next.run(request).await
        }
    }
}

/// Middleware to log rate limit violations
pub async fn rate_limit_logger(request: Request, next: Next) -> Response {
    let client_ip = if let Some(forwarded) = request.headers().get("x-forwarded-for") {
        forwarded.to_str().unwrap_or("unknown").to_string()
    } else if let Some(socket_addr) = request.extensions().get::<SocketAddr>() {
        socket_addr.ip().to_string()
    } else {
        "unknown".to_string()
    };

    let method = request.method().clone();
    let uri = request.uri().clone();

    let response = next.run(request).await;

    // Check if this was a rate limit response (429 status)
    if response.status().as_u16() == 429 {
        warn!(
            client_ip = %client_ip,
            method = %method,
            uri = %uri,
            "Rate limit exceeded"
        );
    } else {
        info!(
            client_ip = %client_ip,
            method = %method,
            uri = %uri,
            status = response.status().as_u16(),
            "Request processed"
        );
    }

    response
}

/// Security headers middleware
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    // Prevent clickjacking
    if let Ok(header_value) = "DENY".parse() {
        headers.insert("X-Frame-Options", header_value);
    }

    // Prevent MIME type sniffing
    if let Ok(header_value) = "nosniff".parse() {
        headers.insert("X-Content-Type-Options", header_value);
    }

    // Enable XSS protection
    if let Ok(header_value) = "1; mode=block".parse() {
        headers.insert("X-XSS-Protection", header_value);
    }

    // Strict transport security (HTTPS only)
    if let Ok(header_value) = "max-age=31536000; includeSubDomains; preload".parse() {
        headers.insert("Strict-Transport-Security", header_value);
    }

    // Content Security Policy for API responses
    if let Ok(header_value) = "default-src 'none'; script-src 'none'; object-src 'none'; style-src 'none'; img-src 'none'; media-src 'none'; frame-src 'none'; font-src 'none'; connect-src 'none'".parse() {
        headers.insert("Content-Security-Policy", header_value);
    }

    // Referrer policy
    if let Ok(header_value) = "strict-origin-when-cross-origin".parse() {
        headers.insert("Referrer-Policy", header_value);
    }

    // Permissions policy
    if let Ok(header_value) = "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), speaker=(), vibrate=(), fullscreen=(), sync-xhr=()".parse() {
        headers.insert("Permissions-Policy", header_value);
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_creation() {
        // Test that rate limiters can be created without panicking
        let limiter = create_template_rate_limiter();

        // Basic functionality test
        assert!(limiter.is_allowed("test_client"));
        assert!(limiter.is_allowed("different_client"));
    }

    #[test]
    fn test_simple_rate_limiter() {
        let limiter = SimpleRateLimiter::new(2, Duration::from_secs(1));

        // First two requests should be allowed
        assert!(limiter.is_allowed("client1"));
        assert!(limiter.is_allowed("client1"));

        // Third request should be denied
        assert!(!limiter.is_allowed("client1"));

        // Different client should be allowed
        assert!(limiter.is_allowed("client2"));
    }

    #[test]
    fn test_rate_limiter_window_reset() {
        let limiter = SimpleRateLimiter::new(1, Duration::from_millis(50));

        // First request allowed
        assert!(limiter.is_allowed("client1"));

        // Second request denied (within window)
        assert!(!limiter.is_allowed("client1"));

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(100));

        // Request should be allowed again
        assert!(limiter.is_allowed("client1"));
    }
}
