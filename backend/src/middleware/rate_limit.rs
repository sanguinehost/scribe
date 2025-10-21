use axum::{extract::Request, middleware::Next, response::Response};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};

#[cfg(feature = "payment")]
use crate::errors::AppError;

/// Simple token bucket rate limiter
///
/// This implements a token bucket algorithm that provides:
/// - Predictable lockout times
/// - Token refill at a steady rate
/// - Clear retry-after information
/// - Burst capacity for legitimate use
#[derive(Debug, Clone)]
pub struct SimpleRateLimiter {
    buckets: Arc<Mutex<HashMap<String, TokenBucket>>>,
    capacity: usize,
    refill_rate: Duration, // Duration to refill one token
}

#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: usize) -> Self {
        Self {
            tokens: capacity as f64,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self, capacity: usize, refill_rate: Duration) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);

        // Calculate how many tokens to add based on elapsed time
        let tokens_to_add = elapsed.as_secs_f64() / refill_rate.as_secs_f64();

        self.tokens = (self.tokens + tokens_to_add).min(capacity as f64);
        self.last_refill = now;
    }

    fn try_consume(&mut self) -> bool {
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn time_until_next_token(&self, refill_rate: Duration) -> Duration {
        let tokens_needed = 1.0 - self.tokens;
        if tokens_needed <= 0.0 {
            Duration::from_secs(0)
        } else {
            Duration::from_secs_f64(tokens_needed * refill_rate.as_secs_f64())
        }
    }
}

impl SimpleRateLimiter {
    /// Create a new token bucket rate limiter
    ///
    /// # Arguments
    /// * `capacity` - Maximum number of tokens (burst capacity)
    /// * `refill_rate` - Duration to refill one token
    pub fn new(capacity: usize, refill_rate: Duration) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            capacity,
            refill_rate,
        }
    }

    /// Check if a request is allowed and return retry-after duration if not
    ///
    /// Returns: (is_allowed, retry_after_seconds)
    pub fn check_request(&self, client_id: &str) -> (bool, Option<u64>) {
        let mut buckets = self.buckets.lock().unwrap();

        let bucket = buckets
            .entry(client_id.to_string())
            .or_insert_with(|| TokenBucket::new(self.capacity));

        // Refill tokens based on elapsed time
        bucket.refill(self.capacity, self.refill_rate);

        // Try to consume a token
        if bucket.try_consume() {
            (true, None)
        } else {
            // Calculate when next token will be available
            let wait_time = bucket.time_until_next_token(self.refill_rate);
            (false, Some(wait_time.as_secs().max(1))) // At least 1 second
        }
    }

    /// Legacy method for backward compatibility
    pub fn is_allowed(&self, client_id: &str) -> bool {
        self.check_request(client_id).0
    }
}

/// Rate limiter for template endpoints (restrictive)
/// 30 token capacity, refills 1 token every 2 seconds (30 per minute rate)
pub fn create_template_rate_limiter() -> SimpleRateLimiter {
    SimpleRateLimiter::new(30, Duration::from_secs(2))
}

/// Rate limiter for credit purchase endpoints (very restrictive)
/// 5 token capacity, refills 1 token every 5 minutes (allows 5 purchases per hour with bursts)
/// Retry wait time: 5 minutes max (not 1 hour!)
pub fn create_credit_purchase_rate_limiter() -> SimpleRateLimiter {
    SimpleRateLimiter::new(5, Duration::from_secs(300)) // 5 minutes per token
}

/// Rate limiter for subscription management endpoints (restrictive)
/// 3 token capacity, refills 1 token every 10 minutes (allows 6 operations per hour with bursts)
/// Retry wait time: 10 minutes max (not 1 hour!)
pub fn create_subscription_rate_limiter() -> SimpleRateLimiter {
    SimpleRateLimiter::new(3, Duration::from_secs(600)) // 10 minutes per token
}

/// Rate limiter for webhook endpoints (allow more for reliability)
/// 100 token capacity, refills 1 token per 0.6 seconds (100 per minute rate)
pub fn create_webhook_rate_limiter() -> SimpleRateLimiter {
    SimpleRateLimiter::new(100, Duration::from_millis(600))
}

/// Rate limiter for AI lorebook endpoints (restrictive due to high cost)
/// Production: 5 token capacity, refills 1 token every 12 minutes (5 AI operations per hour with bursts)
/// Test mode: 5 token capacity, refills 1 token every 1 second (for fast test execution)
/// Retry wait time: 12 minutes max (production), 1 second (test)
pub fn create_ai_lorebook_rate_limiter() -> SimpleRateLimiter {
    // In test mode, use a much faster refill rate to avoid test interference
    #[cfg(test)]
    {
        SimpleRateLimiter::new(5, Duration::from_secs(1)) // 1 second per token for tests
    }
    #[cfg(not(test))]
    {
        SimpleRateLimiter::new(5, Duration::from_secs(720)) // 12 minutes per token for production
    }
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

    // Check rate limit with accurate retry-after
    let (is_allowed, retry_after) = limiter.check_request(&client_ip);

    if !is_allowed {
        let retry_seconds = retry_after.unwrap_or(300); // Default to 5 minutes
        warn!(
            client_ip = %client_ip,
            retry_after_seconds = retry_seconds,
            "Credit purchase rate limit exceeded"
        );

        let mut response = Response::new(
            format!(
                "Too Many Requests - Please wait {} seconds ({} minutes) before purchasing more credits",
                retry_seconds,
                retry_seconds / 60
            )
            .into(),
        );
        *response.status_mut() = axum::http::StatusCode::TOO_MANY_REQUESTS;

        response
            .headers_mut()
            .insert("X-RateLimit-Limit", "5".parse().unwrap());
        response
            .headers_mut()
            .insert("X-RateLimit-Refill-Rate", "300".parse().unwrap()); // 5 minutes per token
        response
            .headers_mut()
            .insert("Retry-After", retry_seconds.to_string().parse().unwrap());

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

    // Check rate limit with accurate retry-after
    let (is_allowed, retry_after) = limiter.check_request(&client_ip);

    if !is_allowed {
        let retry_seconds = retry_after.unwrap_or(600); // Default to 10 minutes
        warn!(
            client_ip = %client_ip,
            retry_after_seconds = retry_seconds,
            "Subscription management rate limit exceeded"
        );

        let mut response = Response::new(
            format!(
                "Too Many Requests - Please wait {} seconds ({} minutes) before modifying subscription",
                retry_seconds,
                retry_seconds / 60
            )
            .into(),
        );
        *response.status_mut() = axum::http::StatusCode::TOO_MANY_REQUESTS;

        response
            .headers_mut()
            .insert("X-RateLimit-Limit", "3".parse().unwrap());
        response
            .headers_mut()
            .insert("X-RateLimit-Refill-Rate", "600".parse().unwrap()); // 10 minutes per token
        response
            .headers_mut()
            .insert("Retry-After", retry_seconds.to_string().parse().unwrap());

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

/// Rate limiter middleware for AI lorebook endpoints
pub async fn ai_lorebook_rate_limit_middleware(request: Request, next: Next) -> Response {
    static RATE_LIMITER: std::sync::OnceLock<SimpleRateLimiter> = std::sync::OnceLock::new();
    let limiter = RATE_LIMITER.get_or_init(|| create_ai_lorebook_rate_limiter());

    // Extract client identifier - use both IP and user_id if available
    let client_ip = if let Some(forwarded) = request.headers().get("x-forwarded-for") {
        forwarded.to_str().unwrap_or("unknown").to_string()
    } else if let Some(socket_addr) = request.extensions().get::<SocketAddr>() {
        socket_addr.ip().to_string()
    } else {
        "unknown".to_string()
    };

    // For test environments where client_ip is "unknown", use user_id from session to ensure
    // each user gets their own rate limit bucket (prevents test interference)
    let rate_limit_key = if client_ip == "unknown" {
        // Try to get user_id from auth session
        use crate::auth::user_store::Backend as AuthBackend;
        use axum_login::AuthSession;

        if let Some(auth_session) = request.extensions().get::<AuthSession<AuthBackend>>() {
            if let Some(user) = &auth_session.user {
                format!("user:{}", user.id)
            } else {
                client_ip.clone()
            }
        } else {
            client_ip.clone()
        }
    } else {
        client_ip.clone()
    };

    // Security logging: Track all AI lorebook request attempts
    let uri_path = request.uri().path();
    info!(
        client_ip = %client_ip,
        path = %uri_path,
        "AI lorebook request rate limit check"
    );

    // Check rate limit with accurate retry-after
    let (is_allowed, retry_after) = limiter.check_request(&rate_limit_key);

    if !is_allowed {
        let retry_seconds = retry_after.unwrap_or(720); // Default to 12 minutes
        warn!(
            client_ip = %client_ip,
            path = %uri_path,
            retry_after_seconds = retry_seconds,
            "AI lorebook rate limit exceeded - request blocked"
        );

        let mut response = Response::new(
            format!(
                "Too Many Requests - AI lorebook operations are limited. Please wait {} seconds ({} minutes) before trying again",
                retry_seconds,
                retry_seconds / 60
            )
            .into(),
        );
        *response.status_mut() = axum::http::StatusCode::TOO_MANY_REQUESTS;

        response
            .headers_mut()
            .insert("X-RateLimit-Limit", "5".parse().unwrap());
        response
            .headers_mut()
            .insert("X-RateLimit-Refill-Rate", "720".parse().unwrap()); // 12 minutes per token
        response
            .headers_mut()
            .insert("Retry-After", retry_seconds.to_string().parse().unwrap());

        return response;
    }

    // Security logging: Track allowed AI lorebook requests
    info!(
        client_ip = %client_ip,
        path = %uri_path,
        "AI lorebook request allowed by rate limiter"
    );

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
        use crate::auth::user_store::Backend as AuthBackend;
        use crate::services::payment::SoftLimitService;
        use crate::AppState;
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        use axum::Json;
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
            // Check soft limit status
            let user_id = user.id;
            let pool = state.pool.clone();
            let check_result = crate::db::with_conn(&pool, move |conn| {
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
            }).await;

            match check_result {
                Ok((_has_limit, usage_percentage, is_over_limit)) => {
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
                Err(e) => {
                    warn!("Failed to check soft limits: {}", e);
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
    use crate::auth::user_store::Backend as AuthBackend;
    use crate::services::payment::SoftLimitService;
    use crate::AppState;
    use axum::http::{HeaderValue, StatusCode};
    use axum::response::IntoResponse;
    use axum::Json;
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
    let user_id = user.id;
    let pool = state.pool.clone();

    let check_result = crate::db::with_conn(&pool, move |conn| {
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
    }).await;

    match check_result {
        Ok((current_usage, limit, throttle_info, tier)) => {
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
        Err(e) => {
            warn!("Soft limit check failed: {}", e);
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
    fn test_token_bucket_rate_limiter() {
        // 2 token capacity, 1 second refill per token
        let limiter = SimpleRateLimiter::new(2, Duration::from_secs(1));

        // First two requests should be allowed (consume both tokens)
        assert!(limiter.is_allowed("client1"));
        assert!(limiter.is_allowed("client1"));

        // Third request should be denied (no tokens left)
        let (allowed, retry_after) = limiter.check_request("client1");
        assert!(!allowed);
        assert!(retry_after.is_some());
        assert!(retry_after.unwrap() > 0);

        // Different client should be allowed (separate bucket)
        assert!(limiter.is_allowed("client2"));
    }

    #[test]
    fn test_token_bucket_refill() {
        // 1 token capacity, 50ms refill per token
        let limiter = SimpleRateLimiter::new(1, Duration::from_millis(50));

        // First request allowed (consume token)
        assert!(limiter.is_allowed("client1"));

        // Second request denied (no tokens)
        assert!(!limiter.is_allowed("client1"));

        // Wait for token to refill
        std::thread::sleep(Duration::from_millis(100));

        // Request should be allowed again (token refilled)
        assert!(limiter.is_allowed("client1"));
    }

    #[test]
    fn test_token_bucket_accurate_retry_after() {
        // 2 token capacity, 100ms refill per token
        let limiter = SimpleRateLimiter::new(2, Duration::from_millis(100));

        // Consume both tokens
        assert!(limiter.is_allowed("client1"));
        assert!(limiter.is_allowed("client1"));

        // Check retry-after is reasonable (should be ~100ms = 0 seconds, rounds to 1)
        let (allowed, retry_after) = limiter.check_request("client1");
        assert!(!allowed);
        let retry_seconds = retry_after.unwrap();
        assert!(
            retry_seconds >= 1,
            "Retry-after should be at least 1 second (was {})",
            retry_seconds
        );
    }

    #[test]
    fn test_token_bucket_burst_capacity() {
        // 3 token capacity, 1 second refill per token
        let limiter = SimpleRateLimiter::new(3, Duration::from_secs(1));

        // Can burst 3 requests immediately
        assert!(limiter.is_allowed("client1"));
        assert!(limiter.is_allowed("client1"));
        assert!(limiter.is_allowed("client1"));

        // Fourth request denied
        assert!(!limiter.is_allowed("client1"));

        // Wait for 2 seconds (should refill 2 tokens)
        std::thread::sleep(Duration::from_millis(2100));

        // Can make 2 more requests
        assert!(limiter.is_allowed("client1"));
        assert!(limiter.is_allowed("client1"));

        // Third request after refill should be denied
        assert!(!limiter.is_allowed("client1"));
    }
}
