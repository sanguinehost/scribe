use crate::errors::AppError;
use axum::{extract::Request, middleware::Next, response::Response};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tower_governor::{
    governor::GovernorConfigBuilder, 
    key_extractor::SmartIpKeyExtractor, 
    GovernorLayer,
};
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
        let client_requests = requests.entry(client_id.to_string()).or_insert_with(Vec::new);
        
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

/// Rate limiter middleware for template endpoints
pub async fn template_rate_limit_middleware(
    request: Request,
    next: Next,
) -> Response {
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
        
        let mut response = Response::new(
            "Too Many Requests - Template rate limit exceeded".into()
        );
        *response.status_mut() = axum::http::StatusCode::TOO_MANY_REQUESTS;
        
        // Add rate limit headers
        response.headers_mut().insert(
            "X-RateLimit-Limit",
            "30".parse().unwrap(),
        );
        response.headers_mut().insert(
            "X-RateLimit-Window",
            "60".parse().unwrap(),
        );
        response.headers_mut().insert(
            "Retry-After",
            "60".parse().unwrap(),
        );
        
        return response;
    }

    // Continue with request
    next.run(request).await
}

/// Middleware to log rate limit violations
pub async fn rate_limit_logger(
    request: Request,
    next: Next,
) -> Response {
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
pub async fn security_headers(
    request: Request,
    next: Next,
) -> Response {
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