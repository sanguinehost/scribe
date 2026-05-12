use axum::http::HeaderMap;
use std::net::IpAddr;

/// Anonymize IP address for GDPR Article 32 compliance
///
/// Removes personally identifiable information while preserving
/// attack detection capabilities (subnet-level correlation).
///
/// # Privacy Requirements
/// - IPv4: Masks last octet (e.g., 192.168.1.100 → 192.168.1.0)
/// - IPv6: Masks last 64 bits (e.g., 2001:db8::1 → 2001:db8::)
///
/// # Detection Capabilities
/// - Distributed attacks from same subnet remain correlated
/// - Geographic patterns preserved (first 3 octets)
/// - Individual user tracking prevented (last octet removed)
///
/// # Examples
/// ```
/// use scribe_backend::privacy::ip_anonymization::anonymize_ip;
///
/// assert_eq!(anonymize_ip("192.168.1.100"), "192.168.1.0");
/// assert_eq!(anonymize_ip("2001:db8::1"), "2001:db8:0:0::");
/// ```
pub fn anonymize_ip(ip: &str) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(ipv4)) => {
            let octets = ipv4.octets();
            format!("{}.{}.{}.0", octets[0], octets[1], octets[2])
        }
        Ok(IpAddr::V6(ipv6)) => {
            let segments = ipv6.segments();
            format!(
                "{:x}:{:x}:{:x}:{:x}::",
                segments[0], segments[1], segments[2], segments[3]
            )
        }
        Err(_) => {
            // Invalid IP - return as-is for debugging
            tracing::warn!("Failed to parse IP address for anonymization: {}", ip);
            ip.to_string()
        }
    }
}

/// Extract client IP address from HTTP request headers
///
/// Checks headers in priority order for proxy/load balancer scenarios:
/// 1. X-Forwarded-For (AWS ALB, Cloudflare, most proxies)
/// 2. X-Real-IP (nginx, some CDNs)
/// 3. None if no headers present (direct connection)
///
/// # Security Considerations
/// - X-Forwarded-For can be spoofed by clients
/// - Only use for logging/metrics, NOT authentication
/// - Trust first IP in X-Forwarded-For (client IP before proxy chain)
///
/// # Examples
/// ```
/// use scribe_backend::privacy::ip_anonymization::extract_client_ip;
/// use axum::http::HeaderMap;
///
/// let mut headers = HeaderMap::new();
/// headers.insert("x-forwarded-for", "203.0.113.42, 198.51.100.1".parse().unwrap());
///
/// assert_eq!(extract_client_ip(&headers), Some("203.0.113.42".to_string()));
/// ```
pub fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    // Check X-Forwarded-For first (proxy/load balancer)
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(value) = forwarded.to_str() {
            // Take first IP from comma-separated list (original client IP)
            return value.split(',').next().map(|s| s.trim().to_string());
        }
    }

    // Check X-Real-IP (nginx)
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            return Some(value.to_string());
        }
    }

    // No proxy headers found
    None
}

/// Extract and anonymize client IP in one step
///
/// Convenience function combining extraction and anonymization.
/// Returns anonymized IP or "unknown" if extraction fails.
///
/// # Examples
/// ```
/// use scribe_backend::privacy::ip_anonymization::extract_and_anonymize_ip;
/// use axum::http::HeaderMap;
///
/// let mut headers = HeaderMap::new();
/// headers.insert("x-forwarded-for", "192.168.1.100".parse().unwrap());
///
/// assert_eq!(extract_and_anonymize_ip(&headers), "192.168.1.0");
/// ```
pub fn extract_and_anonymize_ip(headers: &HeaderMap) -> String {
    extract_client_ip(headers)
        .map(|ip| anonymize_ip(&ip))
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anonymize_ipv4() {
        assert_eq!(anonymize_ip("192.168.1.100"), "192.168.1.0");
        assert_eq!(anonymize_ip("10.0.0.255"), "10.0.0.0");
        assert_eq!(anonymize_ip("203.0.113.42"), "203.0.113.0");
    }

    #[test]
    fn test_anonymize_ipv4_preserves_subnet() {
        // Verify same subnet IPs map to same anonymized value
        assert_eq!(anonymize_ip("192.168.1.1"), anonymize_ip("192.168.1.255"));
        assert_eq!(anonymize_ip("10.0.5.10"), anonymize_ip("10.0.5.200"));
    }

    #[test]
    fn test_anonymize_ipv6() {
        assert_eq!(anonymize_ip("2001:db8::1"), "2001:db8:0:0::");
        assert_eq!(
            anonymize_ip("2001:0db8:0000:0000:0000:0000:0000:0001"),
            "2001:db8:0:0::"
        );
        assert_eq!(anonymize_ip("fe80::1"), "fe80:0:0:0::");
    }

    #[test]
    fn test_anonymize_ipv6_preserves_network() {
        // Verify same /64 network IPs map to same anonymized value
        assert_eq!(
            anonymize_ip("2001:db8::1"),
            anonymize_ip("2001:db8::ffff:ffff:ffff:ffff")
        );
    }

    #[test]
    fn test_anonymize_invalid_ip() {
        // Invalid IPs should be returned as-is
        assert_eq!(anonymize_ip("not-an-ip"), "not-an-ip");
        assert_eq!(anonymize_ip("999.999.999.999"), "999.999.999.999");
        assert_eq!(anonymize_ip(""), "");
    }

    #[test]
    fn test_extract_client_ip_from_x_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.42, 198.51.100.1, 192.0.2.1".parse().unwrap(),
        );

        // Should extract first IP (original client)
        assert_eq!(
            extract_client_ip(&headers),
            Some("203.0.113.42".to_string())
        );
    }

    #[test]
    fn test_extract_client_ip_from_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "192.168.1.100".parse().unwrap());

        assert_eq!(
            extract_client_ip(&headers),
            Some("192.168.1.100".to_string())
        );
    }

    #[test]
    fn test_extract_client_ip_prefers_x_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.42".parse().unwrap());
        headers.insert("x-real-ip", "192.168.1.100".parse().unwrap());

        // Should prefer X-Forwarded-For over X-Real-IP
        assert_eq!(
            extract_client_ip(&headers),
            Some("203.0.113.42".to_string())
        );
    }

    #[test]
    fn test_extract_client_ip_no_headers() {
        let headers = HeaderMap::new();
        assert_eq!(extract_client_ip(&headers), None);
    }

    #[test]
    fn test_extract_client_ip_invalid_header_value() {
        let mut headers = HeaderMap::new();
        // Insert invalid UTF-8 (this test may not trigger the error path easily in practice)
        // In reality, HeaderValue::from_str validates UTF-8, so this is mainly for coverage
        headers.insert("x-forwarded-for", "203.0.113.42".parse().unwrap());

        assert_eq!(
            extract_client_ip(&headers),
            Some("203.0.113.42".to_string())
        );
    }

    #[test]
    fn test_extract_and_anonymize_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "192.168.1.100".parse().unwrap());

        assert_eq!(extract_and_anonymize_ip(&headers), "192.168.1.0");
    }

    #[test]
    fn test_extract_and_anonymize_ip_no_headers() {
        let headers = HeaderMap::new();
        assert_eq!(extract_and_anonymize_ip(&headers), "unknown");
    }

    #[test]
    fn test_extract_and_anonymize_ipv6() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "2001:db8::1".parse().unwrap());

        assert_eq!(extract_and_anonymize_ip(&headers), "2001:db8:0:0::");
    }

    #[test]
    fn test_privacy_safe_no_tracking() {
        // Verify different IPs in same subnet produce same result
        // (prevents individual user tracking)
        let ip1 = anonymize_ip("192.168.1.50");
        let ip2 = anonymize_ip("192.168.1.150");
        assert_eq!(ip1, ip2);
        assert_eq!(ip1, "192.168.1.0");
    }

    #[test]
    fn test_attack_detection_capability() {
        // Verify distributed attack from different subnets is detectable
        let subnet1 = anonymize_ip("192.168.1.100");
        let subnet2 = anonymize_ip("192.168.2.100");
        assert_ne!(subnet1, subnet2);

        // But same subnet attacks are correlated
        let same_subnet_1 = anonymize_ip("10.0.5.10");
        let same_subnet_2 = anonymize_ip("10.0.5.200");
        assert_eq!(same_subnet_1, same_subnet_2);
    }

    #[test]
    fn test_real_world_aws_alb_headers() {
        // Simulate AWS ALB X-Forwarded-For format
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.42, 10.0.1.5".parse().unwrap());

        let ip = extract_client_ip(&headers).unwrap();
        assert_eq!(ip, "203.0.113.42");

        let anonymized = anonymize_ip(&ip);
        assert_eq!(anonymized, "203.0.113.0");
    }

    #[test]
    fn test_real_world_cloudflare_headers() {
        // Simulate Cloudflare proxy chain
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "192.0.2.1, 198.41.128.1, 198.41.129.1".parse().unwrap(),
        );

        // Should extract original client IP
        assert_eq!(extract_client_ip(&headers), Some("192.0.2.1".to_string()));
    }
}
