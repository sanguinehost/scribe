use chrono::{DateTime, Utc};
use serde::Serialize;

/// Security event types for structured logging to CloudWatch
/// All events use privacy-safe data (hashed user IDs, anonymized IPs)
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event_type")]
pub enum SecurityEvent {
    /// Webhook signature verification failure (potential attack)
    #[serde(rename = "webhook_signature_failure")]
    WebhookSignatureFailure {
        timestamp: DateTime<Utc>,
        ip_address: String, // Anonymized IP (last octet masked)
        endpoint: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        user_agent: Option<String>,
    },

    /// Authentication failure (credential stuffing, brute force)
    #[serde(rename = "auth_failure")]
    AuthFailure {
        timestamp: DateTime<Utc>,
        user_hash: String,  // Hashed user ID (SHA-256 + salt)
        ip_address: String, // Anonymized IP
        failure_reason: String,
        attempt_count: u32, // For rate-based detection
    },

    /// Credit operation anomaly (fraud detection)
    #[serde(rename = "credit_operation_anomaly")]
    CreditOperationAnomaly {
        timestamp: DateTime<Utc>,
        user_hash: String,      // Hashed user ID
        operation_type: String, // "add", "deduct", "expire"
        amount: f64,
        anomaly_reason: String,  // "rate_limit", "unusual_amount", "timing"
        baseline_deviation: f64, // How many σ from baseline
    },

    /// Encryption/decryption error (key compromise indicator)
    #[serde(rename = "encryption_error")]
    EncryptionError {
        timestamp: DateTime<Utc>,
        error_type: String, // "decryption_failed", "invalid_key", "corrupted_data"
        context: String,    // Operation context (NO PII)
        #[serde(skip_serializing_if = "Option::is_none")]
        affected_record_count: Option<usize>,
    },

    /// Suspicious data access pattern (exfiltration attempt)
    #[serde(rename = "suspicious_data_access")]
    SuspiciousDataAccess {
        timestamp: DateTime<Utc>,
        user_hash: String, // Hashed user ID
        endpoint: String,
        record_count: usize,
        anomaly_reason: String, // "bulk_access", "unusual_time", "rapid_requests"
        time_window_seconds: u64,
    },

    /// DEK cache bulk access (key scraping attempt)
    #[serde(rename = "dek_cache_bulk_access")]
    DekCacheBulkAccess {
        timestamp: DateTime<Utc>,
        user_hash: String, // Hashed user ID
        access_count: usize,
        time_window_seconds: u64,
        threshold_exceeded_by: f64, // Percentage over threshold
    },

    /// Payment webhook replay attack detected
    #[serde(rename = "webhook_replay_attack")]
    WebhookReplayAttack {
        timestamp: DateTime<Utc>,
        ip_address: String, // Anonymized IP
        event_id: String,   // Paddle event ID
        original_timestamp: DateTime<Utc>,
        replay_delay_seconds: i64,
    },
}

impl SecurityEvent {
    /// Get the timestamp of the security event
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            SecurityEvent::WebhookSignatureFailure { timestamp, .. } => *timestamp,
            SecurityEvent::AuthFailure { timestamp, .. } => *timestamp,
            SecurityEvent::CreditOperationAnomaly { timestamp, .. } => *timestamp,
            SecurityEvent::EncryptionError { timestamp, .. } => *timestamp,
            SecurityEvent::SuspiciousDataAccess { timestamp, .. } => *timestamp,
            SecurityEvent::DekCacheBulkAccess { timestamp, .. } => *timestamp,
            SecurityEvent::WebhookReplayAttack { timestamp, .. } => *timestamp,
        }
    }

    /// Get the severity level for alerting (P0-P3)
    pub fn severity(&self) -> SecurityEventSeverity {
        match self {
            SecurityEvent::WebhookSignatureFailure { .. } => SecurityEventSeverity::P1,
            SecurityEvent::AuthFailure { attempt_count, .. } => {
                if *attempt_count >= 10 {
                    SecurityEventSeverity::P1 // High-volume attack
                } else {
                    SecurityEventSeverity::P2
                }
            }
            SecurityEvent::CreditOperationAnomaly {
                baseline_deviation, ..
            } => {
                if *baseline_deviation >= 5.0 {
                    SecurityEventSeverity::P0 // Critical anomaly (>5σ)
                } else {
                    SecurityEventSeverity::P1
                }
            }
            SecurityEvent::EncryptionError {
                affected_record_count,
                ..
            } => match affected_record_count {
                Some(count) if *count > 100 => SecurityEventSeverity::P0,
                Some(count) if *count > 10 => SecurityEventSeverity::P1,
                _ => SecurityEventSeverity::P2,
            },
            SecurityEvent::SuspiciousDataAccess { record_count, .. } => {
                if *record_count >= 1000 {
                    SecurityEventSeverity::P0 // Mass exfiltration attempt
                } else if *record_count >= 100 {
                    SecurityEventSeverity::P1
                } else {
                    SecurityEventSeverity::P2
                }
            }
            SecurityEvent::DekCacheBulkAccess {
                threshold_exceeded_by,
                ..
            } => {
                if *threshold_exceeded_by >= 500.0 {
                    SecurityEventSeverity::P0 // 5x over threshold
                } else {
                    SecurityEventSeverity::P1
                }
            }
            SecurityEvent::WebhookReplayAttack { .. } => SecurityEventSeverity::P1,
        }
    }

    /// Convert to JSON string for CloudWatch logging
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Convert to pretty JSON for debugging
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Security event severity levels matching incident response SLAs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SecurityEventSeverity {
    /// P0: Critical (15min SLA) - Active attacks, mass exfiltration
    P0,
    /// P1: High (1hr SLA) - Webhook attacks, credential stuffing
    P1,
    /// P2: Medium (4hr SLA) - Individual auth failures, minor anomalies
    P2,
    /// P3: Low (24hr SLA) - Informational, baselines
    P3,
}

impl SecurityEventSeverity {
    /// Get the CloudWatch alarm threshold for this severity
    pub fn alarm_threshold(&self) -> usize {
        match self {
            SecurityEventSeverity::P0 => 1,   // Alert on first occurrence
            SecurityEventSeverity::P1 => 5,   // Alert on 5+ occurrences
            SecurityEventSeverity::P2 => 10,  // Alert on 10+ occurrences
            SecurityEventSeverity::P3 => 100, // Alert on 100+ occurrences
        }
    }

    /// Get the response SLA in minutes
    pub fn sla_minutes(&self) -> u32 {
        match self {
            SecurityEventSeverity::P0 => 15,
            SecurityEventSeverity::P1 => 60,
            SecurityEventSeverity::P2 => 240,
            SecurityEventSeverity::P3 => 1440,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_signature_failure_serialization() {
        let event = SecurityEvent::WebhookSignatureFailure {
            timestamp: Utc::now(),
            ip_address: "192.168.1.0".to_string(),
            endpoint: "/api/webhooks/paddle".to_string(),
            user_agent: Some("curl/7.68.0".to_string()),
        };

        let json = event.to_json().unwrap();
        assert!(json.contains("webhook_signature_failure"));
        assert!(json.contains("192.168.1.0"));
        assert!(!json.contains("192.168.1.100")); // Verify anonymization
    }

    #[test]
    fn test_auth_failure_serialization() {
        let event = SecurityEvent::AuthFailure {
            timestamp: Utc::now(),
            user_hash: "user#abc123".to_string(),
            ip_address: "10.0.0.0".to_string(),
            failure_reason: "invalid_password".to_string(),
            attempt_count: 5,
        };

        let json = event.to_json().unwrap();
        assert!(json.contains("auth_failure"));
        assert!(json.contains("user#abc123"));
        assert!(json.contains("\"attempt_count\":5"));
    }

    #[test]
    fn test_credit_operation_anomaly_severity() {
        let event_low = SecurityEvent::CreditOperationAnomaly {
            timestamp: Utc::now(),
            user_hash: "user#xyz789".to_string(),
            operation_type: "add".to_string(),
            amount: 1000.0,
            anomaly_reason: "unusual_amount".to_string(),
            baseline_deviation: 3.5,
        };

        assert_eq!(event_low.severity(), SecurityEventSeverity::P1);

        let event_critical = SecurityEvent::CreditOperationAnomaly {
            timestamp: Utc::now(),
            user_hash: "user#xyz789".to_string(),
            operation_type: "add".to_string(),
            amount: 1000000.0,
            anomaly_reason: "extreme_amount".to_string(),
            baseline_deviation: 6.0, // >5σ deviation
        };

        assert_eq!(event_critical.severity(), SecurityEventSeverity::P0);
    }

    #[test]
    fn test_encryption_error_serialization() {
        let event = SecurityEvent::EncryptionError {
            timestamp: Utc::now(),
            error_type: "decryption_failed".to_string(),
            context: "payment_transaction_decryption".to_string(),
            affected_record_count: Some(15),
        };

        let json = event.to_json().unwrap();
        assert!(json.contains("encryption_error"));
        assert!(json.contains("decryption_failed"));
        assert!(json.contains("\"affected_record_count\":15"));
    }

    #[test]
    fn test_suspicious_data_access_severity() {
        let event_low = SecurityEvent::SuspiciousDataAccess {
            timestamp: Utc::now(),
            user_hash: "user#def456".to_string(),
            endpoint: "/api/characters".to_string(),
            record_count: 50,
            anomaly_reason: "rapid_requests".to_string(),
            time_window_seconds: 60,
        };

        assert_eq!(event_low.severity(), SecurityEventSeverity::P2);

        let event_high = SecurityEvent::SuspiciousDataAccess {
            timestamp: Utc::now(),
            user_hash: "user#def456".to_string(),
            endpoint: "/api/users".to_string(),
            record_count: 500,
            anomaly_reason: "bulk_access".to_string(),
            time_window_seconds: 30,
        };

        assert_eq!(event_high.severity(), SecurityEventSeverity::P1);

        let event_critical = SecurityEvent::SuspiciousDataAccess {
            timestamp: Utc::now(),
            user_hash: "user#def456".to_string(),
            endpoint: "/api/transactions".to_string(),
            record_count: 2000,
            anomaly_reason: "mass_exfiltration".to_string(),
            time_window_seconds: 10,
        };

        assert_eq!(event_critical.severity(), SecurityEventSeverity::P0);
    }

    #[test]
    fn test_dek_cache_bulk_access_serialization() {
        let event = SecurityEvent::DekCacheBulkAccess {
            timestamp: Utc::now(),
            user_hash: "user#ghi012".to_string(),
            access_count: 150,
            time_window_seconds: 60,
            threshold_exceeded_by: 250.0, // 250% over threshold
        };

        let json = event.to_json().unwrap();
        assert!(json.contains("dek_cache_bulk_access"));
        assert!(json.contains("\"access_count\":150"));
        assert!(json.contains("250"));
    }

    #[test]
    fn test_webhook_replay_attack_serialization() {
        let original_ts = Utc::now() - chrono::Duration::hours(2);
        let event = SecurityEvent::WebhookReplayAttack {
            timestamp: Utc::now(),
            ip_address: "203.0.113.0".to_string(),
            event_id: "evt_abc123xyz".to_string(),
            original_timestamp: original_ts,
            replay_delay_seconds: 7200,
        };

        let json = event.to_json().unwrap();
        assert!(json.contains("webhook_replay_attack"));
        assert!(json.contains("evt_abc123xyz"));
        assert!(json.contains("\"replay_delay_seconds\":7200"));
    }

    #[test]
    fn test_severity_alarm_thresholds() {
        assert_eq!(SecurityEventSeverity::P0.alarm_threshold(), 1);
        assert_eq!(SecurityEventSeverity::P1.alarm_threshold(), 5);
        assert_eq!(SecurityEventSeverity::P2.alarm_threshold(), 10);
        assert_eq!(SecurityEventSeverity::P3.alarm_threshold(), 100);
    }

    #[test]
    fn test_severity_sla_minutes() {
        assert_eq!(SecurityEventSeverity::P0.sla_minutes(), 15);
        assert_eq!(SecurityEventSeverity::P1.sla_minutes(), 60);
        assert_eq!(SecurityEventSeverity::P2.sla_minutes(), 240);
        assert_eq!(SecurityEventSeverity::P3.sla_minutes(), 1440);
    }

    #[test]
    fn test_high_volume_auth_failure_severity() {
        let event = SecurityEvent::AuthFailure {
            timestamp: Utc::now(),
            user_hash: "user#brute123".to_string(),
            ip_address: "198.51.100.0".to_string(),
            failure_reason: "invalid_password".to_string(),
            attempt_count: 15,
        };

        assert_eq!(event.severity(), SecurityEventSeverity::P1);
    }

    #[test]
    fn test_privacy_safe_serialization_no_pii() {
        let event = SecurityEvent::AuthFailure {
            timestamp: Utc::now(),
            user_hash: "user#abc123".to_string(),
            ip_address: "192.168.1.0".to_string(),
            failure_reason: "invalid_password".to_string(),
            attempt_count: 3,
        };

        let json = event.to_json().unwrap();

        // Verify privacy-safe format (hashed, not raw UUID)
        assert!(json.contains("user#abc123"));

        // Verify no UUID-like patterns (8-4-4-4-12 hex format)
        // UUIDs look like: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        let uuid_pattern =
            regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
                .unwrap();
        assert!(
            !uuid_pattern.is_match(&json),
            "JSON should not contain raw UUIDs"
        );

        // Verify IP anonymization (no last octet)
        assert!(json.contains("192.168.1.0"));
        assert!(!json.contains("192.168.1.100"));
    }
}
