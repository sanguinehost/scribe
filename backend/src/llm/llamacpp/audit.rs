// backend/src/llm/llamacpp/audit.rs
// Security event logging and monitoring for LLM operations

use crate::llm::llamacpp::security::SecurityError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::{debug, info, warn, error};
use uuid::Uuid;

/// Types of security events that can occur in LLM operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SecurityEventType {
    // Authentication and authorization
    UnauthorizedAccess,
    AuthenticationFailed,
    PrivilegeEscalation,
    
    // OWASP LLM01 - Prompt Injection
    PromptInjectionAttempt,
    JailbreakAttempt,
    SystemPromptBypass,
    InstructionManipulation,
    
    // OWASP LLM02 - Sensitive Information Disclosure  
    SensitiveDataLeakage,
    PiiExposureAttempt,
    CredentialLeakage,
    InternalDataExposure,
    
    // OWASP LLM05 - Improper Output Handling
    UnsafeOutputGenerated,
    XssAttempt,
    SqlInjectionAttempt,
    CodeInjectionAttempt,
    
    // OWASP LLM07 - System Prompt Leakage
    SystemPromptLeakage,
    ConfigurationExposure,
    InternalRulesDisclosure,
    
    // OWASP LLM10 - Unbounded Consumption
    RateLimitExceeded,
    ResourceExhaustion,
    DosAttempt,
    TokenLimitExceeded,
    ConcurrentRequestsExceeded,
    
    // Model and infrastructure security
    ModelTampering,
    ServerCompromise,
    ModelDownloadFailed,
    IntegrityCheckFailed,
    
    // Encryption and privacy
    EncryptionFailure,
    DecryptionFailure,
    DekCompromise,
    DataExfiltration,
    
    // General security violations
    SuspiciousActivity,
    PolicyViolation,
    SecurityControlBypass,
}

/// Severity levels for security events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum SecurityEventSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Security event record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: SecurityEventType,
    pub severity: SecurityEventSeverity,
    pub user_id: Option<Uuid>,
    pub session_id: Option<String>,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub model_id: Option<String>,
    pub endpoint: String,
    pub method: String,
    pub message: String,
    pub details: HashMap<String, serde_json::Value>,
    pub blocked: bool,
    pub remediation_taken: Vec<String>,
}

impl SecurityEvent {
    /// Create a new security event
    pub fn new(
        event_type: SecurityEventType,
        severity: SecurityEventSeverity,
        endpoint: String,
        method: String,
        message: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            severity,
            user_id: None,
            session_id: None,
            source_ip: None,
            user_agent: None,
            model_id: None,
            endpoint,
            method,
            message,
            details: HashMap::new(),
            blocked: false,
            remediation_taken: Vec::new(),
        }
    }

    /// Add user context to the event
    pub fn with_user(mut self, user_id: Uuid) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// Add request context to the event
    pub fn with_request_context(
        mut self,
        session_id: Option<String>,
        source_ip: Option<String>,
        user_agent: Option<String>,
    ) -> Self {
        self.session_id = session_id;
        self.source_ip = source_ip;
        self.user_agent = user_agent;
        self
    }

    /// Add model context to the event
    pub fn with_model(mut self, model_id: String) -> Self {
        self.model_id = Some(model_id);
        self
    }

    /// Add additional details to the event
    pub fn with_detail<T: Serialize>(mut self, key: &str, value: T) -> Self {
        if let Ok(json_value) = serde_json::to_value(value) {
            self.details.insert(key.to_string(), json_value);
        }
        self
    }

    /// Mark the event as blocked/prevented
    pub fn blocked(mut self) -> Self {
        self.blocked = true;
        self
    }

    /// Add remediation action taken
    pub fn with_remediation(mut self, action: String) -> Self {
        self.remediation_taken.push(action);
        self
    }

    /// Get a formatted log message for this event
    pub fn log_message(&self) -> String {
        format!(
            "SECURITY_EVENT[{}]: {} - {} (severity: {:?}, blocked: {}) - {}",
            self.event_type.as_str(),
            self.endpoint,
            self.method,
            self.severity,
            self.blocked,
            self.message
        )
    }
}

impl SecurityEventType {
    /// Get string representation of event type
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnauthorizedAccess => "UNAUTHORIZED_ACCESS",
            Self::AuthenticationFailed => "AUTH_FAILED",
            Self::PrivilegeEscalation => "PRIVILEGE_ESCALATION",
            Self::PromptInjectionAttempt => "PROMPT_INJECTION",
            Self::JailbreakAttempt => "JAILBREAK",
            Self::SystemPromptBypass => "SYSTEM_BYPASS",
            Self::InstructionManipulation => "INSTRUCTION_MANIPULATION",
            Self::SensitiveDataLeakage => "DATA_LEAKAGE",
            Self::PiiExposureAttempt => "PII_EXPOSURE",
            Self::CredentialLeakage => "CREDENTIAL_LEAK",
            Self::InternalDataExposure => "INTERNAL_DATA_EXPOSURE",
            Self::UnsafeOutputGenerated => "UNSAFE_OUTPUT",
            Self::XssAttempt => "XSS_ATTEMPT",
            Self::SqlInjectionAttempt => "SQL_INJECTION",
            Self::CodeInjectionAttempt => "CODE_INJECTION",
            Self::SystemPromptLeakage => "SYSTEM_PROMPT_LEAK",
            Self::ConfigurationExposure => "CONFIG_EXPOSURE",
            Self::InternalRulesDisclosure => "RULES_DISCLOSURE",
            Self::RateLimitExceeded => "RATE_LIMIT",
            Self::ResourceExhaustion => "RESOURCE_EXHAUSTION",
            Self::DosAttempt => "DOS_ATTEMPT",
            Self::TokenLimitExceeded => "TOKEN_LIMIT",
            Self::ConcurrentRequestsExceeded => "CONCURRENT_LIMIT",
            Self::ModelTampering => "MODEL_TAMPERING",
            Self::ServerCompromise => "SERVER_COMPROMISE",
            Self::ModelDownloadFailed => "MODEL_DOWNLOAD_FAILED",
            Self::IntegrityCheckFailed => "INTEGRITY_FAILED",
            Self::EncryptionFailure => "ENCRYPTION_FAILURE",
            Self::DecryptionFailure => "DECRYPTION_FAILURE",
            Self::DekCompromise => "DEK_COMPROMISE",
            Self::DataExfiltration => "DATA_EXFILTRATION",
            Self::SuspiciousActivity => "SUSPICIOUS_ACTIVITY",
            Self::PolicyViolation => "POLICY_VIOLATION",
            Self::SecurityControlBypass => "CONTROL_BYPASS",
        }
    }

    /// Get default severity for this event type
    pub fn default_severity(&self) -> SecurityEventSeverity {
        match self {
            Self::UnauthorizedAccess => SecurityEventSeverity::High,
            Self::AuthenticationFailed => SecurityEventSeverity::Medium,
            Self::PrivilegeEscalation => SecurityEventSeverity::Critical,
            Self::PromptInjectionAttempt => SecurityEventSeverity::High,
            Self::JailbreakAttempt => SecurityEventSeverity::High,
            Self::SystemPromptBypass => SecurityEventSeverity::High,
            Self::InstructionManipulation => SecurityEventSeverity::Medium,
            Self::SensitiveDataLeakage => SecurityEventSeverity::Critical,
            Self::PiiExposureAttempt => SecurityEventSeverity::High,
            Self::CredentialLeakage => SecurityEventSeverity::Critical,
            Self::InternalDataExposure => SecurityEventSeverity::High,
            Self::UnsafeOutputGenerated => SecurityEventSeverity::Medium,
            Self::XssAttempt => SecurityEventSeverity::High,
            Self::SqlInjectionAttempt => SecurityEventSeverity::High,
            Self::CodeInjectionAttempt => SecurityEventSeverity::High,
            Self::SystemPromptLeakage => SecurityEventSeverity::High,
            Self::ConfigurationExposure => SecurityEventSeverity::Medium,
            Self::InternalRulesDisclosure => SecurityEventSeverity::Medium,
            Self::RateLimitExceeded => SecurityEventSeverity::Medium,
            Self::ResourceExhaustion => SecurityEventSeverity::High,
            Self::DosAttempt => SecurityEventSeverity::High,
            Self::TokenLimitExceeded => SecurityEventSeverity::Low,
            Self::ConcurrentRequestsExceeded => SecurityEventSeverity::Medium,
            Self::ModelTampering => SecurityEventSeverity::Critical,
            Self::ServerCompromise => SecurityEventSeverity::Critical,
            Self::ModelDownloadFailed => SecurityEventSeverity::Medium,
            Self::IntegrityCheckFailed => SecurityEventSeverity::High,
            Self::EncryptionFailure => SecurityEventSeverity::High,
            Self::DecryptionFailure => SecurityEventSeverity::High,
            Self::DekCompromise => SecurityEventSeverity::Critical,
            Self::DataExfiltration => SecurityEventSeverity::Critical,
            Self::SuspiciousActivity => SecurityEventSeverity::Medium,
            Self::PolicyViolation => SecurityEventSeverity::Low,
            Self::SecurityControlBypass => SecurityEventSeverity::High,
        }
    }
}

/// Security audit logger for LLM operations
#[derive(Debug)]
pub struct SecurityAuditLogger {
    events: Arc<RwLock<Vec<SecurityEvent>>>,
    max_events: usize,
    alerting_enabled: bool,
    alert_thresholds: HashMap<SecurityEventType, (u32, Duration)>, // (count, time_window)
    user_activity: Arc<RwLock<HashMap<Uuid, Vec<DateTime<Utc>>>>>, // Track user activity
}

impl SecurityAuditLogger {
    /// Create a new security audit logger
    pub fn new(max_events: usize) -> Self {
        let mut logger = Self {
            events: Arc::new(RwLock::new(Vec::with_capacity(max_events))),
            max_events,
            alerting_enabled: true,
            alert_thresholds: HashMap::new(),
            user_activity: Arc::new(RwLock::new(HashMap::new())),
        };
        
        // Set default alert thresholds
        logger.set_alert_threshold(SecurityEventType::PromptInjectionAttempt, 5, Duration::from_secs(300)); // 5 in 5 minutes
        logger.set_alert_threshold(SecurityEventType::RateLimitExceeded, 10, Duration::from_secs(600)); // 10 in 10 minutes
        logger.set_alert_threshold(SecurityEventType::UnauthorizedAccess, 3, Duration::from_secs(300)); // 3 in 5 minutes
        logger.set_alert_threshold(SecurityEventType::SensitiveDataLeakage, 1, Duration::from_secs(60)); // 1 in 1 minute
        
        logger
    }

    /// Set alert threshold for a specific event type
    pub fn set_alert_threshold(&mut self, event_type: SecurityEventType, count: u32, window: Duration) {
        self.alert_thresholds.insert(event_type, (count, window));
    }

    /// Log a security event
    pub fn log_event(&self, event: SecurityEvent) {
        let log_message = event.log_message();
        
        // Log with appropriate level based on severity
        match event.severity {
            SecurityEventSeverity::Info => info!("{}", log_message),
            SecurityEventSeverity::Low => info!("SECURITY: {}", log_message),
            SecurityEventSeverity::Medium => warn!("SECURITY: {}", log_message),
            SecurityEventSeverity::High => error!("SECURITY: {}", log_message),
            SecurityEventSeverity::Critical => error!("SECURITY CRITICAL: {}", log_message),
        }

        // Store the event
        if let Ok(mut events) = self.events.write() {
            events.push(event.clone());
            
            // Rotate events if we exceed max_events
            if events.len() > self.max_events {
                let events_len = events.len();
                events.drain(0..events_len - self.max_events);
            }
        }

        // Track user activity if user is present
        if let Some(user_id) = event.user_id {
            self.track_user_activity(user_id);
        }

        // Check for alert conditions
        if self.alerting_enabled {
            self.check_alert_conditions(&event);
        }
    }

    /// Track user activity for pattern detection
    fn track_user_activity(&self, user_id: Uuid) {
        if let Ok(mut activity) = self.user_activity.write() {
            let user_events = activity.entry(user_id).or_insert_with(Vec::new);
            user_events.push(Utc::now());
            
            // Keep only last hour of activity
            let one_hour_ago = Utc::now() - chrono::Duration::hours(1);
            user_events.retain(|&timestamp| timestamp > one_hour_ago);
        }
    }

    /// Check if event should trigger alerts
    fn check_alert_conditions(&self, event: &SecurityEvent) {
        if let Some((threshold_count, time_window)) = self.alert_thresholds.get(&event.event_type) {
            let since = Utc::now() - chrono::Duration::from_std(*time_window).unwrap_or_default();
            
            if let Ok(events) = self.events.read() {
                let matching_events = events
                    .iter()
                    .filter(|e| e.event_type == event.event_type && e.timestamp > since)
                    .count() as u32;

                if matching_events >= *threshold_count {
                    error!(
                        "SECURITY ALERT: {} events of type {} in the last {:?} (threshold: {})",
                        matching_events,
                        event.event_type.as_str(),
                        time_window,
                        threshold_count
                    );
                }
            }
        }
    }

    /// Get security events with filtering
    pub fn get_events(&self, filter: SecurityEventFilter) -> Vec<SecurityEvent> {
        if let Ok(events) = self.events.read() {
            events
                .iter()
                .filter(|event| filter.matches(event))
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get security metrics summary
    pub fn get_security_metrics(&self) -> SecurityMetrics {
        if let Ok(events) = self.events.read() {
            let mut metrics = SecurityMetrics::default();
            
            for event in events.iter() {
                metrics.total_events += 1;
                
                match event.severity {
                    SecurityEventSeverity::Info => metrics.info_events += 1,
                    SecurityEventSeverity::Low => metrics.low_severity += 1,
                    SecurityEventSeverity::Medium => metrics.medium_severity += 1,
                    SecurityEventSeverity::High => metrics.high_severity += 1,
                    SecurityEventSeverity::Critical => metrics.critical_events += 1,
                }
                
                if event.blocked {
                    metrics.blocked_events += 1;
                }
                
                // Count by event type
                *metrics.event_type_counts.entry(event.event_type.clone()).or_insert(0) += 1;
            }
            
            metrics
        } else {
            SecurityMetrics::default()
        }
    }

    /// Get suspicious user activity
    pub fn get_suspicious_users(&self, min_events: usize) -> Vec<(Uuid, usize)> {
        if let Ok(activity) = self.user_activity.read() {
            activity
                .iter()
                .filter_map(|(&user_id, events)| {
                    if events.len() >= min_events {
                        Some((user_id, events.len()))
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Clear old events beyond retention period
    pub fn cleanup_old_events(&self, retention_hours: i64) {
        if let Ok(mut events) = self.events.write() {
            let cutoff = Utc::now() - chrono::Duration::hours(retention_hours);
            events.retain(|event| event.timestamp > cutoff);
        }
    }
}

/// Filter for querying security events
#[derive(Debug, Default)]
pub struct SecurityEventFilter {
    pub event_types: Option<Vec<SecurityEventType>>,
    pub severity_min: Option<SecurityEventSeverity>,
    pub user_id: Option<Uuid>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub blocked_only: bool,
    pub limit: Option<usize>,
}

impl SecurityEventFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_event_types(mut self, types: Vec<SecurityEventType>) -> Self {
        self.event_types = Some(types);
        self
    }

    pub fn with_min_severity(mut self, severity: SecurityEventSeverity) -> Self {
        self.severity_min = Some(severity);
        self
    }

    pub fn with_user(mut self, user_id: Uuid) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn since(mut self, timestamp: DateTime<Utc>) -> Self {
        self.since = Some(timestamp);
        self
    }

    pub fn blocked_only(mut self) -> Self {
        self.blocked_only = true;
        self
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    fn matches(&self, event: &SecurityEvent) -> bool {
        if let Some(ref types) = self.event_types {
            if !types.contains(&event.event_type) {
                return false;
            }
        }

        if let Some(ref min_severity) = self.severity_min {
            if &event.severity < min_severity {
                return false;
            }
        }

        if let Some(user_id) = self.user_id {
            if event.user_id != Some(user_id) {
                return false;
            }
        }

        if let Some(since) = self.since {
            if event.timestamp < since {
                return false;
            }
        }

        if let Some(until) = self.until {
            if event.timestamp > until {
                return false;
            }
        }

        if self.blocked_only && !event.blocked {
            return false;
        }

        true
    }
}

/// Security metrics summary
#[derive(Debug, Default, Serialize)]
pub struct SecurityMetrics {
    pub total_events: u64,
    pub critical_events: u64,
    pub high_severity: u64,
    pub medium_severity: u64,
    pub low_severity: u64,
    pub info_events: u64,
    pub blocked_events: u64,
    pub event_type_counts: HashMap<SecurityEventType, u64>,
}

/// Convenience functions for logging common security events
impl SecurityAuditLogger {
    /// Log a prompt injection attempt
    pub fn log_prompt_injection(&self, user_id: Option<Uuid>, endpoint: &str, pattern: &str, blocked: bool) {
        let event = SecurityEvent::new(
            SecurityEventType::PromptInjectionAttempt,
            SecurityEventType::PromptInjectionAttempt.default_severity(),
            endpoint.to_string(),
            "POST".to_string(),
            format!("Prompt injection attempt detected: {}", pattern),
        )
        .with_detail("pattern", pattern)
        .with_detail("blocked", blocked);

        let event = if let Some(uid) = user_id {
            event.with_user(uid)
        } else {
            event
        };

        let event = if blocked { event.blocked() } else { event };

        self.log_event(event);
    }

    /// Log rate limit exceeded
    pub fn log_rate_limit_exceeded(&self, user_id: Uuid, endpoint: &str, limit: u32, current: u32) {
        let event = SecurityEvent::new(
            SecurityEventType::RateLimitExceeded,
            SecurityEventType::RateLimitExceeded.default_severity(),
            endpoint.to_string(),
            "POST".to_string(),
            format!("Rate limit exceeded: {}/{}", current, limit),
        )
        .with_user(user_id)
        .with_detail("limit", limit)
        .with_detail("current", current)
        .blocked();

        self.log_event(event);
    }

    /// Log sensitive data leakage
    pub fn log_sensitive_data_leak(&self, user_id: Option<Uuid>, endpoint: &str, data_type: &str) {
        let event = SecurityEvent::new(
            SecurityEventType::SensitiveDataLeakage,
            SecurityEventType::SensitiveDataLeakage.default_severity(),
            endpoint.to_string(),
            "POST".to_string(),
            format!("Sensitive data leakage detected: {}", data_type),
        )
        .with_detail("data_type", data_type)
        .blocked();

        let event = if let Some(uid) = user_id {
            event.with_user(uid)
        } else {
            event
        };

        self.log_event(event);
    }

    /// Log unauthorized access attempt
    pub fn log_unauthorized_access(&self, endpoint: &str, method: &str, ip: Option<String>) {
        let event = SecurityEvent::new(
            SecurityEventType::UnauthorizedAccess,
            SecurityEventType::UnauthorizedAccess.default_severity(),
            endpoint.to_string(),
            method.to_string(),
            "Unauthorized access attempt".to_string(),
        )
        .with_request_context(None, ip, None)
        .blocked();

        self.log_event(event);
    }
}

/// Convert SecurityError to audit event
impl From<SecurityError> for SecurityEvent {
    fn from(error: SecurityError) -> Self {
        let (event_type, message) = match &error {
            SecurityError::PromptInjection { pattern } => (
                SecurityEventType::PromptInjectionAttempt,
                format!("Prompt injection detected: {}", pattern),
            ),
            SecurityError::PromptTooLong { length, max_length } => (
                SecurityEventType::TokenLimitExceeded,
                format!("Prompt too long: {} > {}", length, max_length),
            ),
            SecurityError::OutputValidationFailed { reason } => (
                SecurityEventType::UnsafeOutputGenerated,
                format!("Output validation failed: {}", reason),
            ),
            SecurityError::ResourceLimitExceeded { resource, current, limit } => (
                SecurityEventType::ResourceExhaustion,
                format!("Resource limit exceeded: {} = {} > {}", resource, current, limit),
            ),
            SecurityError::RateLimitExceeded { user_id } => (
                SecurityEventType::RateLimitExceeded,
                format!("Rate limit exceeded for user: {}", user_id),
            ),
            SecurityError::SensitiveInfoLeakage => (
                SecurityEventType::SensitiveDataLeakage,
                "Sensitive information detected in output".to_string(),
            ),
            SecurityError::SystemPromptLeakage => (
                SecurityEventType::SystemPromptLeakage,
                "System prompt leakage attempt detected".to_string(),
            ),
        };

        SecurityEvent::new(
            event_type.clone(),
            event_type.default_severity(),
            "/api/llm".to_string(), // Default endpoint
            "POST".to_string(), // Default method
            message,
        )
        .blocked() // Security errors are typically blocked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_event_creation() {
        let event = SecurityEvent::new(
            SecurityEventType::PromptInjectionAttempt,
            SecurityEventSeverity::High,
            "/api/llm/test".to_string(),
            "POST".to_string(),
            "Test injection attempt".to_string(),
        );

        assert_eq!(event.event_type, SecurityEventType::PromptInjectionAttempt);
        assert_eq!(event.severity, SecurityEventSeverity::High);
        assert_eq!(event.endpoint, "/api/llm/test");
        assert!(!event.blocked);
    }

    #[test]
    fn test_security_audit_logger() {
        let logger = SecurityAuditLogger::new(1000);
        
        let event = SecurityEvent::new(
            SecurityEventType::PromptInjectionAttempt,
            SecurityEventSeverity::High,
            "/api/llm/test".to_string(),
            "POST".to_string(),
            "Test event".to_string(),
        );

        logger.log_event(event);
        
        let metrics = logger.get_security_metrics();
        assert_eq!(metrics.total_events, 1);
        assert_eq!(metrics.high_severity, 1);
    }

    #[test]
    fn test_event_filtering() {
        let logger = SecurityAuditLogger::new(1000);
        
        // Add events with different types
        logger.log_event(SecurityEvent::new(
            SecurityEventType::PromptInjectionAttempt,
            SecurityEventSeverity::High,
            "/api/llm/test".to_string(),
            "POST".to_string(),
            "Prompt injection".to_string(),
        ));
        
        logger.log_event(SecurityEvent::new(
            SecurityEventType::RateLimitExceeded,
            SecurityEventSeverity::Medium,
            "/api/llm/test".to_string(),
            "POST".to_string(),
            "Rate limit".to_string(),
        ));

        let filter = SecurityEventFilter::new()
            .with_event_types(vec![SecurityEventType::PromptInjectionAttempt]);
            
        let filtered_events = logger.get_events(filter);
        assert_eq!(filtered_events.len(), 1);
        assert_eq!(filtered_events[0].event_type, SecurityEventType::PromptInjectionAttempt);
    }
}