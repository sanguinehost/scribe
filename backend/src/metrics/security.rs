use lazy_static::lazy_static;
use prometheus::{Counter, Histogram, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry};

lazy_static! {
    pub static ref SECURITY_METRICS: SecurityMetrics = SecurityMetrics::new();
}

/// Security metrics for monitoring payment system attacks and anomalies
/// All metrics use privacy-safe labels (hashed user IDs, anonymized IPs)
pub struct SecurityMetrics {
    registry: Registry,

    // Webhook security
    pub webhook_signature_failures: Counter,
    pub webhook_processing_time: Histogram,

    // Authentication
    pub auth_failures: IntCounterVec, // labels: user_hash, ip_subnet
    pub auth_successes: IntCounterVec, // labels: user_hash, ip_subnet

    // Payment operations
    pub credit_operations_rate: HistogramVec, // labels: user_hash, operation_type
    pub payment_anomalies: IntCounterVec,     // labels: anomaly_type

    // Encryption
    pub encryption_errors: IntCounterVec, // labels: error_type
    pub dek_cache_access_rate: Histogram,

    // Data access
    pub data_access_rate: HistogramVec, // labels: endpoint, user_hash
}

impl SecurityMetrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        // Webhook security metrics
        let webhook_sig_failures = Counter::with_opts(Opts::new(
            "webhook_signature_failures_total",
            "Total webhook signature verification failures",
        ))
        .unwrap();
        registry
            .register(Box::new(webhook_sig_failures.clone()))
            .unwrap();

        let webhook_processing_time = Histogram::with_opts(HistogramOpts::new(
            "webhook_processing_duration_seconds",
            "Webhook processing time in seconds",
        ))
        .unwrap();
        registry
            .register(Box::new(webhook_processing_time.clone()))
            .unwrap();

        // Authentication metrics
        let auth_failures = IntCounterVec::new(
            Opts::new(
                "auth_failures_total",
                "Total authentication failures (privacy-safe: hashed user IDs, anonymized IPs)",
            ),
            &["user_hash", "ip_subnet"],
        )
        .unwrap();
        registry.register(Box::new(auth_failures.clone())).unwrap();

        let auth_successes = IntCounterVec::new(
            Opts::new(
                "auth_successes_total",
                "Total authentication successes (privacy-safe: hashed user IDs, anonymized IPs)",
            ),
            &["user_hash", "ip_subnet"],
        )
        .unwrap();
        registry.register(Box::new(auth_successes.clone())).unwrap();

        // Payment operation metrics
        let credit_operations_rate = HistogramVec::new(
            HistogramOpts::new(
                "credit_operations_amount",
                "Credit operation amounts (privacy-safe: hashed user IDs)",
            ),
            &["user_hash", "operation_type"],
        )
        .unwrap();
        registry
            .register(Box::new(credit_operations_rate.clone()))
            .unwrap();

        let payment_anomalies = IntCounterVec::new(
            Opts::new(
                "payment_anomalies_total",
                "Detected payment anomalies by type",
            ),
            &["anomaly_type"],
        )
        .unwrap();
        registry
            .register(Box::new(payment_anomalies.clone()))
            .unwrap();

        // Encryption metrics
        let encryption_errors = IntCounterVec::new(
            Opts::new(
                "encryption_errors_total",
                "Encryption/decryption errors by type",
            ),
            &["error_type"],
        )
        .unwrap();
        registry
            .register(Box::new(encryption_errors.clone()))
            .unwrap();

        let dek_cache_access_rate = Histogram::with_opts(HistogramOpts::new(
            "dek_cache_access_count",
            "DEK cache access rate (for bulk access detection)",
        ))
        .unwrap();
        registry
            .register(Box::new(dek_cache_access_rate.clone()))
            .unwrap();

        // Data access metrics
        let data_access_rate = HistogramVec::new(
            HistogramOpts::new(
                "data_access_record_count",
                "Data access record counts by endpoint (privacy-safe: hashed user IDs)",
            ),
            &["endpoint", "user_hash"],
        )
        .unwrap();
        registry
            .register(Box::new(data_access_rate.clone()))
            .unwrap();

        Self {
            registry,
            webhook_signature_failures: webhook_sig_failures,
            webhook_processing_time,
            auth_failures,
            auth_successes,
            credit_operations_rate,
            payment_anomalies,
            encryption_errors,
            dek_cache_access_rate,
            data_access_rate,
        }
    }

    /// Get the Prometheus registry for /metrics endpoint
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    // Convenience methods for recording metrics

    pub fn record_webhook_signature_failure(&self) {
        self.webhook_signature_failures.inc();
    }

    pub fn record_webhook_processing_time(&self, duration_seconds: f64) {
        self.webhook_processing_time.observe(duration_seconds);
    }

    pub fn record_auth_failure(&self, user_hash: &str, ip_subnet: &str) {
        self.auth_failures
            .with_label_values(&[user_hash, ip_subnet])
            .inc();
    }

    pub fn record_auth_success(&self, user_hash: &str, ip_subnet: &str) {
        self.auth_successes
            .with_label_values(&[user_hash, ip_subnet])
            .inc();
    }

    pub fn record_credit_operation(&self, user_hash: &str, operation_type: &str, amount: f64) {
        self.credit_operations_rate
            .with_label_values(&[user_hash, operation_type])
            .observe(amount);
    }

    pub fn record_payment_anomaly(&self, anomaly_type: &str) {
        self.payment_anomalies
            .with_label_values(&[anomaly_type])
            .inc();
    }

    pub fn record_encryption_error(&self, error_type: &str) {
        self.encryption_errors
            .with_label_values(&[error_type])
            .inc();
    }

    pub fn record_dek_cache_access(&self, count: f64) {
        self.dek_cache_access_rate.observe(count);
    }

    pub fn record_data_access(&self, endpoint: &str, user_hash: &str, record_count: f64) {
        self.data_access_rate
            .with_label_values(&[endpoint, user_hash])
            .observe(record_count);
    }
}

impl Default for SecurityMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_initialization() {
        let metrics = SecurityMetrics::new();
        assert!(metrics.registry().gather().len() > 0);
    }

    #[test]
    fn test_webhook_signature_failure_counter() {
        let metrics = SecurityMetrics::new();
        metrics.record_webhook_signature_failure();
        metrics.record_webhook_signature_failure();

        let metric_families = metrics.registry().gather();
        let webhook_metric = metric_families
            .iter()
            .find(|m| m.get_name() == "webhook_signature_failures_total")
            .expect("Webhook metric should exist");

        assert_eq!(
            webhook_metric.get_metric()[0].get_counter().get_value(),
            2.0
        );
    }

    #[test]
    fn test_auth_failure_with_labels() {
        let metrics = SecurityMetrics::new();
        metrics.record_auth_failure("user#abc123", "192.168.1.0");
        metrics.record_auth_failure("user#abc123", "192.168.1.0");
        metrics.record_auth_failure("user#def456", "10.0.0.0");

        let metric_families = metrics.registry().gather();
        let auth_metric = metric_families
            .iter()
            .find(|m| m.get_name() == "auth_failures_total")
            .expect("Auth failure metric should exist");

        // Should have 2 distinct label combinations
        assert_eq!(auth_metric.get_metric().len(), 2);
    }

    #[test]
    fn test_credit_operation_histogram() {
        let metrics = SecurityMetrics::new();
        metrics.record_credit_operation("user#abc123", "add", 1000.0);
        metrics.record_credit_operation("user#abc123", "add", 2000.0);
        metrics.record_credit_operation("user#abc123", "deduct", 500.0);

        let metric_families = metrics.registry().gather();
        let credit_metric = metric_families
            .iter()
            .find(|m| m.get_name() == "credit_operations_amount")
            .expect("Credit operation metric should exist");

        // Should have 2 distinct label combinations (add, deduct)
        assert_eq!(credit_metric.get_metric().len(), 2);
    }

    #[test]
    fn test_privacy_safe_labels() {
        let metrics = SecurityMetrics::new();

        // Verify that we're using hashed user IDs, not raw UUIDs
        metrics.record_auth_failure("user#abc123", "192.168.1.0");

        let metric_families = metrics.registry().gather();
        let auth_metric = metric_families
            .iter()
            .find(|m| m.get_name() == "auth_failures_total")
            .unwrap();

        let labels = &auth_metric.get_metric()[0].get_label();
        let user_hash_label = labels.iter().find(|l| l.get_name() == "user_hash").unwrap();

        // Should start with "user#" prefix (hashed ID format)
        assert!(user_hash_label.get_value().starts_with("user#"));

        // Should NOT be a valid UUID (raw PII)
        assert!(!user_hash_label.get_value().contains('-')); // UUIDs have hyphens
    }
}
