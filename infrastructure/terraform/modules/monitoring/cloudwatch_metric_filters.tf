# CloudWatch Log Metric Filters for Security Events
# Parse structured security events logged by the backend (from Task 9)
# All metrics use privacy-safe labels (hashed user IDs, anonymized IPs)

# Metric Filter 1: Webhook Signature Failures
# Detects potential webhook replay/spoofing attacks
resource "aws_cloudwatch_log_metric_filter" "webhook_signature_failure" {
  name           = "${var.environment}-webhook-signature-failures"
  log_group_name = var.backend_log_group_name

  # JSON filter pattern for webhook_signature_failure events
  pattern = "{ $.event_type = \"webhook_signature_failure\" }"

  metric_transformation {
    name      = "WebhookSignatureFailureCount"
    namespace = "Scribe/Security"
    value     = "1"
    unit      = "Count"
  }
}

# Metric Filter 2: Authentication Failures
# Detects credential stuffing, brute force, account takeover attempts
resource "aws_cloudwatch_log_metric_filter" "auth_failure" {
  name           = "${var.environment}-auth-failures"
  log_group_name = var.backend_log_group_name

  # JSON filter pattern for auth_failure events
  pattern = "{ $.event_type = \"auth_failure\" }"

  metric_transformation {
    name      = "AuthFailureCount"
    namespace = "Scribe/Security"
    value     = "1"
    unit      = "Count"
  }
}

# Metric Filter 3: Credit Anomalies
# Detects payment fraud, credit manipulation, promo code abuse
resource "aws_cloudwatch_log_metric_filter" "credit_anomaly" {
  name           = "${var.environment}-credit-anomalies"
  log_group_name = var.backend_log_group_name

  # JSON filter pattern for credit_anomaly events
  pattern = "{ $.event_type = \"credit_anomaly\" }"

  metric_transformation {
    name      = "CreditAnomalyCount"
    namespace = "Scribe/Security"
    value     = "1"
    unit      = "Count"
  }
}

# Metric Filter 4: Encryption Errors
# Detects encryption/decryption failures, potential key compromise
resource "aws_cloudwatch_log_metric_filter" "encryption_error" {
  name           = "${var.environment}-encryption-errors"
  log_group_name = var.backend_log_group_name

  # JSON filter pattern for encryption_error events
  pattern = "{ $.event_type = \"encryption_error\" }"

  metric_transformation {
    name      = "EncryptionErrorCount"
    namespace = "Scribe/Security"
    value     = "1"
    unit      = "Count"
  }
}

# Metric Filter 5: Data Exfiltration Attempts
# Detects bulk data access, API scraping, unauthorized data access
resource "aws_cloudwatch_log_metric_filter" "data_exfiltration" {
  name           = "${var.environment}-data-exfiltration-attempts"
  log_group_name = var.backend_log_group_name

  # JSON filter pattern for data_exfiltration events
  pattern = "{ $.event_type = \"data_exfiltration\" }"

  metric_transformation {
    name      = "DataExfiltrationCount"
    namespace = "Scribe/Security"
    value     = "1"
    unit      = "Count"
  }
}

# Metric Filter 6: DEK Scraping Attempts
# Detects bulk DEK cache access attempts (encryption key scraping)
resource "aws_cloudwatch_log_metric_filter" "dek_scraping_attempt" {
  name           = "${var.environment}-dek-scraping-attempts"
  log_group_name = var.backend_log_group_name

  # JSON filter pattern for dek_scraping_attempt events
  pattern = "{ $.event_type = \"dek_scraping_attempt\" }"

  metric_transformation {
    name      = "DekScrapingAttemptCount"
    namespace = "Scribe/Security"
    value     = "1"
    unit      = "Count"
  }
}

# Metric Filter 7: Replay Attacks
# Detects webhook replay attacks (duplicate transaction IDs)
resource "aws_cloudwatch_log_metric_filter" "replay_attack" {
  name           = "${var.environment}-replay-attacks"
  log_group_name = var.backend_log_group_name

  # JSON filter pattern for replay_attack events
  pattern = "{ $.event_type = \"replay_attack\" }"

  metric_transformation {
    name      = "ReplayAttackCount"
    namespace = "Scribe/Security"
    value     = "1"
    unit      = "Count"
  }
}

# Metric Filter 8: High-Rate Credit Operations
# Track volume of credit operations for fraud detection
resource "aws_cloudwatch_log_metric_filter" "credit_operation_rate" {
  name           = "${var.environment}-credit-operation-rate"
  log_group_name = var.backend_log_group_name

  # Pattern matches any log with credit operation (add/deduct)
  # We're looking for high frequency, not specific events
  pattern = "[time, request_id, level=INFO, message=\"Recording credit operation*\"]"

  metric_transformation {
    name      = "CreditOperationRate"
    namespace = "Scribe/Security"
    value     = "1"
    unit      = "Count"
  }
}

# Metric Filter 9: Webhook Processing Time (for DDoS detection)
# Track webhook processing duration to detect flooding attacks
resource "aws_cloudwatch_log_metric_filter" "webhook_processing_time" {
  name           = "${var.environment}-webhook-processing-time"
  log_group_name = var.backend_log_group_name

  # Match log lines that contain webhook processing duration
  pattern = "[time, request_id, level, message=\"Webhook processed*\", duration_ms]"

  metric_transformation {
    name      = "WebhookProcessingDuration"
    namespace = "Scribe/Security"
    value     = "$duration_ms"
    unit      = "Milliseconds"
    default_value = 0
  }
}
