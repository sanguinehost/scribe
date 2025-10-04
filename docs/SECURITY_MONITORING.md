# Security Monitoring & Incident Response Architecture

**Status:** 🟢 IMPLEMENTATION READY
**Created:** 2025-10-04
**Branch:** `feat/payment-system-deployment`
**Related:** [OWASP TOP-10](./OWASP-TOP-10.md), [Privacy Safe Logging](./PRIVACY_SAFE_LOGGING.md), [Encryption Architecture](./ENCRYPTION_ARCHITECTURE.md)

---

## Executive Summary

This document defines the comprehensive security monitoring and incident response architecture for Sanguine Scribe's payment system. The architecture is designed to detect and respond to Advanced Persistent Threats (APTs) and state-level actors while maintaining strict privacy compliance—**no PII or PCI data is logged**.

**Key Capabilities:**
- **APT Detection**: Behavioral analytics, correlation rules, threat intelligence integration
- **Privacy-Preserving**: Hashed user IDs, anonymized IPs, aggregated metrics only
- **Multi-SIEM Support**: AWS CloudWatch (default), Datadog, Splunk, ELK Stack
- **Automated Response**: Runbooks for containment, recovery, and forensics
- **Compliance**: OWASP A09, PCI DSS Requirement 10, GDPR Article 32

**Mean Time To Detect (MTTD):** <5 minutes for critical incidents (P0)
**Mean Time To Respond (MTTR):** <30 minutes for critical incidents (P0)

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Layer 1: Application Instrumentation](#layer-1-application-instrumentation)
3. [Layer 2: AWS Infrastructure](#layer-2-aws-infrastructure)
4. [Layer 3: SIEM Integration](#layer-3-siem-integration)
5. [Layer 4: APT Detection](#layer-4-apt-detection)
6. [Privacy Compliance](#privacy-compliance)
7. [Alert Taxonomy & SLAs](#alert-taxonomy--slas)
8. [Critical Security Events](#critical-security-events)
9. [Baseline Calibration](#baseline-calibration)
10. [Incident Response Integration](#incident-response-integration)
11. [Implementation Roadmap](#implementation-roadmap)
12. [Success Metrics](#success-metrics)

---

## Architecture Overview

### Four-Layer Defense-in-Depth

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 4: APT Detection & Response                              │
│ - Behavioral baselines                                          │
│ - Correlation rules (attack patterns)                           │
│ - Automated incident playbooks                                  │
└────────────────────┬────────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────────┐
│ Layer 3: Multi-SIEM Integration                                 │
│ - Datadog (Lambda Forwarder)                                    │
│ - Splunk (HTTP Event Collector)                                 │
│ - ELK (S3 → Filebeat)                                           │
│ - Generic (S3-based ingestion)                                  │
└────────────────────┬────────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────────┐
│ Layer 2: AWS Infrastructure (Default Platform)                  │
│ - CloudWatch Logs (JSON aggregation)                            │
│ - Kinesis Data Firehose (universal SIEM integration)            │
│ - CloudWatch Metrics + Alarms (threshold-based)                 │
│ - GuardDuty (threat intelligence)                               │
│ - Security Hub (compliance dashboards)                          │
└────────────────────┬────────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────────┐
│ Layer 1: Application Instrumentation (Rust/Axum)                │
│ - Structured JSON logging (tracing-subscriber)                  │
│ - Security metrics (Prometheus/CloudWatch)                      │
│ - Privacy-safe event logging (hashed IDs only)                  │
│ - Correlation IDs (distributed tracing)                         │
└─────────────────────────────────────────────────────────────────┘
```

### Design Principles

1. **Privacy First**: No PII/PCI data in logs (GDPR Article 32, PCI DSS SAQ-A)
2. **Defense in Depth**: Multiple detection layers with overlapping coverage
3. **Actionable Alerts**: Low false positive rate (<5%), high signal-to-noise
4. **Automation**: Runbooks for common scenarios, reducing MTTR
5. **Vendor Neutrality**: Multi-SIEM support via standardized log formats
6. **Compliance**: OWASP A09, PCI DSS Requirement 10, AWS FS-ISAC recommendations

---

## Layer 1: Application Instrumentation

### Structured Logging

**Technology Stack:**
- `tracing` crate for structured logging
- `tracing-subscriber` with JSON formatter
- `serde_json` for log serialization
- Existing `privacy` module for PII redaction

**Log Format** (JSON):
```json
{
  "timestamp": "2025-10-04T12:34:56.789Z",
  "level": "WARN",
  "target": "scribe_backend::routes::payment",
  "fields": {
    "event": "webhook_signature_failure",
    "correlation_id": "req_abc123",
    "source_ip_anonymized": "203.0.113.0",
    "event_id": "evt_01k6xyz",
    "error_type": "invalid_signature"
  },
  "span": {
    "name": "paddle_webhook_handler"
  }
}
```

**Key Fields (All Privacy-Safe):**
- `correlation_id`: Request tracking across services (UUID v4)
- `hashed_user_id`: One-way hash of user ID (existing `loggable_user_id()`)
- `source_ip_anonymized`: Last octet masked (e.g., `192.168.1.0`)
- `event`: Structured event name (for metric filters)
- `severity`: Security severity (info, warning, critical)
- `span`: Distributed tracing context

### Security Metrics

**Custom Metrics** (Prometheus/CloudWatch):

| Metric Name | Type | Description | Privacy Status |
|-------------|------|-------------|----------------|
| `webhook_signature_failures_total` | Counter | Webhook signature verification failures | ✅ No PII |
| `auth_failures_total` | Counter | Failed authentication attempts (by hashed user ID) | ✅ Hashed IDs only |
| `credit_operations_rate` | Histogram | Credit operations per minute (by hashed user ID) | ✅ Hashed IDs only |
| `encryption_errors_total` | Counter | Decryption/encryption failures | ✅ No PII |
| `unusual_ip_access_total` | Counter | Access from unexpected geographic regions | ✅ Anonymized IPs |
| `database_query_latency` | Histogram | Database query response times | ✅ No PII |
| `webhook_processing_duration` | Histogram | Time to process webhooks | ✅ No PII |

**Implementation Module**: `backend/src/metrics/security.rs`

```rust
use prometheus::{Counter, Histogram, Registry};

pub struct SecurityMetrics {
    webhook_signature_failures: Counter,
    auth_failures: Counter,
    credit_operations_rate: Histogram,
    encryption_errors: Counter,
    unusual_ip_access: Counter,
}

impl SecurityMetrics {
    pub fn new(registry: &Registry) -> Self {
        // Metric initialization with privacy-safe labels
    }

    pub fn record_webhook_signature_failure(&self, source_ip_anonymized: &str) {
        self.webhook_signature_failures.inc();
        // Log structured event for CloudWatch
    }
}
```

### Security Event Logging

**Event Categories** (all privacy-safe):

1. **Webhook Events**
   - `webhook_signature_failure`: Signature verification failed
   - `webhook_replay_detected`: Duplicate event_id within time window
   - `webhook_processing_error`: Server error during processing
   - `webhook_unknown_event_type`: Unknown Paddle event type
   - `webhook_rate_limit_exceeded`: Too many requests from source

2. **Authentication Events**
   - `auth_failure`: Failed login attempt
   - `auth_lockout`: Account temporarily locked (too many failures)
   - `auth_unusual_location`: Login from unexpected geographic location
   - `auth_impossible_travel`: Same user, different countries within minutes
   - `session_hijack_suspected`: Session token anomaly

3. **Payment Events**
   - `payment_anomaly_detected`: Unusual credit operation pattern
   - `payment_fraud_pattern`: High-confidence fraud indicators
   - `payment_geographic_impossibility`: Conflicting transaction locations
   - `payment_high_velocity`: 100+ operations in short window

4. **Encryption Events**
   - `encryption_failure`: Failed to encrypt data
   - `decryption_failure`: Failed to decrypt data
   - `nonce_reuse_detected`: Critical cryptographic failure
   - `dek_cache_miss`: DEK not found in cache (unusual)

5. **System Events**
   - `lateral_movement_detected`: Unusual service-to-service access
   - `privilege_escalation_attempt`: IAM policy violation
   - `bulk_data_access`: Large query result set (>1000 records)
   - `off_hours_access`: Access outside normal business hours

**Implementation Module**: `backend/src/logging/security_events.rs`

```rust
use serde::Serialize;
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum SecurityEvent {
    WebhookSignatureFailure {
        source_ip_anonymized: String,
        event_id: String,
        error_detail: String,
    },
    AuthenticationFailure {
        hashed_user_id: String,
        attempt_count: u32,
        source_ip_anonymized: String,
    },
    PaymentAnomalyDetected {
        hashed_user_id: String,
        pattern_type: String,
        severity: String,
        operation_count: u32,
    },
    EncryptionServiceError {
        error_type: String,
        affected_operations: u32,
    },
    LateralMovementDetected {
        source_service: String,
        target_service: String,
        unusual_pattern: String,
    },
}

impl SecurityEvent {
    pub fn log(&self) {
        // Log via tracing with structured fields
        tracing::warn!(
            event = serde_json::to_string(self).unwrap(),
            "Security event detected"
        );
    }
}
```

### IP Anonymization

**Privacy Compliance** (GDPR Article 32):

IP addresses are considered PII under GDPR. To preserve security utility while maintaining privacy:

- **IPv4**: Mask last octet (e.g., `192.168.1.234` → `192.168.1.0`)
- **IPv6**: Mask last 64 bits (e.g., `2001:0db8::1234` → `2001:0db8::0000`)
- **Benefit**: Preserves subnet information for distributed attack detection
- **Limitation**: Cannot identify specific user, but can identify attacking networks

**Implementation**:

```rust
// backend/src/privacy/ip_anonymization.rs

pub fn anonymize_ip(ip: &str) -> String {
    if ip.contains('.') {
        // IPv4
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() == 4 {
            format!("{}.{}.{}.0", parts[0], parts[1], parts[2])
        } else {
            "unknown".to_string()
        }
    } else if ip.contains(':') {
        // IPv6 - mask last 64 bits
        let parts: Vec<&str> = ip.split("::").collect();
        if !parts.is_empty() {
            format!("{}::0000", parts[0])
        } else {
            "unknown".to_string()
        }
    } else {
        "unknown".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_anonymization() {
        assert_eq!(anonymize_ip("192.168.1.234"), "192.168.1.0");
        assert_eq!(anonymize_ip("203.0.113.45"), "203.0.113.0");
    }

    #[test]
    fn test_ipv6_anonymization() {
        assert_eq!(anonymize_ip("2001:0db8::1234"), "2001:0db8::0000");
    }
}
```

---

## Layer 2: AWS Infrastructure

### CloudWatch Logs

**Log Groups** (organized by component):

| Log Group | Purpose | Retention |
|-----------|---------|-----------|
| `/aws/scribe/payment` | Payment webhook processing, credit operations | 90 days |
| `/aws/scribe/auth` | Authentication, session management | 90 days |
| `/aws/scribe/security` | Security events, audit logs | 1 year |
| `/aws/scribe/application` | General application logs | 30 days |

**Log Stream Naming**: `{instance_id}/{container_id}/{date}`

**JSON Parsing**: Automatically parsed by CloudWatch Logs Insights

### Kinesis Data Firehose

**Universal SIEM Integration Point**:

```
CloudWatch Logs → Kinesis Data Firehose → Multiple Destinations
                                        ├─> S3 (archive)
                                        ├─> Datadog (via Lambda)
                                        ├─> Splunk (via HEC)
                                        └─> Generic SIEM (via S3 polling)
```

**Configuration** (Terraform):

```hcl
resource "aws_kinesis_firehose_delivery_stream" "security_logs" {
  name        = "scribe-security-logs"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose.arn
    bucket_arn = aws_s3_bucket.security_logs.arn
    prefix     = "logs/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/hour=!{timestamp:HH}/"

    # Buffering: 5MB or 60 seconds (cost-optimized)
    buffer_size     = 5
    buffer_interval = 60

    # GZIP compression (reduces costs by 70-90%)
    compression_format = "GZIP"

    # CloudWatch error logging
    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = "/aws/kinesisfirehose/scribe-security"
      log_stream_name = "S3Delivery"
    }
  }
}
```

**Key Benefits**:
- **Cost-Effective**: Batch delivery reduces API calls
- **Reliable**: Automatic retries, dead-letter queue for failures
- **Flexible**: Single source, multiple destinations
- **Scalable**: Handles 1000+ MB/sec throughput

### CloudWatch Metric Filters

**Purpose**: Extract security metrics from JSON logs for real-time alerting

**Example Filter** (Webhook Signature Failures):

```hcl
resource "aws_cloudwatch_log_metric_filter" "webhook_sig_failure" {
  name           = "WebhookSignatureFailures"
  log_group_name = "/aws/scribe/payment"

  # JSON filter pattern
  pattern = "{ $.event = \"webhook_signature_failure\" }"

  metric_transformation {
    name      = "WebhookSignatureFailureCount"
    namespace = "Scribe/Security"
    value     = "1"
    dimensions = {
      SourceIP = "$.source_ip_anonymized"
    }
  }
}
```

**Common Filter Patterns**:

| Event | Filter Pattern |
|-------|----------------|
| Webhook signature failure | `{ $.event = "webhook_signature_failure" }` |
| Authentication failure | `{ $.event = "auth_failure" }` |
| Payment anomaly | `{ $.event = "payment_anomaly_detected" && $.severity = "high" }` |
| Encryption error | `{ $.event = "encryption_failure" OR $.event = "decryption_failure" }` |
| Lateral movement | `{ $.event = "lateral_movement_detected" }` |

### CloudWatch Alarms

**Threshold-Based Alerting** (after baseline calibration):

```hcl
resource "aws_cloudwatch_metric_alarm" "webhook_attack" {
  alarm_name          = "P1-WebhookAttackDetected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "WebhookSignatureFailureCount"
  namespace           = "Scribe/Security"
  period              = "300" # 5 minutes
  statistic           = "Sum"
  threshold           = "5" # 5+ failures in 5 min

  alarm_description = "Possible webhook replay/spoofing attack - 5+ signature failures in 5 minutes"
  alarm_actions     = [aws_sns_topic.security_alerts_p1.arn]

  dimensions = {
    SourceIP = "*" # Alert on any source IP
  }
}
```

**Composite Alarms** (correlation rules):

```hcl
resource "aws_cloudwatch_metric_alarm" "credential_stuffing" {
  alarm_name = "P1-CredentialStuffingDetected"

  # Correlation: auth failures + unusual IP + high rate
  alarm_rule = "ALARM(auth_failures_high) AND ALARM(unusual_ip_activity)"

  alarm_actions = [aws_sns_topic.security_alerts_p1.arn]
}
```

### AWS GuardDuty

**Threat Intelligence Integration**:

- **Malicious IP Detection**: Identifies requests from known bad actors
- **Compromised Instance Detection**: Unusual outbound traffic, crypto mining
- **IAM Privilege Escalation**: Detects unauthorized permission changes
- **Data Exfiltration**: Large data transfers to unusual destinations

**Configuration**:
- Enable for all AWS accounts (production, staging, development)
- Integrate findings with Security Hub
- Route HIGH/CRITICAL findings to SNS → PagerDuty

### AWS Security Hub

**Compliance Dashboards**:

- **PCI DSS v4.0**: Automated compliance checks
- **AWS Foundational Security Best Practices**: 50+ security checks
- **OWASP Top 10**: Custom security standards

**Integration**:
- Aggregates findings from GuardDuty, Inspector, Config
- Automated remediation via EventBridge → Lambda
- Weekly compliance reports to security team

---

## Layer 3: SIEM Integration

### Architecture Pattern

```
┌─────────────────────────────────────────────────────────────┐
│ CloudWatch Logs (JSON format)                               │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ Kinesis Data Firehose (buffering + compression)             │
└─────┬──────┬──────┬──────────────────────────────────────────┘
      │      │      │
      ▼      ▼      ▼
   ┌────┐ ┌────┐ ┌────┐ ┌────────┐
   │ S3 │ │ DD │ │ SP │ │ Custom │
   └────┘ └────┘ └────┘ └────────┘
   Archive Datadog Splunk  SIEM
```

### Datadog Integration

**Method**: Kinesis Data Firehose → Lambda Forwarder → Datadog

**Configuration** (Terraform):

```hcl
resource "aws_lambda_function" "datadog_forwarder" {
  function_name = "datadog-forwarder"
  role          = aws_iam_role.datadog_lambda.arn
  runtime       = "python3.11"
  handler       = "lambda_function.handler"

  # Datadog Forwarder from AWS Serverless Application Repository
  # https://github.com/DataDog/datadog-serverless-functions/tree/master/aws/logs_monitoring

  environment {
    variables = {
      DD_API_KEY = data.aws_secretsmanager_secret_version.datadog_api_key.secret_string
      DD_SITE    = "datadoghq.com"
      DD_TAGS    = "env:production,service:scribe-payment"
    }
  }
}

# Subscribe Lambda to Kinesis Firehose delivery failures
resource "aws_cloudwatch_log_subscription_filter" "datadog" {
  name            = "datadog-logs"
  log_group_name  = "/aws/scribe/security"
  filter_pattern  = "" # All logs
  destination_arn = aws_lambda_function.datadog_forwarder.arn
}
```

**Custom Metrics Mapping**:

| CloudWatch Metric | Datadog Metric | Dashboard Widget |
|-------------------|----------------|------------------|
| `WebhookSignatureFailureCount` | `scribe.security.webhook_signature_failures` | Timeseries, Anomaly Detection |
| `AuthFailureCount` | `scribe.security.auth_failures` | Heatmap (by geographic region) |
| `CreditOperationsRate` | `scribe.payment.credit_operations` | Distribution, P99 latency |

### Splunk Integration

**Method**: Kinesis Data Firehose → Splunk HTTP Event Collector (HEC)

**Configuration**:

```hcl
resource "aws_kinesis_firehose_delivery_stream" "splunk" {
  name        = "scribe-security-splunk"
  destination = "splunk"

  splunk_configuration {
    hec_endpoint               = "https://splunk.example.com:8088"
    hec_token                  = data.aws_secretsmanager_secret_version.splunk_hec_token.secret_string
    hec_acknowledgment_timeout = 180
    retry_duration             = 300

    s3_backup_mode = "FailedEventsOnly"
    s3_configuration {
      role_arn   = aws_iam_role.firehose.arn
      bucket_arn = aws_s3_bucket.splunk_failures.arn
    }
  }
}
```

**Splunk Search Queries** (SOC team):

```spl
# Detect credential stuffing attacks
index=scribe sourcetype=security event="auth_failure"
| stats count by source_ip_anonymized
| where count > 10
| join source_ip_anonymized [search index=scribe event="unusual_ip_access"]

# Webhook attack detection
index=scribe sourcetype=payment event="webhook_signature_failure"
| timechart span=5m count by source_ip_anonymized

# Payment fraud patterns
index=scribe sourcetype=payment event="payment_anomaly_detected"
| stats count, values(pattern_type) by hashed_user_id
| where count > 5
```

### ELK Stack Integration

**Method**: Kinesis Data Firehose → S3 → Filebeat → Logstash → Elasticsearch

**Architecture**:

```
Kinesis → S3 (logs/year=2025/month=10/...)
            ↓
        Filebeat (S3 input plugin)
            ↓
        Logstash (JSON parsing, enrichment)
            ↓
        Elasticsearch (indexing)
            ↓
        Kibana (visualization)
```

**Filebeat Configuration** (`filebeat.yml`):

```yaml
filebeat.inputs:
  - type: aws-s3
    queue_url: https://sqs.us-east-1.amazonaws.com/123456789012/scribe-logs
    credential_profile_name: default
    expand_event_list_from_field: Records

processors:
  - decode_json_fields:
      fields: ["message"]
      target: ""
      overwrite_keys: true

output.logstash:
  hosts: ["logstash.example.com:5044"]
  ssl.enabled: true
```

**Logstash Pipeline** (`logstash.conf`):

```ruby
input {
  beats {
    port => 5044
    ssl => true
  }
}

filter {
  json {
    source => "message"
  }

  # Enrich with GeoIP (on anonymized IPs)
  geoip {
    source => "source_ip_anonymized"
    target => "geoip"
    database => "/usr/share/GeoIP/GeoLite2-City.mmdb"
  }

  # Add security severity field
  if [event] in ["webhook_signature_failure", "encryption_failure", "lateral_movement_detected"] {
    mutate {
      add_field => { "security_severity" => "critical" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["https://elasticsearch.example.com:9200"]
    index => "scribe-security-%{+YYYY.MM.dd}"
  }
}
```

### Generic S3-Based Integration

**For SIEMs without native AWS support**:

1. **Export Format**: GZIP-compressed JSONL (JSON Lines)
2. **Partition Strategy**: `s3://logs/year=YYYY/month=MM/day=DD/hour=HH/`
3. **Polling**: SIEM polls S3 bucket every 5 minutes for new files
4. **Lifecycle**: 7 days HOT, 90 days WARM, 1 year COLD, then Glacier

**S3 Bucket Policy** (read-only for SIEM):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::SIEM_ACCOUNT_ID:role/SIEMIngestionRole"
    },
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": [
      "arn:aws:s3:::scribe-security-logs",
      "arn:aws:s3:::scribe-security-logs/*"
    ]
  }]
}
```

---

## Layer 4: APT Detection

### Behavioral Baselining

**Process** (7-14 day calibration period):

1. **Deploy instrumented application** with structured logging
2. **Collect baseline metrics** (mean, stddev, p99) for all security events
3. **Analyze normal patterns** using CloudWatch Logs Insights
4. **Calculate thresholds** (mean + 3σ, or 2x baseline average)
5. **Enable CloudWatch Alarms** with calibrated thresholds
6. **Continuous tuning** based on false positive rates

**Baseline Queries** (CloudWatch Logs Insights):

```sql
-- Webhook failure rate baseline
fields @timestamp, event
| filter event = "webhook_processing_error"
| stats count(*) as failures by bin(1h) as time_window
| stats avg(failures) as mean_failures, stddev(failures) as stddev_failures

-- Authentication failure patterns
fields @timestamp, hashed_user_id, source_ip_anonymized
| filter event = "auth_failure"
| stats count(*) by hashed_user_id
| stats percentile(count, 95) as p95_failures, percentile(count, 99) as p99_failures

-- Credit operation rates
fields @timestamp, hashed_user_id, operation_count
| filter event = "payment_anomaly_detected"
| stats avg(operation_count) as mean_operations, max(operation_count) as max_operations
```

**Baseline Documentation**: `docs/MONITORING_BASELINES.md`

### Correlation Rules

**APT Attack Patterns** (detected via composite alarms):

#### 1. Credential Stuffing Attack

**Indicators**:
- 3+ failed authentication attempts from same source IP
- Access from known malicious IP (GuardDuty finding)
- Unusual port usage (not 80/443)

**Correlation Rule**:

```
ALARM(auth_failures_high)
  AND ALARM(guardduty_malicious_ip)
  AND ALARM(unusual_port_activity)
```

**Response**: Activate `CREDENTIAL_STUFFING.md` playbook

#### 2. Webhook Replay/Spoofing Attack

**Indicators**:
- 5+ signature verification failures in 5 minutes
- From same source IP or subnet
- Payload hash mismatch (tampering)

**Correlation Rule**:

```
ALARM(webhook_signature_failures_high)
  AND ALARM(webhook_replay_detected)
```

**Response**: Activate `WEBHOOK_ATTACK.md` playbook

#### 3. Payment Fraud Pattern

**Indicators**:
- 100+ credit operations in 1 minute
- Geographic impossibility (same user, different countries within 10 minutes)
- Rapid subscription changes (upgrade → downgrade → upgrade)

**Correlation Rule**:

```
ALARM(credit_operations_velocity_high)
  OR ALARM(geographic_impossibility_detected)
  OR ALARM(subscription_cycling_pattern)
```

**Response**: Activate `PAYMENT_FRAUD.md` playbook

#### 4. Data Exfiltration Attempt

**Indicators**:
- Bulk database query (>1000 records in single query)
- Unusual off-hours access (2 AM - 6 AM local time)
- DEK cache access from unexpected service

**Correlation Rule**:

```
ALARM(bulk_data_access)
  AND (ALARM(off_hours_access) OR ALARM(unusual_service_access))
```

**Response**: Activate `DATA_EXFILTRATION.md` playbook

#### 5. Encryption Service Compromise

**Indicators**:
- Decryption error rate >1% of requests
- Nonce reuse detected (critical)
- DEK cache poisoning attempt

**Correlation Rule**:

```
ALARM(decryption_errors_high)
  OR ALARM(nonce_reuse_critical)
  OR ALARM(dek_cache_anomaly)
```

**Response**: Activate `ENCRYPTION_FAILURE.md` playbook

#### 6. Lateral Movement / Privilege Escalation

**Indicators**:
- Unusual service-to-service API calls
- IAM policy changes (GuardDuty finding)
- Access to DEK cache from non-auth services

**Correlation Rule**:

```
ALARM(lateral_movement_detected)
  OR ALARM(guardduty_privilege_escalation)
  OR ALARM(unauthorized_service_access)
```

**Response**: Activate `LATERAL_MOVEMENT.md` playbook

### Machine Learning Anomaly Detection

**AWS Anomaly Detection** (CloudWatch Anomaly Detection):

- Automatically learns normal patterns over 2-week period
- Detects deviations using ML models
- Adaptive thresholds (adjusts to seasonal patterns, traffic growth)
- Lower false positive rate than static thresholds

**Enabled For**:
- Webhook processing rate
- Authentication failure rate
- Credit operation velocity
- Database query patterns

---

## Privacy Compliance

### No PII/PCI Data in Logs

**Guarantees** (enforced by code):

| Data Type | Storage | Logging | Compliance |
|-----------|---------|---------|------------|
| User IDs | Database | **Hashed only** (SHA-256 + salt) | ✅ GDPR Article 32 |
| Email addresses | Database (encrypted) | **Never logged** | ✅ PCI DSS SAQ-A |
| IP addresses | Headers | **Anonymized** (last octet masked) | ✅ GDPR Article 32 |
| Card data | **Never in system** (Paddle handles) | **Never logged** | ✅ PCI DSS SAQ-A |
| Payment amounts | Database | **Aggregated only** (no user linkage) | ✅ GDPR Article 32 |
| Paddle customer IDs | Database | **External reference only** (no PII) | ✅ PCI DSS SAQ-A |

**Enforcement**:
- Existing `privacy` module (`loggable_user_id()`, `sanitize_personal_info()`)
- Pre-commit hooks scan for card data patterns
- Automated tests verify no PII in log output
- Security Hub compliance dashboard

### Hashed User IDs

**Implementation** (existing):

```rust
// backend/src/privacy/logging.rs

use sha2::{Sha256, Digest};
use std::env;

pub fn loggable_user_id(user_id: uuid::Uuid) -> String {
    let salt = env::var("PRIVACY_HASH_SALT")
        .unwrap_or_else(|_| "default-dev-salt".to_string());

    let mut hasher = Sha256::new();
    hasher.update(user_id.as_bytes());
    hasher.update(salt.as_bytes());

    let result = hasher.finalize();
    format!("user_{}", hex::encode(&result[..8])) // First 64 bits
}
```

**Properties**:
- **One-way**: Cannot reverse to original user ID
- **Consistent**: Same user ID always hashes to same value (for correlation)
- **Salted**: Different environments produce different hashes
- **Collision-resistant**: SHA-256 provides strong uniqueness guarantees

### Audit Trail Without PII

**Payment Audit Logs** (existing `PaymentAuditService`):

- **Hashed user IDs only** (no reversible identifiers)
- **Event types**: credit_added, payment_processed, subscription_updated
- **Amounts and status**: Logged for compliance
- **External references**: Paddle transaction IDs (hashed for privacy)
- **30-day retention**: Auto-purge after compliance period

**Compliance Verification**:

```sql
-- Verify no plaintext user IDs in audit logs
SELECT COUNT(*) as plaintext_uuids
FROM payment_audit_logs
WHERE user_id_hash ~ '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
-- Expected result: 0

-- Verify all user IDs are hashed
SELECT COUNT(*) as total_entries,
       COUNT(DISTINCT user_id_hash) as unique_users
FROM payment_audit_logs
WHERE user_id_hash LIKE 'user_%';
```

---

## Alert Taxonomy & SLAs

### Severity Levels

| Priority | Name | Description | MTTD | MTTR | Escalation | Examples |
|----------|------|-------------|------|------|------------|----------|
| **P0** | Critical | Active attack, data breach, encryption failure | <5 min | <30 min | Immediate PagerDuty | Data exfiltration, encryption compromise, lateral movement |
| **P1** | High | Attack indicators, multiple security events | <15 min | <1 hr | PagerDuty after 15 min | Credential stuffing, webhook attack, payment fraud |
| **P2** | Medium | Anomalous patterns, potential threats | <1 hr | <4 hrs | Email + Slack | Unusual access patterns, soft limit violations |
| **P3** | Low | Information, compliance warnings | <24 hrs | Best effort | Email only | Configuration drift, baseline deviations |

### Alert Routing

**SNS Topics** (per severity):

```hcl
# P0: Critical - Immediate PagerDuty
resource "aws_sns_topic" "security_alerts_p0" {
  name = "scribe-security-p0-critical"
}

resource "aws_sns_topic_subscription" "p0_pagerduty" {
  topic_arn = aws_sns_topic.security_alerts_p0.arn
  protocol  = "https"
  endpoint  = "https://events.pagerduty.com/integration/..."
}

# P1: High - PagerDuty + Slack
resource "aws_sns_topic" "security_alerts_p1" {
  name = "scribe-security-p1-high"
}

resource "aws_sns_topic_subscription" "p1_pagerduty" {
  topic_arn = aws_sns_topic.security_alerts_p1.arn
  protocol  = "https"
  endpoint  = "https://events.pagerduty.com/integration/..."
}

resource "aws_sns_topic_subscription" "p1_slack" {
  topic_arn = aws_sns_topic.security_alerts_p1.arn
  protocol  = "https"
  endpoint  = "https://hooks.slack.com/services/..."
}

# P2: Medium - Slack + Email
resource "aws_sns_topic" "security_alerts_p2" {
  name = "scribe-security-p2-medium"
}

resource "aws_sns_topic_subscription" "p2_email" {
  topic_arn = aws_sns_topic.security_alerts_p2.arn
  protocol  = "email"
  endpoint  = "security-team@example.com"
}

# P3: Low - Email only
resource "aws_sns_topic" "security_alerts_p3" {
  name = "scribe-security-p3-low"
}
```

### Alert Fatigue Prevention

**Strategies**:

1. **Baseline Calibration**: 7-14 day period before enabling alarms
2. **Statistical Thresholds**: Mean + 3σ (reduces false positives to <1%)
3. **Composite Alarms**: Require multiple indicators (reduces noise)
4. **Anomaly Detection**: ML-based adaptive thresholds
5. **Alert Aggregation**: Group similar alerts (e.g., 5+ auth failures → 1 alert)
6. **Suppression Windows**: Maintenance mode disables non-critical alerts
7. **Feedback Loop**: Track false positive rate, tune thresholds monthly

**Target**: <10 actionable alerts per day, <5% false positive rate

---

## Critical Security Events

### Event Catalog

**Webhook Security Events**:

| Event Name | Severity | MTTD | Description | Response Playbook |
|------------|----------|------|-------------|-------------------|
| `webhook_signature_failure` | P1 | 5 min | Webhook signature verification failed | `WEBHOOK_ATTACK.md` |
| `webhook_replay_detected` | P1 | 5 min | Duplicate event_id within time window | `WEBHOOK_ATTACK.md` |
| `webhook_rate_limit_exceeded` | P2 | 15 min | Too many requests from source IP | Rate limiting (automatic) |
| `webhook_processing_error` | P3 | 1 hr | 5xx error during webhook processing | Standard error handling |

**Authentication Events**:

| Event Name | Severity | MTTD | Description | Response Playbook |
|------------|----------|------|-------------|-------------------|
| `auth_failure` | P3 | 1 hr | Failed login attempt | Standard logging |
| `auth_lockout` | P2 | 30 min | Account locked (3+ failures) | Monitor for brute force |
| `auth_impossible_travel` | P1 | 15 min | Same user, different countries <10 min | `CREDENTIAL_STUFFING.md` |
| `session_hijack_suspected` | P0 | 5 min | Session token anomaly | `DATA_EXFILTRATION.md` |

**Payment Events**:

| Event Name | Severity | MTTD | Description | Response Playbook |
|------------|----------|------|-------------|-------------------|
| `payment_anomaly_detected` | P2 | 30 min | Unusual credit operation pattern | `PAYMENT_FRAUD.md` |
| `payment_fraud_pattern` | P1 | 15 min | High-confidence fraud indicators | `PAYMENT_FRAUD.md` |
| `payment_geographic_impossibility` | P1 | 15 min | Conflicting transaction locations | `PAYMENT_FRAUD.md` |
| `payment_high_velocity` | P0 | 5 min | 100+ operations in 1 minute | `PAYMENT_FRAUD.md` |

**Encryption Events**:

| Event Name | Severity | MTTD | Description | Response Playbook |
|------------|----------|------|-------------|-------------------|
| `encryption_failure` | P1 | 15 min | Failed to encrypt data | `ENCRYPTION_FAILURE.md` |
| `decryption_failure` | P1 | 15 min | Failed to decrypt data | `ENCRYPTION_FAILURE.md` |
| `nonce_reuse_detected` | P0 | 5 min | **CRITICAL** cryptographic failure | `ENCRYPTION_FAILURE.md` |
| `dek_cache_miss` | P2 | 1 hr | DEK not found in cache | Force re-authentication |

**System Events**:

| Event Name | Severity | MTTD | Description | Response Playbook |
|------------|----------|------|-------------|-------------------|
| `lateral_movement_detected` | P0 | 5 min | Unusual service-to-service access | `LATERAL_MOVEMENT.md` |
| `privilege_escalation_attempt` | P0 | 5 min | IAM policy violation | `LATERAL_MOVEMENT.md` |
| `bulk_data_access` | P1 | 15 min | Query returned >1000 records | `DATA_EXFILTRATION.md` |
| `off_hours_access` | P2 | 1 hr | Access 2 AM - 6 AM local time | Monitor pattern |

---

## Baseline Calibration

### Process Overview

**Timeline**: 7-14 days (recommended: 14 days for seasonal patterns)

**Steps**:

1. **Deploy instrumented application** (Week 1)
   - Enable structured logging
   - Deploy security metrics module
   - Configure CloudWatch Logs
   - **DO NOT** enable alarms yet

2. **Collect baseline data** (Weeks 1-2)
   - Monitor all security events
   - Track normal traffic patterns
   - Identify peak/off-peak periods
   - Document edge cases

3. **Analyze statistical distribution** (End of Week 2)
   - Calculate mean, stddev, p95, p99 for all metrics
   - Identify normal vs. anomalous ranges
   - Account for webhook failure rate (5-10% is normal)
   - Document findings in `MONITORING_BASELINES.md`

4. **Calculate thresholds** (Week 3)
   - **Conservative**: Mean + 3σ (99.7% confidence, <1% false positives)
   - **Moderate**: Mean + 2σ (95% confidence, ~5% false positives)
   - **Aggressive**: 2x baseline average (for high-priority events)

5. **Enable alarms gradually** (Week 3)
   - P3 alerts first (info-level, monitor for noise)
   - P2 alerts second (adjust thresholds based on P3 feedback)
   - P1 alerts third (validate with SOC team)
   - P0 alerts last (only after P1 proven stable)

6. **Continuous tuning** (Ongoing)
   - Track false positive rate weekly
   - Adjust thresholds if FP rate >5%
   - Update baselines quarterly (traffic growth, seasonal patterns)

### Baseline Queries

**CloudWatch Logs Insights** (save as query templates):

#### Webhook Failure Rate

```sql
fields @timestamp, event, status_code
| filter event = "webhook_processing_error"
| stats count(*) as failures by bin(1h) as hour
| sort hour asc
```

**Expected Output**:
```
hour                 failures
2025-10-04 00:00:00  2
2025-10-04 01:00:00  1
2025-10-04 02:00:00  0
...
2025-10-04 12:00:00  45
```

**Analysis**:
- Calculate: mean = 15, stddev = 20
- Threshold: mean + 3σ = 15 + (3 × 20) = 75 failures/hour
- **Note**: 5-10% failure rate is normal for webhooks (network issues)

#### Authentication Failure Patterns

```sql
fields @timestamp, hashed_user_id, source_ip_anonymized
| filter event = "auth_failure"
| stats count(*) as failures by hashed_user_id
| sort failures desc
| limit 100
```

**Expected Output**:
```
hashed_user_id     failures
user_a1b2c3d4      5
user_e5f6g7h8      3
user_i9j0k1l2      2
```

**Analysis**:
- p95 = 3 failures per user per day
- p99 = 5 failures per user per day
- Threshold: 10 failures in 1 hour (2x p99) → alert

#### Credit Operation Velocity

```sql
fields @timestamp, hashed_user_id, operation_count
| filter event like /credit_/
| stats count(*) as operations by hashed_user_id, bin(1m) as minute
| sort operations desc
| limit 100
```

**Expected Output**:
```
hashed_user_id     minute               operations
user_a1b2c3d4      2025-10-04 12:34:00  15
user_e5f6g7h8      2025-10-04 12:35:00  8
user_i9j0k1l2      2025-10-04 12:36:00  3
```

**Analysis**:
- p95 = 10 operations/minute
- p99 = 20 operations/minute
- Threshold: 100 operations/minute (5x p99) → fraud alert

### Baseline Documentation

**Template**: `docs/MONITORING_BASELINES.md`

```markdown
# Security Monitoring Baselines

**Baseline Period:** 2025-10-04 to 2025-10-18 (14 days)
**Total Requests:** 1,234,567
**Unique Users (hashed):** 5,432

## Webhook Processing

| Metric | Mean | Stddev | P95 | P99 | Threshold | Alarm Name |
|--------|------|--------|-----|-----|-----------|------------|
| Processing rate (req/min) | 85 | 45 | 150 | 200 | 300 | `webhook_rate_high` |
| Failure rate (%) | 6.2% | 2.1% | 8.5% | 10.3% | 15% | `webhook_failures_high` |
| Signature failures (/hr) | 1 | 2 | 3 | 5 | 5 | `webhook_attack` |

## Authentication

| Metric | Mean | Stddev | P95 | P99 | Threshold | Alarm Name |
|--------|------|--------|-----|-----|-----------|------------|
| Login attempts/min | 125 | 67 | 200 | 250 | 400 | `auth_rate_high` |
| Failed logins/hr | 45 | 23 | 75 | 95 | 150 | `auth_failures_high` |
| Lockouts/day | 3 | 2 | 5 | 8 | 10 | `auth_lockouts_high` |

## Payment Operations

| Metric | Mean | Stddev | P95 | P99 | Threshold | Alarm Name |
|--------|------|--------|-----|-----|-----------|------------|
| Credit ops/user/min | 5 | 8 | 15 | 25 | 100 | `payment_fraud` |
| Subscription changes/hr | 12 | 6 | 20 | 28 | 50 | `subscription_cycling` |

## Notes

- Webhook failure baseline (6.2%) is within expected range (5-10%)
- Authentication failures spike during peak hours (12 PM - 2 PM)
- Credit operations show seasonal pattern (month-end +40%)
- Baseline will be re-calculated quarterly to account for growth
```

---

## Incident Response Integration

### Playbook Activation

**Automated Triggers** (EventBridge rules):

```hcl
resource "aws_cloudwatch_event_rule" "webhook_attack" {
  name        = "scribe-webhook-attack-detected"
  description = "Triggers webhook attack playbook"

  event_pattern = jsonencode({
    source      = ["aws.cloudwatch"]
    detail-type = ["CloudWatch Alarm State Change"]
    detail = {
      alarmName = ["P1-WebhookAttackDetected"]
      state = {
        value = ["ALARM"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "run_playbook" {
  rule      = aws_cloudwatch_event_rule.webhook_attack.name
  target_id = "RunPlaybook"
  arn       = aws_lambda_function.playbook_executor.arn

  input = jsonencode({
    playbook = "WEBHOOK_ATTACK",
    severity = "P1",
    automated_response = true
  })
}
```

**Playbook Executor Lambda**:

```python
# infrastructure/lambda/playbook_executor/handler.py

import boto3
import json

def handler(event, context):
    playbook = event['playbook']
    severity = event['severity']

    # Execute automated response steps
    if playbook == 'WEBHOOK_ATTACK':
        execute_webhook_attack_response(event)
    elif playbook == 'CREDENTIAL_STUFFING':
        execute_credential_stuffing_response(event)
    # ... other playbooks

    # Create PagerDuty incident
    create_pagerduty_incident(playbook, severity, event)

    # Notify SOC team
    send_sns_notification(playbook, event)

def execute_webhook_attack_response(event):
    # 1. Extract source IP from alarm
    source_ip = event['alarm_details']['source_ip_anonymized']

    # 2. Block IP in WAF
    waf = boto3.client('wafv2')
    waf.update_ip_set(
        Name='ScribeBlockedIPs',
        Scope='REGIONAL',
        Addresses=[f'{source_ip}/32']
    )

    # 3. Invoke Systems Manager runbook
    ssm = boto3.client('ssm')
    ssm.start_automation_execution(
        DocumentName='SSM-Scribe-WebhookAttackResponse',
        Parameters={
            'SourceIP': [source_ip],
            'Severity': ['P1']
        }
    )
```

### SOC Team Interface

**Slack Integration** (for P1/P2 alerts):

```python
# Send alert to Slack with action buttons
def send_slack_alert(playbook, event):
    webhook_url = get_secret('slack/webhook_url')

    message = {
        "text": f"🚨 Security Alert: {playbook}",
        "attachments": [{
            "color": "danger",
            "fields": [
                {"title": "Severity", "value": event['severity'], "short": True},
                {"title": "MTTD", "value": "5 minutes", "short": True},
                {"title": "Source IP", "value": event['source_ip_anonymized'], "short": True},
                {"title": "Event Count", "value": str(event['event_count']), "short": True}
            ],
            "actions": [
                {
                    "type": "button",
                    "text": "View Logs",
                    "url": f"https://console.aws.amazon.com/cloudwatch/logs?..."
                },
                {
                    "type": "button",
                    "text": "Acknowledge",
                    "url": f"https://api.example.com/incidents/{event['incident_id']}/ack"
                },
                {
                    "type": "button",
                    "text": "View Playbook",
                    "url": f"https://github.com/example/scribe/blob/main/docs/playbooks/{playbook}.md"
                }
            ]
        }]
    }

    requests.post(webhook_url, json=message)
```

### Playbook Documentation

**Structure** (all playbooks follow this template):

```markdown
# [Incident Type] Response Playbook

**Severity:** P[0-3]
**MTTD:** <X minutes>
**MTTR:** <X minutes>

## Detection Criteria

- Metric: `[metric_name]`
- Threshold: `[threshold_value]`
- Alarm: `[cloudwatch_alarm_name]`

## Indicators of Compromise (IOCs)

1. [Specific indicator 1]
2. [Specific indicator 2]
3. [Specific indicator 3]

## Investigation Steps (Privacy-Safe)

1. **Check CloudWatch Logs**
   ```sql
   fields @timestamp, event, hashed_user_id, source_ip_anonymized
   | filter event = "[event_name]"
   | filter @timestamp > ago(1h)
   | sort @timestamp desc
   | limit 100
   ```

2. **Verify Pattern**
   - [ ] Confirm threshold breach
   - [ ] Check for false positive
   - [ ] Correlate with other events

3. **Identify Scope**
   - Affected users (hashed IDs): `[query]`
   - Time window: `[start]` to `[end]`
   - Geographic distribution: `[query]`

## Containment Actions

1. **Immediate** (automated):
   - [ ] [Action 1]
   - [ ] [Action 2]

2. **Manual** (SOC team):
   - [ ] [Action 3]
   - [ ] [Action 4]

## Recovery Procedures

1. [Recovery step 1]
2. [Recovery step 2]

## Post-Incident Review

- [ ] Document root cause
- [ ] Update baselines if needed
- [ ] Tune alert thresholds
- [ ] Update playbook with lessons learned
- [ ] Conduct tabletop exercise

## Related Playbooks

- [Related playbook 1]
- [Related playbook 2]
```

---

## Implementation Roadmap

### Phase 1: Application Instrumentation (Week 1)

**Tasks**:
- [ ] Create `backend/src/metrics/security.rs` module
- [ ] Create `backend/src/logging/security_events.rs` module
- [ ] Add `backend/src/privacy/ip_anonymization.rs` utility
- [ ] Instrument `backend/src/routes/payment.rs` with security events
- [ ] Instrument `backend/src/auth/` modules with auth events
- [ ] Update `backend/src/services/payment/credit_service.rs` with anomaly detection
- [ ] Add correlation ID middleware to Axum router
- [ ] Write unit tests for all new modules
- [ ] Update `Cargo.toml` dependencies (`prometheus`, `tracing-subscriber`)

**Deliverables**:
- Structured JSON logging enabled
- Security metrics exposed at `/metrics` endpoint
- Privacy-safe event logging throughout codebase

### Phase 2: AWS Infrastructure Setup (Week 2)

**Tasks**:
- [ ] Create `infrastructure/terraform/modules/monitoring/` directory
- [ ] Implement `cloudwatch_log_groups.tf`
- [ ] Implement `kinesis_firehose.tf`
- [ ] Implement `cloudwatch_metric_filters.tf`
- [ ] Implement `cloudwatch_alarms.tf` (disabled initially)
- [ ] Implement `sns_topics.tf` for alert routing
- [ ] Implement `guardduty.tf` configuration
- [ ] Implement `security_hub.tf` with PCI DSS standard
- [ ] Create `infrastructure/terraform/modules/monitoring/variables.tf`
- [ ] Create `infrastructure/terraform/modules/monitoring/outputs.tf`
- [ ] Deploy to staging environment

**Deliverables**:
- CloudWatch Logs aggregating application logs
- Kinesis Data Firehose streaming to S3
- SNS topics for alert routing (P0-P3)
- GuardDuty enabled for AWS account
- Security Hub compliance dashboard

### Phase 3: Baseline Calibration (Weeks 3-4)

**Tasks**:
- [ ] Deploy instrumented application to production
- [ ] Monitor all security events for 14 days
- [ ] Run baseline queries daily in CloudWatch Logs Insights
- [ ] Document statistical distribution (mean, stddev, p95, p99)
- [ ] Calculate alarm thresholds (mean + 3σ)
- [ ] Create `docs/MONITORING_BASELINES.md`
- [ ] Validate baselines with SOC team
- [ ] Account for normal webhook failure rate (5-10%)

**Deliverables**:
- Baseline documentation with statistical analysis
- Calibrated alarm thresholds
- Validation report from SOC team

### Phase 4: Alert Activation (Week 5)

**Tasks**:
- [ ] Enable P3 alarms (info-level, monitor for noise)
- [ ] Monitor P3 alerts for 3 days, adjust thresholds if needed
- [ ] Enable P2 alarms (medium severity)
- [ ] Monitor P2 alerts for 3 days, validate with SOC team
- [ ] Enable P1 alarms (high severity)
- [ ] Conduct tabletop exercise for P1 scenarios
- [ ] Enable P0 alarms (critical severity)
- [ ] Validate P0 alert routing to PagerDuty
- [ ] Document false positive rate
- [ ] Update playbooks based on initial alerts

**Deliverables**:
- All alarms enabled with calibrated thresholds
- False positive rate <5%
- PagerDuty integration validated
- SOC team trained on alert triage

### Phase 5: SIEM Integration (Week 6)

**Tasks**:
- [ ] Choose SIEM platform (Datadog, Splunk, ELK, or custom)
- [ ] Implement SIEM-specific Terraform module
- [ ] Configure Kinesis Data Firehose destination
- [ ] Set up log parsing/enrichment in SIEM
- [ ] Create SIEM dashboards for security metrics
- [ ] Configure SIEM alerts (secondary layer)
- [ ] Test end-to-end log flow (application → SIEM)
- [ ] Document SIEM integration in `docs/SIEM_INTEGRATION.md`

**Deliverables**:
- SIEM receiving logs from Kinesis
- Security dashboards in SIEM
- Dual-layer alerting (CloudWatch + SIEM)
- Integration documentation

### Phase 6: Incident Response Automation (Week 7)

**Tasks**:
- [ ] Create all 6 playbook documents in `docs/playbooks/`
- [ ] Implement `infrastructure/lambda/playbook_executor/`
- [ ] Create AWS Systems Manager runbooks in `infrastructure/runbooks/`
- [ ] Implement automated containment functions (IP blocking, rate limiting)
- [ ] Configure EventBridge rules to trigger playbooks
- [ ] Test each playbook with simulated incidents
- [ ] Create Slack integration for SOC alerts
- [ ] Document runbook automation in `docs/INCIDENT_RESPONSE_PROCEDURES.md`

**Deliverables**:
- 6 incident response playbooks
- Automated runbooks for common scenarios
- EventBridge-triggered automation
- Slack integration for SOC team

### Phase 7: Continuous Improvement (Ongoing)

**Tasks**:
- [ ] Schedule quarterly tabletop exercises
- [ ] Track MTTD/MTTR metrics monthly
- [ ] Review false positive rate weekly
- [ ] Update baselines quarterly
- [ ] Tune alarm thresholds based on feedback
- [ ] Conduct post-incident reviews
- [ ] Update playbooks with lessons learned
- [ ] Annual external security audit

**Deliverables**:
- Quarterly exercise reports
- Monthly metrics dashboard
- Updated baselines and thresholds
- Post-incident review documentation

---

## Success Metrics

### Key Performance Indicators (KPIs)

| Metric | Target | Measurement Method | Review Frequency |
|--------|--------|-------------------|------------------|
| **MTTD (P0)** | <5 minutes | CloudWatch alarm timestamp → incident detection | Weekly |
| **MTTD (P1)** | <15 minutes | CloudWatch alarm timestamp → incident detection | Weekly |
| **MTTR (P0)** | <30 minutes | Incident detection → incident resolution | Weekly |
| **MTTR (P1)** | <1 hour | Incident detection → incident resolution | Weekly |
| **False Positive Rate** | <5% | Alerts → confirmed incidents ratio | Weekly |
| **Alert Fatigue** | <10 alerts/day | Total alerts per day (actionable only) | Daily |
| **Compliance Score** | 100% | Security Hub PCI DSS compliance | Monthly |
| **Baseline Accuracy** | >95% | Threshold breaches → true positives | Quarterly |

### Operational Metrics

| Metric | Target | Current | Notes |
|--------|--------|---------|-------|
| **Log Volume** | <100 GB/day | TBD | After baseline period |
| **SIEM Ingestion Rate** | <10 MB/s peak | TBD | After SIEM integration |
| **CloudWatch Costs** | <$500/month | TBD | Logs + Metrics + Alarms |
| **Kinesis Costs** | <$200/month | TBD | Data transfer + buffering |
| **Storage Costs (S3)** | <$100/month | TBD | Compressed logs, 1-year retention |

### Security Metrics

| Metric | Target | Measurement | Notes |
|--------|--------|-------------|-------|
| **Webhook Attack Detection** | 100% | Simulated attacks → alarms | Quarterly pen-test |
| **Credential Stuffing Detection** | >95% | Simulated attacks → alarms | Quarterly tabletop |
| **Payment Fraud Detection** | >90% | Historical fraud patterns | Quarterly review |
| **Data Exfiltration Detection** | 100% | Simulated exfiltration → alarms | Quarterly tabletop |
| **Zero PII Leakage** | 100% | Automated log scanning | Daily (CI/CD) |

### Compliance Metrics

| Requirement | Status | Evidence | Audit Frequency |
|-------------|--------|----------|-----------------|
| **OWASP A09** | ✅ | Security logging framework | Annual |
| **PCI DSS Req 10** | ✅ | Audit log retention, daily review | Quarterly (SAQ-A) |
| **GDPR Article 32** | ✅ | No PII in logs, encryption at rest | Annual |
| **AWS FS-ISAC** | ✅ | Tabletop exercises, baselines | Quarterly |

---

## Related Documentation

- **Incident Response Playbooks**: [`docs/playbooks/`](./playbooks/)
- **Privacy-Safe Logging**: [`docs/PRIVACY_SAFE_LOGGING.md`](./PRIVACY_SAFE_LOGGING.md)
- **OWASP Top 10**: [`docs/OWASP-TOP-10.md`](./OWASP-TOP-10.md)
- **Encryption Architecture**: [`docs/ENCRYPTION_ARCHITECTURE.md`](./ENCRYPTION_ARCHITECTURE.md)
- **Monitoring Baselines**: [`docs/MONITORING_BASELINES.md`](./MONITORING_BASELINES.md) (created after baseline period)
- **SIEM Integration**: [`docs/SIEM_INTEGRATION.md`](./SIEM_INTEGRATION.md) (created during Phase 5)
- **Incident Response Procedures**: [`docs/INCIDENT_RESPONSE_PROCEDURES.md`](./INCIDENT_RESPONSE_PROCEDURES.md)
- **FIX_PLAN.md**: [`docs/FIX_PLAN.md`](./FIX_PLAN.md) (Tasks 8, 9, 10)

---

**Last Updated:** 2025-10-04
**Status:** 🟢 Implementation Ready
**Next Review:** After baseline calibration (Week 4)
**Maintained By:** Security Team + Platform Engineering
