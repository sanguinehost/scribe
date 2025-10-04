# Baseline Calibration Procedure
# Security Monitoring Alarm Threshold Calibration

**Status**: 📋 READY FOR EXECUTION
**Duration**: 7-14 days
**Related**: Task 10.5 (Payment System Security Implementation)

---

## Overview

All security alarms created in Task 10 are deployed in **CALIBRATION MODE** (disabled). This document guides the team through the baseline establishment process required before enabling production alerts.

**Why Calibration Matters**:
- Prevents alert fatigue from false positives
- Establishes environment-specific thresholds (staging ≠ production)
- Reduces incident response noise (target: <5% false positive rate)
- Enables statistical confidence (mean + 3σ = <1% false positives)

---

## Prerequisites

✅ Security events are being logged
✅ Infrastructure deployed (Metric filters, alarms created but disabled)
✅ Kinesis Firehose streaming logs to S3
✅ Backend application running in target environment (staging/production)
✅ Access to CloudWatch Logs Insights

---

## Phase 1: Deploy Monitoring Infrastructure (Week 1, Day 1)

### 1.1 Verify Deployment

```bash
# Navigate to staging environment
cd infrastructure/terraform/environments/staging

# Verify Terraform state
terraform plan

# Expected output: No changes (infrastructure already deployed)
```

### 1.2 Confirm Alarm Status

**Via AWS Console**:
1. Navigate to CloudWatch → Alarms
2. Filter: `staging-scribe-*` or `production-scribe-*`
3. Verify all alarms show **"Actions Disabled"** badge

**Via AWS CLI**:
```bash
aws cloudwatch describe-alarms \
  --alarm-name-prefix "staging-P" \
  --query 'MetricAlarms[*].[AlarmName,ActionsEnabled]' \
  --output table

# Expected: All alarms show ActionsEnabled=false
```

### 1.3 Verify Metric Filters

```bash
# List all security metric filters
aws logs describe-metric-filters \
  --log-group-name "/ecs/staging-scribe-backend" \
  --query 'metricFilters[*].[filterName,metricTransformations[0].metricName]' \
  --output table

# Expected: 9 metric filters (webhook failures, auth failures, etc.)
```

### 1.4 Verify Kinesis Firehose

```bash
# Check Firehose delivery stream status
aws firehose describe-delivery-stream \
  --delivery-stream-name "staging-scribe-security-logs" \
  --query 'DeliveryStreamDescription.DeliveryStreamStatus'

# Expected: "ACTIVE"
```

---

## Phase 2: Collect Baseline Data (Week 1-2)

### 2.1 Duration

- **Minimum**: 7 days (1 full week)
- **Recommended**: 14 days (2 weeks for weekly patterns)
- **Production**: 14 days minimum (captures weekend traffic variations)

### 2.2 Monitoring Checklist

During calibration period, **DO NOT**:
- ❌ Enable any security alarms
- ❌ Run penetration tests or security drills
- ❌ Perform unusual bulk operations
- ❌ Import large datasets

**DO**:
- ✅ Run normal production workloads
- ✅ Monitor metric dashboards daily
- ✅ Document any anomalies (deployments, traffic spikes)
- ✅ Track legitimate security events (accidental auth failures, etc.)

### 2.3 Daily Monitoring Dashboard

**CloudWatch Metrics to Watch**:
```
Namespace: Scribe/Security

Metrics:
- WebhookSignatureFailureCount
- AuthFailureCount
- CreditOperationRate
- EncryptionErrorCount
- DataExfiltrationCount
- DekScrapingAttemptCount
- ReplayAttackCount
```

**Create Custom Dashboard**:
```bash
# Use AWS Console: CloudWatch → Dashboards → Create Dashboard
# Name: "Security Metrics Calibration"
# Add widgets for all 7 security metrics
# Period: 5 minutes, Statistic: Sum, Time range: Last 7 days
```

---

## Phase 3: Analyze Baseline Data (Week 3, Day 1-3)

### 3.1 CloudWatch Logs Insights Queries

**Query 1: Webhook Signature Failures Baseline**
```sql
fields @timestamp, event_type, ip_address
| filter event_type = "webhook_signature_failure"
| stats count() as failure_count by bin(5m)
| stats avg(failure_count) as mean,
        stddev(failure_count) as stddev,
        pct(failure_count, 95) as p95,
        pct(failure_count, 99) as p99
```

**Expected Output**:
| Mean | Stddev | P95 | P99 | Threshold (Mean + 3σ) |
|------|--------|-----|-----|-----------------------|
| 1.2  | 2.1    | 3   | 5   | 7.5 → **8 failures/5min** |

**Query 2: Authentication Failures Baseline**
```sql
fields @timestamp, event_type, user_hash, ip_address
| filter event_type = "auth_failure"
| stats count() as failure_count by bin(5m)
| stats avg(failure_count) as mean,
        stddev(failure_count) as stddev,
        pct(failure_count, 95) as p95,
        pct(failure_count, 99) as p99
```

**Query 3: Credit Operations Rate Baseline**
```sql
fields @timestamp, @message
| filter @message like /Recording credit operation/
| stats count() as credit_ops by bin(5m)
| stats avg(credit_ops) as mean,
        stddev(credit_ops) as stddev,
        pct(credit_ops, 95) as p95,
        pct(credit_ops, 99) as p99
```

**Query 4: Encryption Errors Baseline**
```sql
fields @timestamp, event_type
| filter event_type = "encryption_error"
| stats count() as error_count by bin(15m)
| stats avg(error_count) as mean,
        stddev(error_count) as stddev,
        pct(error_count, 95) as p95,
        pct(error_count, 99) as p99
```

**Query 5: Data Exfiltration Baseline**
```sql
fields @timestamp, event_type
| filter event_type = "data_exfiltration"
| stats count() as exfiltration_count by bin(15m)
| stats avg(exfiltration_count) as mean,
        stddev(exfiltration_count) as stddev,
        pct(exfiltration_count, 95) as p95,
        pct(exfiltration_count, 99) as p99
```

### 3.2 Statistical Threshold Calculation

**Formula**: `Threshold = Mean + 3 × StdDev`

**Example Calculation** (Webhook Failures):
- Mean: 1.2 failures/5min
- StdDev: 2.1
- Threshold: 1.2 + (3 × 2.1) = **7.5 failures/5min**
- Round up to: **8 failures/5min**

**Why Mean + 3σ?**
- Covers 99.7% of normal distribution (only 0.3% false positives)
- Balances sensitivity vs. noise
- Industry standard for anomaly detection

### 3.3 Baseline Data Template

Create `docs/BASELINE_DATA_[ENVIRONMENT].md`:

```markdown
# Baseline Data - [Staging/Production]
**Collection Period**: YYYY-MM-DD to YYYY-MM-DD (14 days)

## Webhook Signature Failures
| Metric | Value | Alarm Threshold |
|--------|-------|-----------------|
| Mean | 1.2/5min | 8/5min (mean + 3σ) |
| StdDev | 2.1 | - |
| P95 | 3/5min | - |
| P99 | 5/5min | - |
| Max Observed | 7/5min | - |

## Authentication Failures
| Metric | Value | Alarm Threshold |
|--------|-------|-----------------|
| Mean | 6.5/5min | 25/5min (mean + 3σ) |
| StdDev | 4.2 | - |
| P95 | 12/5min | - |
| P99 | 18/5min | - |
| Max Observed | 22/5min | - |

... (repeat for all metrics)
```

---

## Phase 4: Update Alarm Thresholds (Week 3, Day 3-4)

### 4.1 Threshold Comparison

**Current Alarm Thresholds** (from Task 10 implementation):
| Alarm | Current Threshold | Baseline Threshold | Action |
|-------|-------------------|--------------------| -------|
| P0-WebhookAttackDetected | 5/5min | 8/5min (calculated) | ✅ Keep (more sensitive) |
| P0-AccountTakeoverDetected | 10/5min | 25/5min (calculated) | ✅ Keep (more sensitive) |
| P1-PaymentFraudDetected | 50/5min | TBD (analyze) | ⚠️ Adjust if needed |
| P2-EncryptionFailureDetected | 5/15min | TBD (analyze) | ⚠️ Adjust if needed |

**Decision Matrix**:
- If **Baseline > Current**: Keep current (more sensitive, acceptable)
- If **Baseline < Current**: Update to baseline (reduce false positives)
- If **Baseline ≈ Current** (±20%): Keep current (good estimate)

### 4.2 Update Terraform Configuration

**IF adjustments needed**:
```hcl
# infrastructure/terraform/modules/monitoring/cloudwatch_alarms.tf

resource "aws_cloudwatch_metric_alarm" "webhook_attack_p0" {
  # ... existing config ...
  threshold           = "8"  # Updated from baseline
  # ... rest of config ...
}
```

**Deploy changes**:
```bash
cd infrastructure/terraform/environments/staging
terraform plan  # Review changes
terraform apply # Apply threshold updates
```

---

## Phase 5: Gradual Alarm Activation (Week 3-4)

### 5.1 Activation Schedule

**IMPORTANT**: Enable alarms gradually to catch configuration issues early.

| Day | Action | Alarms to Enable | Monitor For |
|-----|--------|------------------|-------------|
| Week 3, Day 5 | Enable P3 (Low) | All P3 alarms | False positive rate |
| Week 3, Day 7 | P3 Review | - | Validate <5% FP rate |
| Week 4, Day 1 | Enable P2 (Medium) | All P2 alarms | Alert volume |
| Week 4, Day 3 | P2 Review | - | Validate <5% FP rate |
| Week 4, Day 5 | Enable P1 (High) | All P1 alarms | SOC team training |
| Week 4, Day 7 | P1 Review | - | Incident response drill |
| Week 5, Day 1 | Enable P0 (Critical) | All P0 alarms | PagerDuty integration |
| Week 5, Day 2 | P0 Validation | - | Full tabletop exercise |

### 5.2 Enable Alarms (Terraform)

**Step 1: Update variable**
```hcl
# infrastructure/terraform/environments/staging/terraform.tfvars

enable_security_alarms = true  # Enable alarm actions

# Optionally configure email alerts
alert_email_p0 = "security-p0@example.com"
alert_email_p1 = "security-p1@example.com"
alert_email_p2 = "security-p2@example.com"
alert_email_p3 = "security-p3@example.com"
```

**Step 2: Apply changes**
```bash
cd infrastructure/terraform/environments/staging
terraform plan  # Review changes
terraform apply # Enable alarms
```

**Step 3: Confirm email subscriptions**
- Check email inboxes for SNS subscription confirmation emails
- Click "Confirm subscription" for each severity level
- Verify subscriptions in AWS Console: SNS → Topics → Subscriptions

### 5.3 Test Alert Flow

**Trigger Test Alert** (use AWS CLI):
```bash
# Set alarm to ALARM state manually (testing only)
aws cloudwatch set-alarm-state \
  --alarm-name "staging-P3-CreditAnomalyDetected" \
  --state-value "ALARM" \
  --state-reason "Testing alert flow during calibration"

# Verify email received within 5 minutes
```

**Reset alarm**:
```bash
aws cloudwatch set-alarm-state \
  --alarm-name "staging-P3-CreditAnomalyDetected" \
  --state-value "OK" \
  --state-reason "Test complete"
```

---

## Phase 6: Monitor and Tune (Week 5+)

### 6.1 False Positive Tracking

**Target**: <5% false positive rate

**Daily Checklist** (First 2 weeks after activation):
- [ ] Check CloudWatch alarm history
- [ ] Review triggered alarms with incident response team
- [ ] Classify each alarm: True Positive / False Positive / Inconclusive
- [ ] Document false positives in `docs/FALSE_POSITIVE_LOG.md`

**False Positive Rate Calculation**:
```
FP Rate = (False Positives) / (Total Alarms) × 100%

Example:
- Total alarms in 7 days: 42
- False positives: 3
- FP Rate: (3/42) × 100% = 7.1%
- Action: Adjust thresholds (target <5%)
```

### 6.2 Threshold Tuning

**IF FP Rate > 5%**:
1. Identify most noisy alarm
2. Analyze triggering pattern (time of day, specific events)
3. Options:
   - Increase threshold (e.g., 5 → 8 failures)
   - Increase evaluation periods (e.g., 1 → 2 periods)
   - Adjust period duration (e.g., 5min → 10min)
4. Update Terraform, apply changes
5. Monitor for 3 more days

**IF FP Rate < 1%** (too conservative):
1. Review incident response logs - were any real attacks missed?
2. Consider reducing threshold for P1/P2 alarms (not P0)
3. Consult with SOC team before changes

---

## Phase 7: Production Rollout

### 7.1 Staging Validation Checklist

Before deploying to production, confirm:
- [ ] Staging alarms enabled for 7+ days
- [ ] False positive rate <5%
- [ ] All P0 alarms tested with tabletop exercises
- [ ] PagerDuty integration validated (if applicable)
- [ ] Incident response playbooks reviewed by SOC team
- [ ] Email alert subscriptions confirmed
- [ ] Kinesis Firehose delivering logs to S3 successfully

### 7.2 Production Deployment

**Repeat calibration for production environment**:
- Production traffic patterns differ from staging
- Higher volume may require different thresholds
- Follow same 14-day calibration process
- **Do not** copy staging thresholds directly

---

## Appendix A: Common Issues

### Issue 1: No Security Events Logged

**Symptom**: All metrics show 0 count
**Diagnosis**:
```bash
# Check if security events are being logged
aws logs filter-log-events \
  --log-group-name "/ecs/staging-scribe-backend" \
  --filter-pattern '{ $.event_type = * }' \
  --limit 10

# Should return security events
```

**Fix**:
- Verify Task 9 code deployed (security events implementation)
- Check ECS task revision number
- Verify environment variables (RUST_LOG level)

### Issue 2: Metric Filter Not Extracting Values

**Symptom**: Metric exists but always 0
**Diagnosis**:
```bash
# Test metric filter pattern
aws logs test-metric-filter \
  --filter-pattern '{ $.event_type = "webhook_signature_failure" }' \
  --log-event-messages '{"event_type":"webhook_signature_failure","timestamp":"2025-01-01T00:00:00Z"}'

# Should return matched events
```

**Fix**:
- Verify JSON log format matches filter pattern
- Check CloudWatch Logs → Log group → Metric filters → Test pattern

### Issue 3: Alarms Not Triggering

**Symptom**: Alarms stay in "Insufficient data" state
**Diagnosis**:
```bash
# Check metric data points
aws cloudwatch get-metric-statistics \
  --namespace "Scribe/Security" \
  --metric-name "WebhookSignatureFailureCount" \
  --start-time "2025-01-01T00:00:00Z" \
  --end-time "2025-01-02T00:00:00Z" \
  --period 300 \
  --statistics Sum

# Should return data points
```

**Fix**:
- Wait 15-30 minutes for metric data to populate
- Trigger security event manually (test endpoint)
- Verify metric filter is active

---

## Appendix B: CloudWatch Logs Insights Cheat Sheet

### All Security Events (Last 24 Hours)
```sql
fields @timestamp, event_type, severity, user_hash, ip_address
| filter event_type in ["webhook_signature_failure", "auth_failure", "credit_anomaly", "encryption_error", "data_exfiltration", "dek_scraping_attempt", "replay_attack"]
| sort @timestamp desc
| limit 100
```

### Hourly Event Counts (Last 7 Days)
```sql
fields event_type
| filter event_type in ["webhook_signature_failure", "auth_failure", "credit_anomaly"]
| stats count() by event_type, bin(1h)
```

### Top 10 IPs by Auth Failures
```sql
fields ip_address
| filter event_type = "auth_failure"
| stats count() as failure_count by ip_address
| sort failure_count desc
| limit 10
```

### Geographic Distribution (if GeoIP data available)
```sql
fields ip_address
| filter event_type = "auth_failure"
| stats count() by ip_address
| sort count() desc
```

---

## Sign-Off

**Calibration Complete When**:
- [ ] 14 days of baseline data collected
- [ ] Statistical thresholds calculated (mean + 3σ)
- [ ] Alarm thresholds adjusted based on baseline
- [ ] All alarms enabled gradually (P3 → P2 → P1 → P0)
- [ ] False positive rate <5% for 7 consecutive days
- [ ] Incident response playbooks tested

**Next Steps**:
- Document baseline data in `docs/BASELINE_DATA_[ENVIRONMENT].md`
- Archive calibration period logs in S3
- Schedule monthly threshold review (next: YYYY-MM-DD)
- Plan quarterly penetration test to validate detection
