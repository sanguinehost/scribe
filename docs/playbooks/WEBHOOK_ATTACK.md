# Incident Response Playbook: Webhook Attack

**Incident Type:** Webhook Signature Verification Failures / Replay Attacks
**Severity:** P1 (High)
**MTTD Target:** <15 minutes
**MTTR Target:** <1 hour
**Owner:** Security Operations Team

## Overview

This playbook addresses attacks targeting Paddle webhook endpoints through signature verification bypass attempts, replay attacks, or webhook spoofing. Webhook attacks can lead to unauthorized credit allocations, fraudulent subscription activations, or payment processing manipulation.

## Detection Criteria

### Primary Indicators

**CloudWatch Metric Filter:**
```json
{ $.event = "webhook_signature_failure" }
```

**Alert Threshold:**
- **P1 Alert:** 5+ signature failures from single IP within 5 minutes
- **P1 Alert:** 20+ total signature failures within 15 minutes (distributed attack)
- **P2 Alert:** 3+ signature failures from single IP within 5 minutes

**Prometheus Metrics:**
- `webhook_signature_failures_total` > 5 per 5-minute window
- `webhook_processing_time_seconds` > 10s (possible computational DoS)

### Secondary Indicators (Correlation)

- Same `event_id` appearing multiple times (replay attack)
- Webhook requests from non-Paddle IP ranges (spoofing)
- Malformed webhook JSON structures
- Unusual geographic origin (cross-reference with GuardDuty threat intel)
- Spike in 401/403 responses on `/api/payment/webhook`

### Composite Alarm

```hcl
aws_cloudwatch_composite_alarm "webhook_attack_confirmed" {
  alarm_rule = "ALARM(webhook_sig_failure_threshold) AND ALARM(malicious_ip_detected)"
  alarm_actions = [aws_sns_topic.security_alerts_p1.arn]
}
```

## Investigation Steps

### Phase 1: Initial Triage (0-5 minutes)

1. **Check Alert Context**
   ```bash
   # CloudWatch Logs Insights query
   fields @timestamp, event, source_ip_anonymized, event_id, error_detail
   | filter event = "webhook_signature_failure"
   | stats count() by source_ip_anonymized
   | sort count desc
   | limit 20
   ```

2. **Identify Attack Pattern**
   - Single IP brute-force? → Credential stuffing variant
   - Multiple IPs? → Distributed attack / botnet
   - Repeated event_id? → Replay attack
   - Malformed JSON? → API fuzzing / reconnaissance

3. **Check Paddle Service Status**
   - Verify Paddle.com operational status
   - Confirm webhook secret hasn't been rotated (check AWS Secrets Manager)
   - Cross-reference with Paddle security notifications

4. **Assess Impact Scope**
   ```bash
   # Count affected webhook events
   fields @timestamp, event, event_id
   | filter event = "webhook_signature_failure"
   | stats count() by bin(5m)
   ```

### Phase 2: Deep Investigation (5-15 minutes)

1. **Analyze Attack Source**
   ```bash
   # Geographic distribution (privacy-safe)
   fields source_ip_anonymized, country_code
   | filter event = "webhook_signature_failure"
   | stats count() by country_code
   ```

2. **Check for Replay Attacks**
   ```bash
   # Duplicate event_id detection
   fields event_id, @timestamp
   | filter event = "webhook_signature_failure"
   | stats count() by event_id
   | filter count > 1
   ```

3. **Correlate with Successful Webhooks**
   ```bash
   # Check if any webhooks succeeded from same IPs
   fields event, source_ip_anonymized, hashed_user_id
   | filter source_ip_anonymized in ["<flagged_ips>"]
   | stats count() by event
   ```

4. **Review GuardDuty Findings**
   - Check for IoC matches (malicious IPs, known botnets)
   - Look for related AWS account reconnaissance activity
   - Cross-reference with threat intelligence feeds

### Phase 3: Threat Validation (15-30 minutes)

1. **Validate No Successful Bypasses**
   ```sql
   -- PostgreSQL query via jump host (privacy-safe)
   SELECT
     DATE_TRUNC('minute', created_at) as minute,
     COUNT(*) as credit_operations
   FROM payment_audit_logs
   WHERE created_at > NOW() - INTERVAL '1 hour'
   AND event_type IN ('credit_added', 'payment_processed')
   GROUP BY minute
   HAVING COUNT(*) > 50;  -- Anomaly threshold
   ```

2. **Check Credit Balance Anomalies**
   ```sql
   -- Detect unusual credit allocations (hashed user IDs only)
   SELECT
     hashed_user_id,
     COUNT(*) as operations,
     SUM(amount) as total_credits
   FROM payment_audit_logs
   WHERE created_at > NOW() - INTERVAL '1 hour'
   GROUP BY hashed_user_id
   HAVING COUNT(*) > 10 OR SUM(amount) > 100000;
   ```

3. **Review Application Logs for Errors**
   ```bash
   # Check for internal errors during attack window
   fields @timestamp, level, message
   | filter level = "ERROR" and @timestamp > <attack_start_time>
   | stats count() by message
   ```

## Containment Actions

### Immediate (0-15 minutes)

1. **Rate Limit Webhook Endpoint**
   ```rust
   // Emergency rate limit deployment
   // backend/src/routes/payment.rs

   // Reduce from 100/min to 10/min per IP
   .layer(
       ServiceBuilder::new()
           .layer(GovernorLayer {
               config: Arc::new(
                   GovernorConfigBuilder::default()
                       .per_second(1)
                       .burst_size(10)  // Reduced from 100
                       .finish()
                       .unwrap(),
               ),
           })
   )
   ```
   **Deploy:** `./infrastructure/scripts/deploy/deploy-backend-podman.sh`

2. **Block Malicious IPs (if concentrated)**
   ```hcl
   # Terraform: infrastructure/modules/waf/main.tf
   resource "aws_wafv2_ip_set" "blocked_webhook_attackers" {
     name  = "blocked-webhook-ips"
     scope = "REGIONAL"
     ip_address_version = "IPV4"
     addresses = [
       "1.2.3.0/24",  # Anonymized subnet from logs
     ]
   }

   resource "aws_wafv2_web_acl_rule" "block_webhook_attackers" {
     # Block IPs for webhook path only
     statement {
       ip_set_reference_statement {
         arn = aws_wafv2_ip_set.blocked_webhook_attackers.arn
       }
     }
     action { block {} }
   }
   ```
   **Deploy:** `cd infrastructure && terraform apply -target=module.waf`

3. **Increase Webhook Signature Validation**
   ```rust
   // backend/src/services/payment/webhook_validator.rs

   // Add timestamp validation (reject >5min old)
   if webhook_timestamp.elapsed() > Duration::from_secs(300) {
       return Err(AppError::Unauthorized("Webhook timestamp expired".into()));
   }

   // Add event_id deduplication (Redis cache)
   if event_id_cache.contains(&webhook.event_id) {
       return Err(AppError::Conflict("Duplicate webhook event_id".into()));
   }
   ```

### Short-Term (15-60 minutes)

1. **Rotate Webhook Secret (if compromised)**
   ```bash
   # Generate new webhook secret in Paddle dashboard
   # Update AWS Secrets Manager
   aws secretsmanager update-secret \
     --secret-id staging-scribe-paddle-webhook \
     --secret-string '{"webhook_secret":"new_secret_value"}'

   # Redeploy backend with new secret
   ./infrastructure/scripts/deploy/deploy-backend-podman.sh
   ```

2. **Enable Paddle IP Allowlisting**
   ```hcl
   # WAF rule to only allow Paddle's documented IP ranges
   resource "aws_wafv2_ip_set" "paddle_webhook_ips" {
     name  = "paddle-webhook-allowlist"
     scope = "REGIONAL"
     ip_address_version = "IPV4"
     addresses = [
       # Paddle's webhook IPs (update from Paddle docs)
       "34.194.127.46/32",
       "52.5.251.86/32",
     ]
   }

   resource "aws_wafv2_web_acl_rule" "allow_only_paddle_webhooks" {
     statement {
       and_statement {
         statements = [
           { byte_match_statement {
             field_to_match { uri_path {} }
             positional_constraint = "EXACTLY"
             search_string = "/api/payment/webhook"
           }},
           { not_statement {
             statement {
               ip_set_reference_statement {
                 arn = aws_wafv2_ip_set.paddle_webhook_ips.arn
               }
             }
           }}
         ]
       }
     }
     action { block {} }
   }
   ```

3. **Monitor for Lateral Movement**
   - Check auth failure rates (credential stuffing follow-up)
   - Review DEK cache access patterns (data exfiltration attempt)
   - Audit unusual database queries from application layer

## Recovery Procedures

### Data Integrity Verification

1. **Audit Credit Transactions During Attack Window**
   ```sql
   -- Identify all credit operations during incident
   SELECT
     hashed_user_id,
     event_type,
     amount,
     external_reference_hash,
     created_at
   FROM payment_audit_logs
   WHERE created_at BETWEEN '<attack_start>' AND '<attack_end>'
   ORDER BY created_at DESC;
   ```

2. **Cross-Reference with Paddle Transaction Log**
   - Export Paddle transaction history for incident timeframe
   - Compare external_reference_hash values
   - Identify any credit allocations without valid Paddle transaction

3. **Rollback Fraudulent Credits (if bypass occurred)**
   ```sql
   -- Reverse unauthorized credit allocations
   BEGIN;

   -- Log rollback action
   INSERT INTO payment_audit_logs (
     hashed_user_id, event_type, amount, reason
   ) VALUES (
     '<affected_user_hash>', 'credit_rollback_security', -50000, 'Webhook attack remediation'
   );

   -- Update credit balance
   UPDATE credit_balances
   SET balance = balance - 50000
   WHERE hashed_user_id = '<affected_user_hash>';

   COMMIT;
   ```

### Service Restoration

1. **Remove Emergency Rate Limits** (after attack subsides)
   - Restore normal rate limits (100/min per IP)
   - Remove temporary IP blocks after 24 hours
   - Re-enable webhook processing if temporarily disabled

2. **Update Detection Baselines**
   - Exclude attack window from baseline calculations
   - Adjust thresholds if false positive rate too high
   - Update correlation rules with new attack patterns

3. **User Notification (Privacy-Safe)**
   - **IF fraudulent credits allocated:** Send generic security notification to affected users via hashed_user_id mapping (internal only)
   - **NO PII in notifications:** "We detected unusual account activity. Your account security has been verified."
   - **Do NOT mention attack details** to avoid panic

## Post-Incident Review

### Evidence Collection

1. **Archive Attack Logs**
   ```bash
   # Export CloudWatch logs to S3 (tamper-proof)
   aws logs create-export-task \
     --log-group-name /aws/scribe/payment \
     --from <attack_start_epoch> \
     --to <attack_end_epoch> \
     --destination scribe-security-incident-logs \
     --destination-prefix webhook-attack-$(date +%Y%m%d)
   ```

2. **Save Prometheus Metrics Snapshot**
   ```bash
   # Export metrics data for forensic analysis
   curl -G 'http://prometheus:9090/api/v1/query_range' \
     --data-urlencode 'query=webhook_signature_failures_total' \
     --data-urlencode 'start=<attack_start>' \
     --data-urlencode 'end=<attack_end>' \
     --data-urlencode 'step=60' > webhook_attack_metrics.json
   ```

3. **Document Attack Characteristics**
   - Source IP ranges (anonymized)
   - Attack volume (requests/min)
   - Attack duration
   - Exploit techniques attempted
   - Success/failure of containment actions

### Root Cause Analysis

**Questions to Answer:**
1. How did attacker discover webhook endpoint? (Publicly documented vs. reconnaissance)
2. Was webhook secret compromised? (Check for secret exposure in GitHub, logs, etc.)
3. Could signature validation be strengthened? (Add timestamp checks, nonce deduplication)
4. Were detection thresholds appropriate? (MTTD actual vs. target)
5. Did WAF rules provide adequate protection?

### Preventive Measures

1. **Code-Level Improvements**
   - Implement event_id deduplication (Redis cache with 24hr TTL)
   - Add webhook timestamp validation (reject >5min old)
   - Strengthen signature algorithm (HMAC-SHA512 vs. SHA256)
   - Add secondary validation (webhook IP allowlist check)

2. **Infrastructure Hardening**
   - Enable AWS WAF managed rule for known attack patterns
   - Implement Paddle IP allowlisting (if attack from non-Paddle IPs)
   - Add CloudFront layer with geographic restrictions (if applicable)
   - Enable AWS Shield Advanced for DDoS protection

3. **Monitoring Enhancements**
   - Lower detection threshold if attack went undetected initially
   - Add correlation with GuardDuty findings (automated response)
   - Implement anomaly detection for webhook processing times
   - Create dashboard for real-time webhook security metrics

4. **Documentation Updates**
   - Update webhook security architecture diagram
   - Document new attack patterns in threat model
   - Share findings with Paddle security team (responsible disclosure)
   - Update SECURITY_MONITORING.md with lessons learned

### Compliance Reporting

**PCI DSS Requirement 10:** Document incident in audit log with:
- Date/time of incident
- Type of event (webhook signature verification failures)
- Success/failure of exploit attempts
- Identity of affected systems (payment webhook endpoint)
- Origination of event (anonymized IP ranges)

**Incident Report Template:**
```markdown
## Webhook Attack Incident Report

**Incident ID:** INC-WEBHOOK-<YYYYMMDD>-<seq>
**Date/Time:** <UTC timestamp>
**Severity:** P1
**MTTD:** <actual minutes>
**MTTR:** <actual minutes>

### Summary
[Brief description of attack pattern and impact]

### Timeline
- [HH:MM] Attack detected via CloudWatch alarm
- [HH:MM] Investigation initiated
- [HH:MM] Containment actions deployed
- [HH:MM] Attack subsided
- [HH:MM] Service restored

### Impact
- Total webhook signature failures: <count>
- Attack duration: <minutes>
- Fraudulent credits allocated: <count> (if any)
- Users affected: <count> (hashed IDs only)

### Root Cause
[Analysis from RCA section]

### Preventive Actions
[List of implemented improvements]

### Compliance Notes
- PCI DSS Req 10: Logged to tamper-proof audit trail
- GDPR Article 32: No PII exposed during investigation
- OWASP A09: Incident logged with sufficient user context (hashed IDs)
```

## Escalation Matrix

| Condition | Escalate To | Timeline |
|-----------|-------------|----------|
| >100 signature failures in 5min | VP Engineering | Immediate |
| Confirmed bypass (fraudulent credits) | CISO, Legal | Within 15min |
| Distributed attack (>50 IPs) | AWS Support, Paddle Support | Within 30min |
| Suspected webhook secret compromise | Rotate secret immediately, notify executives | Within 1hr |
| Attack duration >2 hours | Incident Commander, PR team | Within 2hrs |

## Checklist

- [ ] Alert received and acknowledged
- [ ] Initial triage completed (attack pattern identified)
- [ ] Impact assessment completed (no unauthorized credits confirmed)
- [ ] Containment actions deployed (rate limits, IP blocks)
- [ ] Paddle service status verified
- [ ] Webhook secret rotation (if required)
- [ ] Recovery procedures executed (fraudulent credits reversed)
- [ ] Service restored to normal operations
- [ ] Evidence archived to tamper-proof storage
- [ ] Post-incident review scheduled (within 48 hours)
- [ ] Preventive measures implemented
- [ ] Documentation updated
- [ ] Compliance reporting completed
- [ ] Team debriefing conducted

## References

- [SECURITY_MONITORING.md](../SECURITY_MONITORING.md) - Full architecture
- [OWASP-TOP-10.md](../OWASP-TOP-10.md) - A09 Security Logging
- [Paddle Webhook Security Docs](https://developer.paddle.com/webhooks/signature-verification)
- [AWS WAF Best Practices](https://docs.aws.amazon.com/waf/latest/developerguide/security-best-practices.html)
- [PCI DSS Requirement 10](https://www.pcisecuritystandards.org/document_library)
