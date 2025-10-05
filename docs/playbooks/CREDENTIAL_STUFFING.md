# Incident Response Playbook: Credential Stuffing Attack

**Incident Type:** Authentication Failures / Brute Force / Account Takeover
**Severity:** P0 (Critical) if successful logins detected, P1 (High) if failed attempts only
**MTTD Target:** <5 minutes (P0), <15 minutes (P1)
**MTTR Target:** <30 minutes (P0), <1 hour (P1)
**Owner:** Security Operations Team

## Overview

This playbook addresses credential stuffing attacks where attackers use stolen username/password pairs from external breaches to attempt unauthorized access to user accounts. This attack can lead to account takeover, data exfiltration, fraudulent credit usage, or lateral movement into the payment system.

## Detection Criteria

### Primary Indicators

**CloudWatch Metric Filter:**
```json
{ $.event = "authentication_failure" }
```

**Alert Thresholds:**
- **P0 Alert:** 10+ failed auth attempts for single hashed_user_id within 5 minutes
- **P0 Alert:** 50+ total failed auth attempts across all users within 5 minutes
- **P1 Alert:** 5+ failed auth attempts from single IP within 5 minutes
- **P2 Alert:** 3+ failed auth attempts for single hashed_user_id within 5 minutes

**Prometheus Metrics:**
- `auth_failures_total` > 50 per 5-minute window (system-wide)
- `auth_attempts_per_user` > 10 per 5-minute window (single user)
- `auth_attempts_per_ip` > 5 per 5-minute window (single IP)
- `successful_logins_after_failures` > 0 (successful account takeover)

### Secondary Indicators (Correlation)

- Malicious IP detected by GuardDuty (threat intelligence match)
- Geographic impossibility (login from US, then China within 1 hour)
- Unusual port scanning activity (reconnaissance)
- User-Agent rotation (automated tooling)
- Time-of-day anomaly (3am logins for normally 9-5 user)

### Composite Alarm

```hcl
aws_cloudwatch_composite_alarm "credential_stuffing_attack" {
  alarm_rule = "ALARM(auth_failure_threshold) AND ALARM(malicious_ip_detected)"
  alarm_actions = [aws_sns_topic.security_alerts_p0.arn]
}
```

## Investigation Steps

### Phase 1: Initial Triage (0-5 minutes)

1. **Check Alert Context**
   ```bash
   # CloudWatch Logs Insights query
   fields @timestamp, event, hashed_user_id, attempt_count, source_ip_anonymized
   | filter event = "authentication_failure"
   | stats sum(attempt_count) as total_attempts by hashed_user_id
   | sort total_attempts desc
   | limit 50
   ```

2. **Identify Attack Pattern**
   - Targeted attack? → Few users, many attempts (password spraying)
   - Distributed attack? → Many users, few attempts each (credential stuffing)
   - Single IP? → Brute force from compromised server
   - Multiple IPs? → Botnet, distributed attack

3. **Check for Successful Logins**
   ```bash
   # CRITICAL: Did any attacker succeed?
   fields @timestamp, hashed_user_id, source_ip_anonymized, event
   | filter event = "authentication_success"
   | filter source_ip_anonymized in ["<flagged_ips>"]
   | sort @timestamp desc
   ```

4. **Assess Attack Scope**
   ```bash
   # Count unique users targeted
   fields hashed_user_id
   | filter event = "authentication_failure"
   | stats dc(hashed_user_id) as unique_users_targeted

   # Count unique attacking IPs
   fields source_ip_anonymized
   | filter event = "authentication_failure"
   | stats dc(source_ip_anonymized) as unique_attack_ips
   ```

### Phase 2: Deep Investigation (5-15 minutes)

1. **Analyze Attack Source**
   ```bash
   # Geographic distribution (privacy-safe)
   fields source_ip_anonymized, country_code, attempt_count
   | filter event = "authentication_failure"
   | stats sum(attempt_count) as total_attempts by country_code
   | sort total_attempts desc
   ```

2. **Check Attack Velocity**
   ```bash
   # Attempts per minute (identify peak attack times)
   fields @timestamp
   | filter event = "authentication_failure"
   | stats count() as attempts by bin(1m)
   | sort @timestamp desc
   ```

3. **Correlate with Known Breach Lists**
   - Cross-reference targeted hashed_user_ids with known breach databases (HaveIBeenPwned API)
   - Check if attack timing coincides with recent data breach announcements
   - Review security researcher reports for active campaigns

4. **Review GuardDuty Findings**
   ```bash
   # Check for related GuardDuty alerts
   aws guardduty list-findings \
     --detector-id <detector-id> \
     --finding-criteria '{"Criterion":{"type":{"Eq":["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"]}}}'
   ```

### Phase 3: Threat Validation (15-30 minutes)

1. **Verify Account Takeover Status**
   ```sql
   -- PostgreSQL query via jump host (privacy-safe)
   SELECT
     hashed_user_id,
     COUNT(DISTINCT source_ip_anonymized) as ip_count,
     MIN(created_at) as first_attempt,
     MAX(created_at) as last_attempt,
     SUM(CASE WHEN success = true THEN 1 ELSE 0 END) as successful_logins
   FROM auth_audit_logs
   WHERE created_at > NOW() - INTERVAL '1 hour'
   GROUP BY hashed_user_id
   HAVING COUNT(*) > 10
   ORDER BY successful_logins DESC, COUNT(*) DESC;
   ```

2. **Check Post-Login Activity (if takeover occurred)**
   ```sql
   -- Detect unusual activity from compromised accounts
   SELECT
     hashed_user_id,
     action_type,
     COUNT(*) as action_count
   FROM payment_audit_logs
   WHERE hashed_user_id IN ('<compromised_user_hashes>')
   AND created_at > '<takeover_timestamp>'
   GROUP BY hashed_user_id, action_type;
   ```

3. **Review Session Activity**
   ```bash
   # Check session creation patterns
   fields hashed_user_id, session_id_hash, source_ip_anonymized
   | filter event = "session_created"
   | filter hashed_user_id in ["<compromised_user_hashes>"]
   | stats count() by hashed_user_id, source_ip_anonymized
   ```

4. **Analyze Geographic Anomalies**
   ```sql
   -- Detect geographic impossibility (logins from distant locations within short time)
   WITH user_logins AS (
     SELECT
       hashed_user_id,
       source_ip_anonymized,
       country_code,
       created_at,
       LAG(country_code) OVER (PARTITION BY hashed_user_id ORDER BY created_at) as prev_country,
       LAG(created_at) OVER (PARTITION BY hashed_user_id ORDER BY created_at) as prev_login_time
     FROM auth_audit_logs
     WHERE created_at > NOW() - INTERVAL '24 hours'
     AND success = true
   )
   SELECT *
   FROM user_logins
   WHERE country_code != prev_country
   AND created_at - prev_login_time < INTERVAL '1 hour';
   ```

## Containment Actions

### Immediate (0-5 minutes)

1. **Enable Aggressive Rate Limiting**
   ```rust
   // Emergency rate limit deployment
   // backend/src/routes/auth.rs

   .layer(
       ServiceBuilder::new()
           .layer(GovernorLayer {
               config: Arc::new(
                   GovernorConfigBuilder::default()
                       .per_second(1)  // Reduced from 5
                       .burst_size(3)  // Reduced from 10
                       .finish()
                       .unwrap(),
               ),
           })
   )
   ```
   **Deploy:** `./infrastructure/scripts/deploy/deploy-backend-podman.sh`

2. **Block Attacking IPs**
   ```hcl
   # Terraform: infrastructure/modules/waf/main.tf
   resource "aws_wafv2_ip_set" "credential_stuffing_attackers" {
     name  = "blocked-auth-attack-ips"
     scope = "REGIONAL"
     ip_address_version = "IPV4"
     addresses = [
       "1.2.3.0/24",  # Anonymized subnet from logs
       "4.5.6.0/24",  # Multiple subnets if distributed
     ]
   }

   resource "aws_wafv2_web_acl_rule" "block_auth_attackers" {
     statement {
       ip_set_reference_statement {
         arn = aws_wafv2_ip_set.credential_stuffing_attackers.arn
       }
     }
     action { block {} }
   }
   ```
   **Deploy:** `cd infrastructure && terraform apply -target=module.waf`

3. **Revoke Active Sessions (if takeover confirmed)**
   ```sql
   -- Invalidate sessions for compromised accounts
   DELETE FROM sessions
   WHERE user_id IN (
     SELECT user_id FROM users
     WHERE hashed_user_id IN ('<compromised_user_hashes>')
   );
   ```

   ```rust
   // backend/src/auth/session_management.rs

   // Also clear DEK cache to force re-authentication
   pub async fn revoke_user_sessions(
       auth_backend: &AuthBackend,
       hashed_user_ids: &[String],
   ) -> Result<(), AppError> {
       for hashed_id in hashed_user_ids {
           if let Some(user_id) = resolve_hashed_to_uuid(hashed_id).await? {
               auth_backend.remove_dek_from_cache(user_id).await;
           }
       }
       Ok(())
   }
   ```

### Short-Term (5-30 minutes)

1. **Implement Account Lockout Policy**
   ```rust
   // backend/src/auth/user_store.rs

   // Lock account after 5 failed attempts within 15 minutes
   pub async fn check_account_lockout(
       &self,
       user_id: Uuid,
   ) -> Result<bool, AppError> {
       let failed_attempts = sqlx::query_scalar!(
           "SELECT COUNT(*) FROM auth_audit_logs
            WHERE user_id = $1
            AND success = false
            AND created_at > NOW() - INTERVAL '15 minutes'",
           user_id
       )
       .fetch_one(&self.pool)
       .await?;

       if failed_attempts >= 5 {
           // Set account lockout flag
           sqlx::query!(
               "UPDATE users SET locked_until = NOW() + INTERVAL '1 hour' WHERE id = $1",
               user_id
           )
           .execute(&self.pool)
           .await?;
           return Ok(true);
       }
       Ok(false)
   }
   ```

2. **Enable CAPTCHA for Flagged IPs**
   ```rust
   // backend/src/middleware/captcha.rs

   // Require CAPTCHA after 3 failed attempts from same IP
   pub async fn captcha_middleware(
       ConnectInfo(addr): ConnectInfo<SocketAddr>,
       req: Request<Body>,
       next: Next,
   ) -> Result<Response, AppError> {
       let ip = anonymize_ip(&addr.ip().to_string());
       let recent_failures = count_recent_auth_failures(&ip).await?;

       if recent_failures >= 3 {
           // Verify CAPTCHA token from request headers
           let captcha_token = req.headers()
               .get("X-Captcha-Token")
               .and_then(|h| h.to_str().ok());

           if let Some(token) = captcha_token {
               verify_captcha_token(token).await?;
           } else {
               return Err(AppError::Unauthorized(
                   "CAPTCHA verification required".into()
               ));
           }
       }

       Ok(next.run(req).await)
   }
   ```

3. **Force Password Reset (if takeover confirmed)**
   ```sql
   -- Set password_reset_required flag
   UPDATE users
   SET password_reset_required = true,
       password_reset_token = gen_random_uuid(),
       password_reset_expires_at = NOW() + INTERVAL '24 hours'
   WHERE hashed_user_id IN ('<compromised_user_hashes>');
   ```

4. **Monitor for Lateral Movement**
   - Watch for unusual payment operations from compromised accounts
   - Check for DEK cache access attempts
   - Review credit balance changes
   - Audit character/chat data access patterns

### Long-Term (30min - 24 hours)

1. **Implement Passwordless Authentication** (future)
   - WebAuthn/FIDO2 support
   - Magic link email authentication
   - Biometric authentication for mobile apps

2. **Enable Anomaly Detection**
   - ML-based login pattern analysis (AWS Cognito Advanced Security)
   - Device fingerprinting
   - Behavioral biometrics

3. **Enforce Strong Password Policy**
   ```rust
   // backend/src/auth/password_policy.rs

   pub fn validate_password_strength(password: &str) -> Result<(), AppError> {
       // Minimum 12 characters
       if password.len() < 12 {
           return Err(AppError::BadRequest("Password must be at least 12 characters".into()));
       }

       // Check against common password lists (zxcvbn)
       let estimate = zxcvbn::zxcvbn(password, &[]);
       if estimate.score() < 3 {
           return Err(AppError::BadRequest("Password is too weak".into()));
       }

       // Check against HaveIBeenPwned Passwords API
       if is_password_pwned(password).await? {
           return Err(AppError::BadRequest(
               "Password appears in known data breaches. Please choose a different password.".into()
           ));
       }

       Ok(())
   }
   ```

## Recovery Procedures

### Account Recovery (Compromised Accounts)

1. **Identify Affected Users**
   ```sql
   -- Find users with successful logins during attack window
   SELECT DISTINCT hashed_user_id
   FROM auth_audit_logs
   WHERE success = true
   AND source_ip_anonymized IN ('<attacking_ips>')
   AND created_at BETWEEN '<attack_start>' AND '<attack_end>';
   ```

2. **Audit Unauthorized Actions**
   ```sql
   -- Review actions taken by compromised accounts
   SELECT
     hashed_user_id,
     event_type,
     amount,
     created_at
   FROM payment_audit_logs
   WHERE hashed_user_id IN ('<compromised_user_hashes>')
   AND created_at > '<takeover_timestamp>'
   ORDER BY created_at;
   ```

3. **Rollback Fraudulent Operations**
   ```sql
   -- Reverse unauthorized credit usage
   BEGIN;

   -- Log rollback action
   INSERT INTO payment_audit_logs (
     hashed_user_id, event_type, amount, reason
   ) VALUES (
     '<affected_user_hash>', 'credit_rollback_security', -5000, 'Credential stuffing remediation'
   );

   -- Restore credit balance
   UPDATE credit_balances
   SET balance = balance + 5000
   WHERE hashed_user_id = '<affected_user_hash>';

   COMMIT;
   ```

4. **Notify Affected Users (Privacy-Safe)**
   ```sql
   -- Get notification targets (internal mapping only)
   SELECT user_id FROM users
   WHERE hashed_user_id IN ('<compromised_user_hashes>');
   ```

   **Email Template:**
   ```
   Subject: Security Alert - Password Reset Required

   We detected unusual login activity on your Sanguine Scribe account and have
   temporarily locked it to protect your data. Please reset your password using
   the link below:

   [Password Reset Link]

   If you did not request this, please contact security@sanguinescribe.com.

   Security Team
   ```

### Service Restoration

1. **Remove Emergency Blocks** (after attack subsides)
   - Restore normal rate limits (5/sec, 10 burst)
   - Remove temporary IP blocks after 24-48 hours
   - Remove CAPTCHA requirement for previously blocked IPs

2. **Unlock Legitimate Accounts**
   ```sql
   -- Unlock accounts that were locked due to attack
   UPDATE users
   SET locked_until = NULL
   WHERE locked_until IS NOT NULL
   AND locked_until < NOW();
   ```

3. **Update Detection Baselines**
   - Exclude attack window from baseline calculations
   - Adjust lockout thresholds if false positives occurred
   - Update geographic anomaly rules with new patterns

## Post-Incident Review

### Evidence Collection

1. **Archive Attack Logs**
   ```bash
   # Export CloudWatch logs to S3 (tamper-proof)
   aws logs create-export-task \
     --log-group-name /aws/scribe/auth \
     --from <attack_start_epoch> \
     --to <attack_end_epoch> \
     --destination scribe-security-incident-logs \
     --destination-prefix credential-stuffing-$(date +%Y%m%d)
   ```

2. **Extract Attacker IOCs**
   ```bash
   # Anonymized IP ranges
   fields source_ip_anonymized
   | filter event = "authentication_failure"
   | stats count() by source_ip_anonymized
   | filter count > 10
   | sort count desc
   > attacker_ips.txt

   # User-Agent strings (identify attack tools)
   fields user_agent
   | filter event = "authentication_failure"
   | stats count() by user_agent
   | sort count desc
   > attacker_user_agents.txt
   ```

3. **Document Attack Characteristics**
   - Total failed attempts
   - Unique users targeted
   - Unique attacking IPs
   - Attack duration
   - Successful account takeovers
   - Fraudulent operations performed

### Root Cause Analysis

**Questions to Answer:**
1. Was this a targeted attack or opportunistic? (User list from breach vs. random attempts)
2. How were credentials obtained? (Data breach, phishing, malware)
3. Were rate limits effective? (MTTD vs. attack velocity)
4. Did account lockout prevent takeovers? (Success rate analysis)
5. Were there any false positives? (Legitimate users locked out)

### Preventive Measures

1. **Code-Level Improvements**
   - Implement progressive rate limiting (exponential backoff)
   - Add device fingerprinting (browser/OS/timezone consistency)
   - Implement anomaly-based account lockout (geographic, time-of-day)
   - Add HaveIBeenPwned password validation on registration/reset

2. **Infrastructure Hardening**
   - Enable AWS WAF Rate-Based Rules for `/api/auth/login`
   - Implement distributed rate limiting (Redis cluster)
   - Add CloudFront geographic restrictions (if applicable)
   - Deploy AWS Shield Advanced for DDoS protection

3. **Monitoring Enhancements**
   - Lower detection threshold for targeted attacks (5 attempts vs. 10)
   - Add ML-based anomaly detection (AWS Cognito Advanced Security)
   - Create dashboard for real-time authentication metrics
   - Implement automated account lockout on P0 alerts

4. **User Education**
   - Email notification about password security best practices
   - Encourage 2FA/MFA enrollment (future feature)
   - Provide breach notification sign-up (HaveIBeenPwned alerts)
   - Display last login location/time on dashboard

### Compliance Reporting

**OWASP A09 Compliance:** Log all authentication failures with:
- Timestamp
- Hashed user ID (privacy-safe)
- Source IP (anonymized)
- Attempt count
- Success/failure status

**PCI DSS Requirement 8:** Document incident in audit log with:
- Date/time of incident
- Type of event (credential stuffing attack)
- Success/failure of account takeover
- Identity of affected systems (authentication service)
- Origination of event (anonymized IP ranges)

**Incident Report Template:**
```markdown
## Credential Stuffing Incident Report

**Incident ID:** INC-CRED-<YYYYMMDD>-<seq>
**Date/Time:** <UTC timestamp>
**Severity:** P0/P1
**MTTD:** <actual minutes>
**MTTR:** <actual minutes>

### Summary
[Brief description of attack pattern and impact]

### Timeline
- [HH:MM] Attack detected via CloudWatch alarm
- [HH:MM] Investigation initiated
- [HH:MM] Containment actions deployed (rate limits, IP blocks)
- [HH:MM] Compromised accounts identified
- [HH:MM] Sessions revoked, password resets forced
- [HH:MM] Attack subsided
- [HH:MM] Service restored

### Impact
- Total failed authentication attempts: <count>
- Unique users targeted: <count>
- Successful account takeovers: <count>
- Fraudulent operations: <count>
- Attack duration: <minutes>

### Root Cause
[Analysis from RCA section]

### Preventive Actions
[List of implemented improvements]

### Compliance Notes
- OWASP A09: All authentication failures logged
- PCI DSS Req 8: Incident documented in tamper-proof audit trail
- GDPR Article 32: No PII exposed during investigation
```

## Escalation Matrix

| Condition | Escalate To | Timeline |
|-----------|-------------|----------|
| >100 failed auth attempts in 5min | Security Operations Manager | Immediate |
| Confirmed account takeover | CISO, VP Engineering | Within 5min |
| >10 successful takeovers | Incident Commander, Legal, PR | Within 15min |
| Fraudulent credit usage detected | CFO, Finance team | Within 30min |
| Attack duration >1 hour | AWS Support, DDoS mitigation team | Within 1hr |

## Checklist

- [ ] Alert received and acknowledged
- [ ] Initial triage completed (attack pattern identified)
- [ ] Successful account takeovers confirmed/ruled out
- [ ] Containment actions deployed (rate limits, IP blocks, CAPTCHA)
- [ ] Compromised accounts identified
- [ ] Active sessions revoked for compromised accounts
- [ ] Password reset forced for compromised accounts
- [ ] Fraudulent operations audited and rolled back
- [ ] Affected users notified (privacy-safe)
- [ ] Service restored to normal operations
- [ ] Evidence archived to tamper-proof storage
- [ ] IOCs extracted and shared with threat intelligence
- [ ] Post-incident review scheduled (within 48 hours)
- [ ] Preventive measures implemented
- [ ] Documentation updated
- [ ] Compliance reporting completed
- [ ] Team debriefing conducted

## References

- [SECURITY_MONITORING.md](../SECURITY_MONITORING.md) - Full architecture
- [OWASP-TOP-10.md](../OWASP-TOP-10.md) - A07 Identification and Authentication Failures
- [PRIVACY_SAFE_LOGGING.md](../PRIVACY_SAFE_LOGGING.md) - Hashed user ID logging
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) - Digital Identity Guidelines
- [HaveIBeenPwned API](https://haveibeenpwned.com/API/v3) - Password breach detection
