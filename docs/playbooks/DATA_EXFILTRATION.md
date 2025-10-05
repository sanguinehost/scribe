# Incident Response Playbook: Data Exfiltration

**Incident Type:** Bulk Data Access / Unauthorized Queries / Training Data Theft
**Severity:** P0 (Critical)
**MTTD Target:** <5 minutes
**MTTR Target:** <30 minutes
**Owner:** Security Operations Team + Data Protection Officer

## Overview

This playbook addresses unauthorized attempts to extract user data, including:
- Bulk chat message access (conversation scraping)
- Character data harvesting (training data theft)
- User persona enumeration
- Lorebook/world-building content theft
- Database credential compromise
- API abuse for data aggregation

**Critical Note:** All data is encrypted at rest with per-user DEKs. Exfiltration requires either:
1. Active authenticated session (DEK in memory)
2. Compromised DEK cache
3. Password/recovery phrase compromise
4. Database export with user credentials

## Detection Criteria

### Primary Indicators

**CloudWatch Metric Filter:**
```json
{ $.event = "data_access_anomaly" }
```

**Alert Thresholds:**
- **P0 Alert:** >1000 chat messages accessed within 5 minutes (single user)
- **P0 Alert:** >100 character records accessed within 5 minutes (single user)
- **P0 Alert:** Database query returning >10,000 rows (bulk export attempt)
- **P1 Alert:** API requests to list endpoints >100/minute (enumeration)
- **P2 Alert:** Off-hours access (3am-6am local time) with >50 records retrieved

**Prometheus Metrics:**
- `chat_message_access_rate` > 1000 per 5-minute window
- `character_list_pagination_rate` > 20 pages per minute
- `database_query_row_count` > 10,000 rows returned
- `api_list_endpoint_calls` > 100 per minute

### Secondary Indicators (Correlation)

- DEK cache access spike (>100 cache hits in 5 minutes)
- Unusual database connection source (non-application IP)
- Sequential ID enumeration (accessing character IDs 1, 2, 3, ... N)
- Scraping user-agent patterns ("python-requests", "curl", "wget")
- Geographic anomaly (access from new country)
- Time-of-day anomaly (3am access for normally 9am-5pm user)

### Composite Alarm

```hcl
aws_cloudwatch_composite_alarm "data_exfiltration_detected" {
  alarm_rule = "ALARM(bulk_data_access) AND
                (ALARM(dek_cache_spike) OR ALARM(off_hours_access))"
  alarm_actions = [
    aws_sns_topic.security_alerts_p0.arn,
    aws_sns_topic.dpo_alerts.arn  # Data Protection Officer
  ]
}
```

## Investigation Steps

### Phase 1: Initial Triage (0-5 minutes)

1. **Check Alert Context**
   ```bash
   # CloudWatch Logs Insights query
   fields @timestamp, event, hashed_user_id, access_pattern, record_count
   | filter event = "data_access_anomaly"
   | sort @timestamp desc
   | limit 50
   ```

2. **Identify Access Pattern**
   - Bulk API calls? → Automated scraping, API abuse
   - Database query? → SQL injection, compromised credentials
   - DEK cache access? → Session hijacking, memory dump
   - Sequential access? → Enumeration attack

3. **Check Data Type Accessed**
   ```bash
   # Categorize accessed data types
   fields @timestamp, hashed_user_id, data_type, record_count
   | filter event = "data_access_anomaly"
   | stats sum(record_count) as total_records by data_type
   | sort total_records desc
   ```

4. **Assess Exfiltration Scope**
   ```sql
   -- PostgreSQL query via jump host
   -- Count records accessed during anomaly window
   SELECT
     'chat_messages' as data_type,
     COUNT(*) as records_accessed
   FROM chat_message_access_log  -- If logging implemented
   WHERE accessed_at BETWEEN '<anomaly_start>' AND NOW()
   AND hashed_user_id IN ('<flagged_user_hashes>')

   UNION ALL

   SELECT
     'characters' as data_type,
     COUNT(*) as records_accessed
   FROM character_access_log
   WHERE accessed_at BETWEEN '<anomaly_start>' AND NOW()
   AND hashed_user_id IN ('<flagged_user_hashes>');
   ```

### Phase 2: Deep Investigation (5-15 minutes)

1. **Analyze API Access Patterns**
   ```bash
   # CloudWatch API access log analysis
   fields @timestamp, hashed_user_id, endpoint, method, status_code, response_size
   | filter hashed_user_id in ["<flagged_user_hashes>"]
   | filter @timestamp > <anomaly_start_timestamp>
   | stats
       count() as request_count,
       sum(response_size) as total_bytes,
       avg(response_size) as avg_response_size
     by endpoint
   | sort total_bytes desc
   ```

2. **Check for Sequential Enumeration**
   ```bash
   # Detect ID enumeration patterns
   fields @timestamp, endpoint, query_params
   | filter hashed_user_id = "<flagged_user_hash>"
   | filter endpoint like "/api/characters/"
   | parse query_params /character_id=(?<char_id>\d+)/
   | stats count() by char_id
   | sort char_id
   # If char_ids are 1, 2, 3, 4... → enumeration attack
   ```

3. **Review DEK Cache Access**
   ```bash
   # Check DEK cache hit patterns
   fields @timestamp, event, hashed_user_id, dek_cache_hits
   | filter event = "dek_cache_access"
   | filter hashed_user_id in ["<flagged_user_hashes>"]
   | stats sum(dek_cache_hits) as total_hits by bin(1m)
   | sort @timestamp
   # Spike >100 hits/min → bulk decryption attempt
   ```

4. **Check Database Access Logs**
   ```sql
   -- PostgreSQL: Review pg_stat_statements for unusual queries
   SELECT
     userid::regrole,
     dbid,
     query,
     calls,
     total_exec_time,
     rows
   FROM pg_stat_statements
   WHERE query LIKE '%chat_messages%'
   OR query LIKE '%characters%'
   OR query LIKE '%user_personas%'
   ORDER BY rows DESC
   LIMIT 50;

   -- Look for queries returning >10k rows (bulk export)
   ```

### Phase 3: Threat Validation (15-30 minutes)

1. **Verify Data Encryption Integrity**
   ```sql
   -- Confirm all accessed data was encrypted at rest
   SELECT
     id,
     content IS NULL as is_encrypted,  -- NULL = encrypted BYTEA
     content_nonce IS NOT NULL as has_nonce
   FROM chat_messages
   WHERE id IN (
     SELECT message_id FROM chat_message_access_log
     WHERE accessed_at > '<anomaly_start>'
     AND hashed_user_id IN ('<flagged_user_hashes>')
   )
   LIMIT 100;

   -- If content is readable plaintext → CRITICAL: encryption bypass
   ```

2. **Check for Data Export Attempts**
   ```bash
   # Look for large response bodies (bulk data)
   fields @timestamp, endpoint, response_size, compression
   | filter hashed_user_id = "<flagged_user_hash>"
   | filter response_size > 1048576  # >1MB
   | stats sum(response_size) as total_export_size
   # Total >100MB → likely exfiltration attempt
   ```

3. **Analyze Network Traffic** (if CloudWatch VPC Flow Logs enabled)
   ```bash
   # Check for unusual egress traffic
   aws ec2 describe-flow-logs --filter "Name=resource-id,Values=<eni-id>"

   # Look for large data transfers to external IPs
   # (requires VPC Flow Logs + CloudWatch Insights integration)
   ```

4. **Review Session Validity**
   ```sql
   -- Check if exfiltration came from legitimate session
   SELECT
     s.id as session_id,
     s.user_id,
     s.created_at,
     s.expires_at,
     s.last_accessed_at,
     u.hashed_user_id
   FROM sessions s
   JOIN users u ON s.user_id = u.id
   WHERE u.hashed_user_id IN ('<flagged_user_hashes>')
   AND s.last_accessed_at > '<anomaly_start>';

   -- If session expired or never existed → session hijacking
   ```

5. **Check for Credential Compromise**
   ```bash
   # Look for password changes, recovery phrase usage
   fields @timestamp, event, hashed_user_id, reason
   | filter hashed_user_id in ["<flagged_user_hashes>"]
   | filter event in ["password_changed", "recovery_phrase_used", "dek_decrypted"]
   | sort @timestamp
   ```

## Containment Actions

### Immediate (0-5 minutes)

1. **Revoke Active Sessions**
   ```sql
   -- Invalidate all sessions for affected users
   DELETE FROM sessions
   WHERE user_id IN (
     SELECT id FROM users WHERE hashed_user_id IN ('<flagged_user_hashes>')
   );
   ```

   ```rust
   // Clear DEK cache immediately
   // backend/src/auth/mod.rs

   pub async fn emergency_dek_cache_clear(
       auth_backend: &AuthBackend,
       hashed_user_ids: &[String],
   ) -> Result<(), AppError> {
       for hashed_id in hashed_user_ids {
           if let Some(user_id) = resolve_hashed_to_uuid(hashed_id).await? {
               auth_backend.remove_dek_from_cache(user_id).await;
               tracing::warn!(
                   hashed_user_id = %hashed_id,
                   "DEK evicted from cache due to exfiltration alert"
               );
           }
       }
       Ok(())
   }
   ```

2. **Block API Access**
   ```rust
   // Emergency rate limit to 1 request/minute
   // backend/src/routes/api.rs

   .layer(
       ServiceBuilder::new()
           .layer(GovernorLayer {
               config: Arc::new(
                   GovernorConfigBuilder::default()
                       .per_minute(1)  # Drastically reduced
                       .burst_size(1)
                       .finish()
                       .unwrap(),
               ),
           })
   )
   ```

3. **Freeze Affected Accounts**
   ```sql
   UPDATE users
   SET
     account_frozen = true,
     frozen_reason = 'Data exfiltration investigation - contact security@sanguinescribe.com',
     frozen_at = NOW()
   WHERE hashed_user_id IN ('<flagged_user_hashes>');
   ```

4. **Block Source IPs** (if concentrated)
   ```hcl
   # Terraform WAF rule
   resource "aws_wafv2_ip_set" "data_exfiltration_ips" {
     name  = "blocked-exfiltration-ips"
     scope = "REGIONAL"
     ip_address_version = "IPV4"
     addresses = ["<anonymized_ip_subnets>"]
   }
   ```

### Short-Term (5-30 minutes)

1. **Enable Query Logging** (if not already enabled)
   ```sql
   -- PostgreSQL: Enable full query logging temporarily
   ALTER SYSTEM SET log_statement = 'all';
   ALTER SYSTEM SET log_min_duration_statement = 0;
   SELECT pg_reload_conf();
   ```

2. **Implement Data Access Auditing**
   ```rust
   // backend/src/middleware/data_access_audit.rs

   pub async fn audit_data_access(
       session: Session,
       req: Request<Body>,
       next: Next,
   ) -> Result<Response, AppError> {
       let user_id = session.get_user_id()?;
       let endpoint = req.uri().path();
       let method = req.method();

       // Execute request
       let start = Instant::now();
       let response = next.run(req).await;
       let duration = start.elapsed();

       // Log data access
       tracing::info!(
           hashed_user_id = %loggable_user_id(user_id),
           endpoint = endpoint,
           method = %method,
           duration_ms = duration.as_millis(),
           status = response.status().as_u16(),
           "Data access audit log"
       );

       // Check for anomalies
       if is_bulk_access_pattern(endpoint, &response).await? {
           tracing::error!(
               hashed_user_id = %loggable_user_id(user_id),
               endpoint = endpoint,
               "Bulk data access detected - possible exfiltration"
           );
           // Trigger alert
       }

       Ok(response)
   }
   ```

3. **Restrict Database Access**
   ```sql
   -- PostgreSQL: Revoke read permissions temporarily
   REVOKE SELECT ON chat_messages FROM scribe_app_user;
   REVOKE SELECT ON characters FROM scribe_app_user;

   -- Grant only necessary permissions
   GRANT SELECT ON chat_messages TO scribe_app_user
   WHERE user_id = CURRENT_USER_ID();  -- Row-level security

   -- Re-enable after investigation
   ```

4. **Enable Response Size Limits**
   ```rust
   // backend/src/middleware/response_size_limit.rs

   pub async fn limit_response_size(
       req: Request<Body>,
       next: Next,
   ) -> Result<Response, AppError> {
       let response = next.run(req).await;
       let content_length = response.headers()
           .get(CONTENT_LENGTH)
           .and_then(|h| h.to_str().ok())
           .and_then(|s| s.parse::<usize>().ok())
           .unwrap_or(0);

       // Limit individual responses to 10MB
       if content_length > 10_485_760 {
           return Err(AppError::PayloadTooLarge(
               "Response size exceeds limit. Use pagination.".into()
           ));
       }

       Ok(response)
   }
   ```

### Long-Term (30min - 7 days)

1. **Force Password Reset** (if credential compromise suspected)
   ```sql
   UPDATE users
   SET
     password_reset_required = true,
     password_reset_token = gen_random_uuid(),
     password_reset_expires_at = NOW() + INTERVAL '24 hours'
   WHERE hashed_user_id IN ('<compromised_user_hashes>');
   ```

2. **Rotate DEK** (if DEK compromise suspected)
   ```rust
   // backend/src/crypto/dek_rotation.rs

   pub async fn rotate_user_dek(
       user_id: Uuid,
       old_password: &str,
       new_password: &str,
   ) -> Result<(), AppError> {
       // 1. Decrypt old DEK
       let old_kek = derive_kek(old_password, &user.kek_salt)?;
       let plaintext_dek = decrypt_dek(&user.encrypted_dek, &user.dek_nonce, &old_kek)?;

       // 2. Re-encrypt all user data with new DEK
       let new_dek = generate_dek()?;
       re_encrypt_user_data(user_id, &plaintext_dek, &new_dek).await?;

       // 3. Encrypt new DEK with new KEK
       let new_kek_salt = generate_salt()?;
       let new_kek = derive_kek(new_password, &new_kek_salt)?;
       let (new_encrypted_dek, new_dek_nonce) = encrypt_dek(&new_dek, &new_kek)?;

       // 4. Update database
       sqlx::query!(
           "UPDATE users SET encrypted_dek = $1, dek_nonce = $2, kek_salt = $3
            WHERE id = $4",
           new_encrypted_dek, new_dek_nonce, new_kek_salt, user_id
       ).execute(&pool).await?;

       Ok(())
   }

   async fn re_encrypt_user_data(
       user_id: Uuid,
       old_dek: &SecretBox<Vec<u8>>,
       new_dek: &SecretBox<Vec<u8>>,
   ) -> Result<(), AppError> {
       // Re-encrypt chat messages
       let messages = sqlx::query!(
           "SELECT id, content, content_nonce FROM chat_messages WHERE user_id = $1",
           user_id
       ).fetch_all(&pool).await?;

       for msg in messages {
           let plaintext = decrypt(&msg.content, &msg.content_nonce, old_dek)?;
           let (new_ciphertext, new_nonce) = encrypt(&plaintext, new_dek)?;

           sqlx::query!(
               "UPDATE chat_messages SET content = $1, content_nonce = $2 WHERE id = $3",
               new_ciphertext, new_nonce, msg.id
           ).execute(&pool).await?;
       }

       // Re-encrypt characters, personas, etc.
       // ...

       Ok(())
   }
   ```

3. **Implement Row-Level Security (RLS)**
   ```sql
   -- PostgreSQL: Enable RLS to enforce user isolation
   ALTER TABLE chat_messages ENABLE ROW LEVEL SECURITY;

   CREATE POLICY chat_messages_isolation ON chat_messages
   FOR ALL
   USING (user_id = current_setting('app.current_user_id')::uuid);

   -- Application must set current_user_id on each connection
   SET app.current_user_id = '<user_uuid>';
   ```

4. **Implement ML-Based Anomaly Detection**
   ```rust
   // backend/src/services/ml_anomaly_detector.rs

   pub struct AnomalyScore {
       pub is_anomalous: bool,
       pub confidence: f32,
       pub anomaly_type: String,
   }

   pub async fn detect_data_access_anomaly(
       &self,
       hashed_user_id: &str,
   ) -> Result<AnomalyScore, AppError> {
       // Features for ML model
       let features = DataAccessFeatures {
           requests_per_minute: self.get_request_rate(hashed_user_id).await?,
           avg_response_size: self.get_avg_response_size(hashed_user_id).await?,
           time_of_day: chrono::Utc::now().hour(),
           day_of_week: chrono::Utc::now().weekday().num_days_from_monday(),
           endpoint_diversity: self.get_endpoint_diversity(hashed_user_id).await?,
           geographic_consistency: self.check_geo_consistency(hashed_user_id).await?,
       };

       // Compare against user's 90-day baseline
       let baseline = self.get_user_baseline(hashed_user_id).await?;
       let z_score = calculate_z_score(&features, &baseline);

       Ok(AnomalyScore {
           is_anomalous: z_score > 3.0,  // >3 std deviations
           confidence: z_score / 5.0,     // Normalized confidence
           anomaly_type: identify_anomaly_type(&features, &baseline),
       })
   }
   ```

## Recovery Procedures

### Data Breach Assessment

1. **Determine Data Exposure Scope**
   ```sql
   -- Audit exactly what data was accessed
   WITH accessed_data AS (
     SELECT
       'chat_messages' as data_type,
       COUNT(DISTINCT id) as record_count,
       SUM(LENGTH(content)) as total_bytes
     FROM chat_messages
     WHERE id IN (
       SELECT message_id FROM chat_message_access_log
       WHERE accessed_at > '<exfiltration_start>'
       AND hashed_user_id IN ('<attacker_hashes>')
     )
     UNION ALL
     SELECT
       'characters',
       COUNT(DISTINCT id),
       SUM(LENGTH(definition))
     FROM characters
     WHERE id IN (
       SELECT character_id FROM character_access_log
       WHERE accessed_at > '<exfiltration_start>'
       AND hashed_user_id IN ('<attacker_hashes>')
     )
   )
   SELECT
     data_type,
     record_count,
     total_bytes,
     total_bytes / 1024 / 1024 as total_mb
   FROM accessed_data;
   ```

2. **Assess Encryption Protection**
   ```bash
   # Verify attacker only got encrypted data (ciphertext)
   # IF attacker had DEK in session → plaintext exposed
   # IF attacker only got database dump → ciphertext only (safe)

   # Check if DEK was in cache during exfiltration
   fields @timestamp, event, hashed_user_id, dek_status
   | filter hashed_user_id in ["<attacker_hashes>"]
   | filter event = "dek_cache_hit"
   | filter @timestamp > <exfiltration_start>
   # If results found → plaintext likely exposed
   ```

3. **Calculate Breach Severity**
   - **Low:** Encrypted data only, no DEK compromise
   - **Medium:** Limited plaintext exposure (<100 records)
   - **High:** Significant plaintext exposure (100-10k records)
   - **Critical:** Mass plaintext exposure (>10k records) or PII leaked

### User Notification (GDPR Compliance)

**If plaintext data was exfiltrated:**

```sql
-- Identify affected users (victims, not attacker)
SELECT DISTINCT u.hashed_user_id
FROM users u
JOIN chat_messages cm ON cm.user_id = u.id
WHERE cm.id IN (
  SELECT message_id FROM chat_message_access_log
  WHERE hashed_user_id IN ('<attacker_hashes>')
  AND accessed_at > '<exfiltration_start>'
);
```

**GDPR Article 34 Notification Template:**
```
Subject: Security Incident Notification

We are writing to inform you of a security incident that may have affected your
Sanguine Scribe account data.

What Happened:
On [DATE], we detected unauthorized access to user conversation data.

What Data Was Affected:
- Chat messages: [COUNT] conversations
- Characters: [COUNT] character definitions
- NO payment information or passwords were exposed

What We're Doing:
- Terminated attacker access immediately
- Enhanced security monitoring
- Forced password reset for your account
- Implemented additional access controls

What You Should Do:
- Reset your password using the link below: [LINK]
- Review your recent account activity
- Enable 2FA when available (coming soon)

For Questions:
Contact our Data Protection Officer at dpo@sanguinescribe.com

We sincerely apologize for this incident.
```

### Regulatory Reporting

**GDPR (EU):** Report to supervisory authority within 72 hours if high risk

**CCPA (California):** Notify affected users within reasonable time

**Breach Notification Laws:** Varies by jurisdiction, consult legal team

### Service Restoration

1. **Unfreeze Legitimate Accounts**
   ```sql
   UPDATE users
   SET account_frozen = false, frozen_reason = NULL
   WHERE hashed_user_id IN ('<legitimate_user_hashes>');
   ```

2. **Restore Normal Rate Limits**
   - Return API limits to normal (10 req/sec)
   - Remove response size restrictions (or set reasonable limits)
   - Re-enable query optimizations

3. **Disable Emergency Logging**
   ```sql
   -- PostgreSQL: Reduce log verbosity
   ALTER SYSTEM SET log_statement = 'ddl';  -- Only log schema changes
   ALTER SYSTEM SET log_min_duration_statement = 1000;  -- Only log slow queries
   SELECT pg_reload_conf();
   ```

## Post-Incident Review

### Evidence Collection

1. **Archive Access Logs**
   ```bash
   # Export all access logs for exfiltration window
   aws logs create-export-task \
     --log-group-name /aws/scribe/application \
     --from <exfiltration_start_epoch> \
     --to <exfiltration_end_epoch> \
     --destination scribe-security-incident-logs \
     --destination-prefix data-exfiltration-$(date +%Y%m%d)
   ```

2. **Database Forensics**
   ```sql
   -- Export PostgreSQL query logs
   COPY (
     SELECT * FROM pg_stat_statements
     WHERE query_start > '<exfiltration_start>'
   ) TO '/tmp/pg_query_log.csv' CSV HEADER;
   ```

3. **Network Traffic Analysis** (if available)
   - VPC Flow Logs for data egress
   - CloudFront access logs
   - Load balancer logs

### Root Cause Analysis

**Questions to Answer:**
1. How did attacker gain access? (Stolen credentials, session hijacking, SQL injection)
2. Why didn't rate limits prevent bulk access?
3. Was data encrypted during exfiltration? (DEK in session cache?)
4. Could pagination limits have prevented this?
5. Did monitoring detect anomaly quickly enough? (MTTD analysis)

### Preventive Measures

1. **Code-Level Improvements**
   - Implement pagination hard limits (max 100 records per request)
   - Add response size limits (max 10MB per response)
   - Implement data access auditing middleware
   - Add ML-based anomaly detection for data access patterns

2. **Infrastructure Hardening**
   - Enable PostgreSQL row-level security (RLS)
   - Implement query result size limits
   - Add database connection pooling restrictions
   - Enable AWS GuardDuty for threat detection

3. **Monitoring Enhancements**
   - Create data access heatmaps (identify unusual patterns)
   - Implement real-time anomaly detection
   - Add baseline behavioral analysis per user
   - Enable CloudWatch anomaly detection

4. **Process Improvements**
   - Regular security audits of data access patterns
   - Quarterly penetration testing (data exfiltration scenarios)
   - User education on password security
   - Implement principle of least privilege (POLP) for database roles

### Compliance Reporting

**Incident Report Template:**
```markdown
## Data Exfiltration Incident Report

**Incident ID:** INC-EXFIL-<YYYYMMDD>-<seq>
**Date/Time:** <UTC timestamp>
**Severity:** P0
**MTTD:** <actual minutes>
**MTTR:** <actual minutes>
**Data Breach:** YES/NO

### Summary
[Brief description of exfiltration method and scope]

### Timeline
- [HH:MM] Exfiltration detected via CloudWatch alarm
- [HH:MM] Sessions revoked, accounts frozen
- [HH:MM] Data exposure scope assessed
- [HH:MM] Encryption protection verified
- [HH:MM] Affected users identified
- [HH:MM] Breach notification initiated (if required)
- [HH:MM] Service restored

### Impact
- Total records accessed: <count>
- Data types: chat_messages, characters, personas
- Encrypted data only: YES/NO
- Affected users: <count>
- Regulatory notification required: YES/NO

### Root Cause
[Analysis from RCA section]

### Preventive Actions
[List of security enhancements]

### Compliance Notes
- GDPR Article 33/34: Breach reported to DPO within 72 hours
- Affected users notified within 72 hours
- Encryption protected data: [YES/NO - explain]
```

## Escalation Matrix

| Condition | Escalate To | Timeline |
|-----------|-------------|----------|
| Data exfiltration detected (any amount) | CISO, DPO, Security Ops Manager | Immediate |
| Plaintext data exposed (>100 records) | CEO, Legal, PR team | Within 15min |
| Plaintext data exposed (>10k records) | Board, Regulatory authorities | Within 30min |
| PII/sensitive data exposed | Legal, External counsel, Regulators | Within 1hr |
| Ongoing exfiltration (>1 hour) | Law Enforcement, AWS Support | Within 1hr |

## Checklist

- [ ] Alert received and acknowledged
- [ ] Exfiltration pattern identified
- [ ] Data exposure scope assessed
- [ ] Sessions revoked, DEK cache cleared
- [ ] Accounts frozen, API access blocked
- [ ] Encryption protection verified
- [ ] Affected users identified
- [ ] Regulatory notification determination made
- [ ] Breach notification sent (if required)
- [ ] Evidence archived
- [ ] Post-incident review scheduled
- [ ] Preventive measures implemented
- [ ] Compliance reporting completed
- [ ] DPO notified and engaged

## References

- [SECURITY_MONITORING.md](../SECURITY_MONITORING.md) - Full architecture
- [ENCRYPTION_ARCHITECTURE.md](../ENCRYPTION_ARCHITECTURE.md) - DEK/KEK system
- [PRIVACY_SAFE_LOGGING.md](../PRIVACY_SAFE_LOGGING.md) - Logging best practices
- [GDPR Article 33/34](https://gdpr-info.eu/) - Breach notification requirements
- [OWASP Top 10 A01](https://owasp.org/www-project-top-ten/) - Broken Access Control
