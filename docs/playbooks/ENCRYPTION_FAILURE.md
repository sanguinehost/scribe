# Incident Response Playbook: Encryption Failure

**Incident Type:** DEK/KEK Decryption Errors / Nonce Reuse / Cryptographic Integrity Failure
**Severity:** P0 (Critical) - Data loss risk
**MTTD Target:** <5 minutes
**MTTR Target:** <30 minutes
**Owner:** Security Operations Team + Infrastructure Team

## Overview

This playbook addresses failures in the per-user encryption system, including:
- DEK decryption failures (wrong password, corrupted DEK, missing KEK salt)
- Nonce reuse detection (catastrophic AES-GCM failure)
- Data decryption errors (corrupted ciphertext, missing nonces)
- DEK cache corruption
- Encryption key rotation failures
- Password/recovery phrase compromise leading to key recovery issues

**Critical Context:** The entire Scribe data encryption system relies on:
- **DEK (Data Encryption Key):** Unique per user, encrypts all user data
- **KEK (Key Encryption Key):** Derived from user password, encrypts DEK
- **RKEK (Recovery KEK):** Derived from recovery phrase, encrypts DEK (backup)
- **Nonces:** Unique per encryption operation, MUST NEVER be reused

Encryption failures can lead to permanent data loss if not handled correctly.

## Detection Criteria

### Primary Indicators

**CloudWatch Metric Filter:**
```json
{ $.event = "encryption_error" }
```

**Alert Thresholds:**
- **P0 Alert:** >10 decryption failures for single user within 5 minutes (data corruption)
- **P0 Alert:** Nonce reuse detected (ANY occurrence - critical vulnerability)
- **P0 Alert:** DEK cache corruption detected
- **P1 Alert:** >5 decryption failures for single user within 15 minutes
- **P2 Alert:** Single decryption failure spike across multiple users (system-wide issue)

**Prometheus Metrics:**
- `dek_decryption_failures_total` > 10 per 5-minute window (per user)
- `nonce_reuse_detected` > 0 (ANY reuse is critical)
- `aes_gcm_authentication_failures` > 5 per minute
- `dek_cache_eviction_errors` > 0

### Secondary Indicators (Correlation)

- Sudden spike in 500 errors on data access endpoints
- User reports of "corrupted data" or "cannot decrypt messages"
- Database migration failures (nonce column missing)
- Password change failures (KEK derivation error)
- Recovery phrase validation failures

### Composite Alarm

```hcl
aws_cloudwatch_composite_alarm "encryption_system_failure" {
  alarm_rule = "ALARM(decryption_error_threshold) OR
                ALARM(nonce_reuse_detected) OR
                ALARM(dek_cache_corruption)"
  alarm_actions = [
    aws_sns_topic.security_alerts_p0.arn,
    aws_sns_topic.infrastructure_alerts_p0.arn
  ]
}
```

## Investigation Steps

### Phase 1: Initial Triage (0-5 minutes)

1. **Check Alert Context**
   ```bash
   # CloudWatch Logs Insights query
   fields @timestamp, event, hashed_user_id, error_type, error_detail
   | filter event = "encryption_error"
   | stats count() as error_count by error_type, hashed_user_id
   | sort error_count desc
   | limit 50
   ```

2. **Identify Failure Type**
   - **DEK Decryption Failure:** Wrong password, corrupted encrypted_dek, missing kek_salt
   - **Data Decryption Failure:** Corrupted ciphertext, missing nonce, wrong DEK
   - **Nonce Reuse:** Same nonce used for multiple encryptions (CRITICAL)
   - **Cache Corruption:** DEK cache returning invalid keys
   - **KEK Derivation Failure:** Argon2 error, salt issues

3. **Assess Impact Scope**
   ```bash
   # Count affected users
   fields hashed_user_id
   | filter event = "encryption_error"
   | stats dc(hashed_user_id) as affected_users
   ```

   ```sql
   -- PostgreSQL: Check for system-wide vs. user-specific issue
   SELECT
     COUNT(DISTINCT hashed_user_id) as affected_users,
     COUNT(*) as total_failures
   FROM encryption_error_log
   WHERE created_at > NOW() - INTERVAL '15 minutes';
   -- If affected_users = 1 → user-specific (password/DEK issue)
   -- If affected_users > 100 → system-wide (code bug, deployment issue)
   ```

4. **Check for Data Loss Risk**
   ```sql
   -- Verify DEK still exists and is recoverable
   SELECT
     hashed_user_id,
     encrypted_dek IS NOT NULL as has_encrypted_dek,
     dek_nonce IS NOT NULL as has_dek_nonce,
     kek_salt IS NOT NULL as has_kek_salt,
     encrypted_dek_by_recovery IS NOT NULL as has_recovery_dek,
     recovery_kek_salt IS NOT NULL as has_recovery_salt
   FROM users
   WHERE hashed_user_id IN ('<affected_user_hashes>')
   LIMIT 100;
   -- If any NULL values → CRITICAL: key material missing, data loss imminent
   ```

### Phase 2: Deep Investigation (5-15 minutes)

1. **Analyze Decryption Error Patterns**
   ```bash
   # CloudWatch error detail analysis
   fields @timestamp, error_type, error_detail, stack_trace
   | filter event = "encryption_error"
   | filter hashed_user_id in ["<affected_user_hashes>"]
   | sort @timestamp desc
   ```

   **Common Error Patterns:**
   - `AES-GCM authentication failed` → Ciphertext tampered or wrong key
   - `Nonce length invalid` → Database schema issue, missing nonce column
   - `Argon2 derivation failed` → KEK_salt corruption, memory issue
   - `DEK cache miss` → Session expired, cache eviction bug

2. **Check Database Integrity**
   ```sql
   -- Verify encryption metadata completeness
   SELECT
     'chat_messages' as table_name,
     COUNT(*) as total_records,
     COUNT(content) as encrypted_records,
     COUNT(content_nonce) as records_with_nonce,
     COUNT(*) - COUNT(content_nonce) as missing_nonces
   FROM chat_messages
   WHERE user_id IN (
     SELECT id FROM users WHERE hashed_user_id IN ('<affected_user_hashes>')
   )
   UNION ALL
   SELECT
     'characters',
     COUNT(*),
     COUNT(definition),
     COUNT(definition_nonce),
     COUNT(*) - COUNT(definition_nonce)
   FROM characters
   WHERE user_id IN (
     SELECT id FROM users WHERE hashed_user_id IN ('<affected_user_hashes>')
   );
   -- If missing_nonces > 0 → CRITICAL: data cannot be decrypted
   ```

3. **Check for Nonce Reuse** (CRITICAL)
   ```sql
   -- Detect duplicate nonces (catastrophic for AES-GCM)
   SELECT
     content_nonce,
     COUNT(*) as reuse_count,
     ARRAY_AGG(id) as affected_message_ids
   FROM chat_messages
   WHERE user_id IN (
     SELECT id FROM users WHERE hashed_user_id IN ('<affected_user_hashes>')
   )
   GROUP BY content_nonce
   HAVING COUNT(*) > 1;
   -- If ANY results → CRITICAL: nonce reuse detected, re-encryption required
   ```

4. **Review Recent Code Deployments**
   ```bash
   # Check recent deployments for encryption-related changes
   git log --since="24 hours ago" --grep="encrypt\|decrypt\|DEK\|KEK\|nonce" --oneline

   # Check deployment logs
   aws ecs describe-task-definition --task-definition scribe-backend:latest \
     | jq '.taskDefinition.containerDefinitions[0].environment'
   # Verify COOKIE_SIGNING_KEY, PAYMENT_DATA_ENCRYPTION_KEY, PRIVACY_HASH_SALT unchanged
   ```

### Phase 3: Threat Validation (15-30 minutes)

1. **Verify No External Attack**
   ```bash
   # Check for password brute-force attempts
   fields @timestamp, event, hashed_user_id, attempt_count
   | filter event = "authentication_failure"
   | filter hashed_user_id in ["<affected_user_hashes>"]
   | stats sum(attempt_count) as total_failures by hashed_user_id
   # If >20 failures → possible brute-force causing password invalidation
   ```

2. **Check for Database Corruption**
   ```sql
   -- PostgreSQL: Run data integrity checks
   SELECT pg_catalog.pg_check_db_integrity();

   -- Check for table corruption
   SELECT * FROM pg_catalog.pg_check_table('users');
   SELECT * FROM pg_catalog.pg_check_table('chat_messages');

   -- Verify foreign key constraints
   SELECT conname, conrelid::regclass, confrelid::regclass
   FROM pg_constraint
   WHERE contype = 'f'
   AND (conrelid::regclass::text LIKE '%users%'
        OR conrelid::regclass::text LIKE '%chat_messages%');
   ```

3. **Test Encryption System with Known-Good Data**
   ```rust
   // backend/tests/encryption_system_tests.rs

   #[tokio::test]
   async fn test_encryption_decryption_roundtrip() {
       let dek = generate_dek().unwrap();
       let plaintext = b"Test message for encryption validation";

       // Encrypt
       let (ciphertext, nonce) = encrypt(plaintext, &dek).unwrap();

       // Decrypt
       let decrypted = decrypt(&ciphertext, &nonce, &dek).unwrap();

       assert_eq!(plaintext, decrypted.as_slice());
   }

   // Run test in production environment to verify crypto library
   RUN_INTEGRATION_TESTS=true cargo test --test encryption_system_tests \
     --features payment -- --nocapture
   ```

4. **Check DEK Cache Health**
   ```rust
   // backend/src/auth/mod.rs

   pub async fn audit_dek_cache_integrity(
       auth_backend: &AuthBackend,
   ) -> Result<CacheHealthReport, AppError> {
       let cache = auth_backend.dek_cache.read().await;

       let report = CacheHealthReport {
           total_cached_deks: cache.len(),
           corrupted_entries: 0,
           successful_test_decryptions: 0,
       };

       for (user_id, dek) in cache.iter() {
           // Test DEK validity
           let test_plaintext = b"cache integrity test";
           match encrypt(test_plaintext, dek) {
               Ok((ciphertext, nonce)) => {
                   match decrypt(&ciphertext, &nonce, dek) {
                       Ok(decrypted) if decrypted == test_plaintext => {
                           report.successful_test_decryptions += 1;
                       }
                       _ => {
                           report.corrupted_entries += 1;
                           tracing::error!(
                               user_id = %user_id,
                               "DEK cache entry failed integrity test"
                           );
                       }
                   }
               }
               Err(_) => report.corrupted_entries += 1,
           }
       }

       Ok(report)
   }
   ```

## Containment Actions

### Immediate (0-5 minutes)

1. **Prevent Data Loss - Stop Write Operations** (if nonce reuse detected)
   ```rust
   // Emergency: Disable data writes to prevent nonce reuse
   // backend/src/middleware/emergency_mode.rs

   pub async fn check_emergency_mode(
       req: Request<Body>,
       next: Next,
   ) -> Result<Response, AppError> {
       let emergency_mode = std::env::var("EMERGENCY_READONLY_MODE")
           .unwrap_or_default() == "true";

       if emergency_mode && (req.method() == Method::POST
                             || req.method() == Method::PUT
                             || req.method() == Method::DELETE) {
           return Err(AppError::ServiceUnavailable(
               "System in emergency read-only mode. Please try again later.".into()
           ));
       }

       Ok(next.run(req).await)
   }
   ```

   ```bash
   # Set emergency mode environment variable
   aws ecs update-service \
     --cluster scribe-staging \
     --service scribe-backend \
     --force-new-deployment \
     --task-definition scribe-backend:latest \
     --overrides '{
       "containerOverrides": [{
         "name": "scribe-backend",
         "environment": [
           {"name": "EMERGENCY_READONLY_MODE", "value": "true"}
         ]
       }]
     }'
   ```

2. **Clear Corrupted DEK Cache**
   ```rust
   // backend/src/auth/mod.rs

   pub async fn emergency_dek_cache_clear(
       auth_backend: &AuthBackend,
   ) -> Result<(), AppError> {
       let mut cache = auth_backend.dek_cache.write().await;
       let cleared_count = cache.len();
       cache.clear();

       tracing::warn!(
           cleared_dek_count = cleared_count,
           "Emergency DEK cache clear - all users must re-authenticate"
       );

       Ok(())
   }
   ```

3. **Revoke All Sessions** (force re-authentication)
   ```sql
   -- Force all users to log in again (re-derive KEK, decrypt DEK)
   TRUNCATE TABLE sessions;

   -- Log mass session revocation
   INSERT INTO security_audit_log (event_type, reason, created_at)
   VALUES ('mass_session_revocation', 'Encryption system integrity incident', NOW());
   ```

### Short-Term (5-30 minutes)

1. **Fix Nonce Generation** (if reuse detected)
   ```rust
   // backend/src/crypto/mod.rs

   use rand::RngCore;

   pub fn generate_nonce() -> Result<Vec<u8>, AppError> {
       // AES-GCM standard nonce size: 12 bytes (96 bits)
       let mut nonce = vec![0u8; 12];

       // CRITICAL: Use cryptographically secure RNG
       let mut rng = rand::rngs::OsRng;
       rng.try_fill_bytes(&mut nonce)
           .map_err(|e| AppError::InternalServerError(
               format!("Failed to generate nonce: {}", e)
           ))?;

       // Verify nonce uniqueness (check against recent nonces in Redis)
       if is_nonce_recently_used(&nonce).await? {
           // Extremely rare, but regenerate to be safe
           return generate_nonce();  // Retry recursively
       }

       Ok(nonce)
   }

   // Add nonce tracking to prevent reuse
   pub async fn is_nonce_recently_used(nonce: &[u8]) -> Result<bool, AppError> {
       // Check Redis cache of recently used nonces (last 1 hour)
       let nonce_key = format!("nonce:{}", hex::encode(nonce));
       let exists = redis_client.exists(&nonce_key).await?;

       if !exists {
           // Store nonce with 1-hour TTL
           redis_client.setex(&nonce_key, 3600, "1").await?;
       }

       Ok(exists)
   }
   ```

2. **Repair Missing Nonces** (if database integrity issue)
   ```sql
   -- Identify records with missing nonces
   SELECT id, user_id
   FROM chat_messages
   WHERE content IS NOT NULL  -- Encrypted
   AND content_nonce IS NULL  -- But no nonce!
   LIMIT 1000;

   -- CRITICAL: Cannot decrypt without nonce - data is LOST
   -- Best option: Mark as corrupted, notify user

   UPDATE chat_messages
   SET metadata = jsonb_set(
     COALESCE(metadata, '{}'::jsonb),
     '{corrupted}',
     'true'::jsonb
   )
   WHERE content IS NOT NULL
   AND content_nonce IS NULL;
   ```

3. **Re-encrypt Data with Reused Nonces** (CRITICAL)
   ```rust
   // backend/src/crypto/re_encryption.rs

   pub async fn re_encrypt_with_new_nonces(
       user_id: Uuid,
       affected_message_ids: &[Uuid],
   ) -> Result<(), AppError> {
       // 1. Fetch user's DEK (must be in cache or re-derive from password)
       let dek = get_user_dek(user_id).await?;

       for message_id in affected_message_ids {
           // 2. Fetch encrypted message
           let message = sqlx::query!(
               "SELECT content, content_nonce FROM chat_messages WHERE id = $1",
               message_id
           ).fetch_one(&pool).await?;

           // 3. Decrypt with old nonce
           let plaintext = decrypt(&message.content, &message.content_nonce, &dek)?;

           // 4. Re-encrypt with NEW nonce
           let new_nonce = generate_nonce()?;
           let new_ciphertext = encrypt_with_nonce(&plaintext, &dek, &new_nonce)?;

           // 5. Update database
           sqlx::query!(
               "UPDATE chat_messages
                SET content = $1, content_nonce = $2, updated_at = NOW()
                WHERE id = $3",
               new_ciphertext, new_nonce, message_id
           ).execute(&pool).await?;

           tracing::info!(
               message_id = %message_id,
               "Re-encrypted message with new nonce"
           );
       }

       Ok(())
   }
   ```

4. **Enable Enhanced Encryption Monitoring**
   ```rust
   // backend/src/middleware/encryption_monitoring.rs

   pub async fn monitor_encryption_operations(
       req: Request<Body>,
       next: Next,
   ) -> Result<Response, AppError> {
       let start = Instant::now();
       let response = next.run(req).await;
       let duration = start.elapsed();

       // Track encryption performance metrics
       metrics::histogram!("encryption_operation_duration_ms", duration.as_millis() as f64);

       // Alert on slow encryption (possible performance issue)
       if duration > Duration::from_secs(1) {
           tracing::warn!(
               duration_ms = duration.as_millis(),
               "Slow encryption operation detected"
           );
       }

       Ok(response)
   }
   ```

### Long-Term (30min - 7 days)

1. **Implement Nonce Deduplication**
   ```rust
   // backend/src/crypto/nonce_tracker.rs

   use redis::AsyncCommands;

   pub struct NonceTracker {
       redis_client: redis::Client,
   }

   impl NonceTracker {
       pub async fn ensure_nonce_unique(&self, nonce: &[u8]) -> Result<(), AppError> {
           let nonce_hex = hex::encode(nonce);
           let key = format!("nonce:{}", nonce_hex);

           // Atomically check-and-set
           let was_set: bool = self.redis_client
               .set_nx(&key, "1")
               .await
               .map_err(|e| AppError::InternalServerError(format!("Redis error: {}", e)))?;

           if !was_set {
               return Err(AppError::InternalServerError(
                   "CRITICAL: Nonce reuse detected - regenerating".into()
               ));
           }

           // Set 24-hour expiry (reasonable safety window)
           self.redis_client.expire(&key, 86400).await?;

           Ok(())
       }
   }
   ```

2. **Implement Automated Encryption Health Checks**
   ```rust
   // backend/src/services/encryption_health.rs

   pub async fn run_encryption_health_check() -> Result<HealthReport, AppError> {
       let report = HealthReport::default();

       // Test 1: Verify KEK derivation
       let test_password = "test_password_for_health_check";
       let test_salt = generate_salt()?;
       match derive_kek(test_password, &test_salt) {
           Ok(_) => report.kek_derivation_healthy = true,
           Err(e) => {
               report.kek_derivation_healthy = false;
               report.errors.push(format!("KEK derivation failed: {}", e));
           }
       }

       // Test 2: Verify DEK generation
       match generate_dek() {
           Ok(_) => report.dek_generation_healthy = true,
           Err(e) => {
               report.dek_generation_healthy = false;
               report.errors.push(format!("DEK generation failed: {}", e));
           }
       }

       // Test 3: Verify encryption/decryption roundtrip
       let test_data = b"health check test";
       match encrypt_decrypt_roundtrip(test_data) {
           Ok(true) => report.roundtrip_healthy = true,
           _ => {
               report.roundtrip_healthy = false;
               report.errors.push("Encryption roundtrip failed".into());
           }
       }

       // Test 4: Check for nonce reuse in database
       report.nonce_reuse_count = check_nonce_reuse_db().await?;

       Ok(report)
   }

   // Run health check every 5 minutes
   #[tokio::main]
   async fn main() {
       let mut interval = tokio::time::interval(Duration::from_secs(300));
       loop {
           interval.tick().await;
           match run_encryption_health_check().await {
               Ok(report) if report.is_healthy() => {
                   tracing::info!("Encryption health check: PASS");
               }
               Ok(report) => {
                   tracing::error!(
                       errors = ?report.errors,
                       "Encryption health check: FAIL"
                   );
                   // Trigger P0 alert
               }
               Err(e) => {
                   tracing::error!(error = %e, "Encryption health check error");
               }
           }
       }
   }
   ```

3. **Implement Database-Level Nonce Uniqueness Constraint**
   ```sql
   -- PostgreSQL: Add unique constraint on (user_id, nonce) pairs
   -- Note: This prevents nonce reuse at database level

   CREATE UNIQUE INDEX CONCURRENTLY idx_chat_messages_user_nonce
   ON chat_messages (user_id, content_nonce)
   WHERE content_nonce IS NOT NULL;

   -- If this index creation fails, there are existing nonce collisions!
   ```

## Recovery Procedures

### Data Recovery (Encrypted Data with Missing Nonces)

**CRITICAL: Data encrypted without nonce cannot be decrypted - it is LOST.**

1. **Identify Irrecoverable Data**
   ```sql
   -- Find all records with missing nonces
   WITH irrecoverable_data AS (
     SELECT
       'chat_messages' as table_name,
       id,
       user_id,
       created_at
     FROM chat_messages
     WHERE content IS NOT NULL AND content_nonce IS NULL
     UNION ALL
     SELECT
       'characters',
       id,
       user_id,
       created_at
     FROM characters
     WHERE definition IS NOT NULL AND definition_nonce IS NULL
   )
   SELECT
     table_name,
       COUNT(*) as irrecoverable_records,
       MIN(created_at) as oldest_record,
       MAX(created_at) as newest_record
     FROM irrecoverable_data
     GROUP BY table_name;
   ```

2. **Notify Affected Users**
   ```sql
   -- Identify users with data loss
   SELECT DISTINCT u.hashed_user_id, COUNT(*) as lost_records
   FROM users u
   JOIN chat_messages cm ON cm.user_id = u.id
   WHERE cm.content IS NOT NULL
   AND cm.content_nonce IS NULL
   GROUP BY u.hashed_user_id;
   ```

   **User Notification Template:**
   ```
   Subject: Important: Data Recovery Notification

   We experienced a technical issue that may have affected some of your
   Sanguine Scribe data.

   What Happened:
   Due to an encryption system error, [COUNT] of your messages could not
   be recovered.

   What Data Was Affected:
   - Chat messages created between [DATE] and [DATE]
   - [Other data types if applicable]

   What We're Doing:
   - We have fixed the underlying issue
   - We have implemented additional safeguards
   - We are offering [COMPENSATION] as an apology

   We sincerely apologize for this incident. If you have questions,
   please contact support@sanguinescribe.com.
   ```

### DEK Recovery (User Lost Password)

**If user lost password AND recovery phrase:**

```rust
// backend/src/auth/dek_recovery.rs

pub async fn attempt_dek_recovery(
    user_id: Uuid,
    old_password_attempts: &[String],  // User tries to remember old passwords
) -> Result<RecoveryStatus, AppError> {
    let user = get_user_by_id(user_id).await?;

    // Try each password attempt
    for password_attempt in old_password_attempts {
        let kek = derive_kek(password_attempt, &user.kek_salt)?;

        match decrypt_dek(&user.encrypted_dek, &user.dek_nonce, &kek) {
            Ok(dek) => {
                // SUCCESS! User remembered correct password
                return Ok(RecoveryStatus::Success(dek));
            }
            Err(_) => continue,  // Try next password
        }
    }

    // If all attempts failed, check recovery phrase option
    if user.encrypted_dek_by_recovery.is_some() {
        return Ok(RecoveryStatus::RecoveryPhraseAvailable);
    }

    // No recovery options left - data is LOST
    Ok(RecoveryStatus::Irrecoverable)
}

pub enum RecoveryStatus {
    Success(SecretBox<Vec<u8>>),  // DEK recovered
    RecoveryPhraseAvailable,      // User can try recovery phrase
    Irrecoverable,                // Data is lost
}
```

## Post-Incident Review

### Evidence Collection

1. **Archive Encryption Error Logs**
   ```bash
   aws logs create-export-task \
     --log-group-name /aws/scribe/application \
     --from <incident_start_epoch> \
     --to <incident_end_epoch> \
     --destination scribe-security-incident-logs \
     --destination-prefix encryption-failure-$(date +%Y%m%d)
   ```

2. **Database Integrity Report**
   ```sql
   -- Generate comprehensive encryption metadata report
   SELECT
     'Users' as table_name,
     COUNT(*) as total_records,
     COUNT(encrypted_dek) as has_encrypted_dek,
     COUNT(kek_salt) as has_kek_salt,
     COUNT(encrypted_dek_by_recovery) as has_recovery_dek
   FROM users
   UNION ALL
   SELECT
     'ChatMessages',
     COUNT(*),
     COUNT(content),
     COUNT(content_nonce),
     NULL
   FROM chat_messages;
   ```

3. **Nonce Reuse Audit**
   ```sql
   -- Export all nonce collisions for analysis
   COPY (
     SELECT content_nonce, COUNT(*) as reuse_count
     FROM chat_messages
     WHERE content_nonce IS NOT NULL
     GROUP BY content_nonce
     HAVING COUNT(*) > 1
   ) TO '/tmp/nonce_collisions.csv' CSV HEADER;
   ```

### Root Cause Analysis

**Questions to Answer:**
1. What triggered the encryption failures? (Code bug, deployment, database migration)
2. Why did nonce reuse occur? (RNG failure, caching bug, race condition)
3. Could encryption health checks have prevented this?
4. Was there data loss? How much? Which users?
5. Did backup/recovery procedures work correctly?

### Preventive Measures

1. **Code-Level Improvements**
   - Implement nonce uniqueness checks (Redis-backed)
   - Add encryption operation monitoring middleware
   - Implement automated encryption health checks (every 5 min)
   - Add database constraints for nonce uniqueness

2. **Infrastructure Hardening**
   - Set up Redis cluster for nonce tracking (high availability)
   - Enable PostgreSQL checksums for data integrity
   - Implement automated database backups (hourly, 30-day retention)
   - Add encryption metadata validation on startup

3. **Monitoring Enhancements**
   - Real-time nonce reuse detection
   - DEK cache health monitoring
   - Encryption operation performance tracking
   - Database integrity alerts

4. **Testing Improvements**
   - Add chaos engineering tests (simulate nonce RNG failure)
   - Test DEK recovery procedures regularly
   - Validate encryption roundtrip in CI/CD
   - Implement automated encryption regression tests

### Compliance Reporting

**Incident Report Template:**
```markdown
## Encryption Failure Incident Report

**Incident ID:** INC-ENCRYPT-<YYYYMMDD>-<seq>
**Date/Time:** <UTC timestamp>
**Severity:** P0
**MTTD:** <actual minutes>
**MTTR:** <actual minutes>
**Data Loss:** YES/NO

### Summary
[Brief description of encryption failure type and scope]

### Timeline
- [HH:MM] Encryption errors detected
- [HH:MM] DEK cache cleared, sessions revoked
- [HH:MM] Nonce reuse identified/ruled out
- [HH:MM] Read-only mode enabled (if applicable)
- [HH:MM] Re-encryption completed
- [HH:MM] Service restored

### Impact
- Affected users: <count>
- Decryption failures: <count>
- Nonce reuse incidents: <count>
- Irrecoverable records: <count>
- Data loss: <YES/NO>

### Root Cause
[Analysis from RCA section]

### Preventive Actions
[List of encryption system improvements]
```

## Escalation Matrix

| Condition | Escalate To | Timeline |
|-----------|-------------|----------|
| Encryption errors detected | Security Ops, Infrastructure | Immediate |
| Nonce reuse detected | CISO, CTO, Security Ops | Immediate |
| Data loss confirmed (>100 records) | CEO, Legal, DPO | Within 15min |
| System-wide encryption failure | Incident Commander, All Hands | Within 5min |
| Irrecoverable data (>10k records) | Board, PR team, Regulators | Within 30min |

## Checklist

- [ ] Alert acknowledged
- [ ] Failure type identified
- [ ] Affected users counted
- [ ] Nonce reuse checked
- [ ] DEK cache cleared
- [ ] Sessions revoked
- [ ] Read-only mode enabled (if applicable)
- [ ] Data loss assessed
- [ ] Re-encryption completed (if nonce reuse)
- [ ] Missing nonces identified
- [ ] Affected users notified
- [ ] Service restored
- [ ] Evidence archived
- [ ] Encryption health checks implemented
- [ ] Preventive measures deployed
- [ ] Compliance reporting completed

## References

- [ENCRYPTION_ARCHITECTURE.md](../ENCRYPTION_ARCHITECTURE.md) - DEK/KEK system
- [SECURITY_MONITORING.md](../SECURITY_MONITORING.md) - Full monitoring architecture
- [AES-GCM Nonce Reuse](https://csrc.nist.gov/publications/detail/sp/800-38d/final) - NIST SP 800-38D
- [Cryptographic Best Practices](https://owasp.org/www-project-top-ten/) - OWASP Cryptographic Failures
