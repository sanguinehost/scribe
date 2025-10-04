# Incident Response Playbook: Payment Fraud

**Incident Type:** Anomalous Credit Operations / Subscription Fraud / Card Testing
**Severity:** P0 (Critical) if active fraud, P1 (High) if suspected anomaly
**MTTD Target:** <5 minutes (P0), <15 minutes (P1)
**MTTR Target:** <30 minutes (P0), <1 hour (P1)
**Owner:** Security Operations Team + Finance Team

## Overview

This playbook addresses fraudulent payment activities including:
- Unauthorized credit allocations (webhook bypass, admin compromise)
- Subscription fraud (trial abuse, stolen cards)
- Card testing attacks (validating stolen card numbers)
- Refund/chargeback fraud
- Credit balance manipulation

## Detection Criteria

### Primary Indicators

**CloudWatch Metric Filter:**
```json
{ $.event = "payment_anomaly_detected" }
```

**Alert Thresholds:**
- **P0 Alert:** Single user >100 credit operations within 5 minutes
- **P0 Alert:** Credit balance change >1M tokens within 1 hour (per user)
- **P1 Alert:** Single user >50 credit operations within 15 minutes
- **P1 Alert:** >10 subscription creations from same payment method within 1 hour
- **P2 Alert:** Geographic impossibility (US transaction, then India transaction <1hr)

**Prometheus Metrics:**
- `credit_operations_rate_per_user` > 100 per 5-minute window
- `credit_balance_change_velocity` > 1M tokens per hour
- `subscription_creation_rate` > 10 per hour (same payment method)
- `payment_reversals_count` > 5 per day (chargeback fraud indicator)

### Secondary Indicators (Correlation)

- Multiple failed payment attempts before success (card testing)
- Subscription created immediately after credit exhaustion (trial abuse)
- Credit consumption rate change >500% from baseline
- Paddle webhook for subscription but no credit allocation (processing failure)
- Unusual payment method (anonymous prepaid cards, cryptocurrency)

### Composite Alarm

```hcl
aws_cloudwatch_composite_alarm "payment_fraud_detected" {
  alarm_rule = "ALARM(credit_operations_anomaly) OR
                (ALARM(subscription_creation_spike) AND ALARM(high_refund_rate))"
  alarm_actions = [aws_sns_topic.security_alerts_p0.arn, aws_sns_topic.finance_alerts.arn]
}
```

## Investigation Steps

### Phase 1: Initial Triage (0-5 minutes)

1. **Check Alert Context**
   ```bash
   # CloudWatch Logs Insights query
   fields @timestamp, event, hashed_user_id, pattern_type, severity, operation_count
   | filter event = "payment_anomaly_detected"
   | sort @timestamp desc
   | limit 50
   ```

2. **Identify Anomaly Pattern**
   - High-velocity operations? → Automated exploitation, API abuse
   - Large single transaction? → Admin account compromise
   - Multiple small transactions? → Card testing
   - Refund/chargeback spike? → Organized fraud ring

3. **Check Credit Balance Integrity**
   ```sql
   -- PostgreSQL query via jump host
   SELECT
     hashed_user_id,
     balance,
     last_updated_at,
     (SELECT SUM(amount) FROM payment_audit_logs
      WHERE payment_audit_logs.hashed_user_id = credit_balances.hashed_user_id) as audit_sum
   FROM credit_balances
   WHERE hashed_user_id IN ('<flagged_user_hashes>')
   AND balance != (SELECT COALESCE(SUM(amount), 0) FROM payment_audit_logs
                   WHERE payment_audit_logs.hashed_user_id = credit_balances.hashed_user_id);
   -- Returns rows where balance doesn't match audit log sum (integrity violation)
   ```

4. **Assess Financial Impact**
   ```sql
   -- Calculate monetary value of fraudulent credits
   SELECT
     hashed_user_id,
     SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END) as credits_added,
     SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END) as credits_consumed,
     SUM(amount) as net_balance_change
   FROM payment_audit_logs
   WHERE hashed_user_id IN ('<flagged_user_hashes>')
   AND created_at > '<anomaly_start_time>'
   GROUP BY hashed_user_id;

   -- Convert to dollars (example: 1000 tokens = $10)
   -- net_balance_change * 0.01 = estimated_dollar_impact
   ```

### Phase 2: Deep Investigation (5-15 minutes)

1. **Analyze Transaction Timeline**
   ```sql
   -- Detailed transaction history for anomalous user
   SELECT
     event_type,
     amount,
     external_reference_hash,
     reason,
     created_at
   FROM payment_audit_logs
   WHERE hashed_user_id = '<flagged_user_hash>'
   AND created_at > NOW() - INTERVAL '24 hours'
   ORDER BY created_at;
   ```

2. **Cross-Reference with Paddle**
   - Export Paddle transaction log for timeframe
   - Match external_reference_hash values
   - Identify credits without corresponding Paddle transaction (CRITICAL: fraud indicator)
   - Check for refund/chargeback status changes

3. **Check Subscription Validity**
   ```sql
   -- Verify subscription integrity
   SELECT
     sub.hashed_user_id,
     sub.paddle_subscription_id,
     sub.plan_type,
     sub.status,
     sub.created_at,
     sub.expires_at
   FROM subscriptions sub
   WHERE sub.hashed_user_id IN ('<flagged_user_hashes>')
   ORDER BY sub.created_at DESC;

   -- Check for trial abuse (multiple accounts, same payment method)
   SELECT
     paddle_customer_id,
     COUNT(DISTINCT hashed_user_id) as unique_users
   FROM subscriptions
   WHERE paddle_customer_id IS NOT NULL
   GROUP BY paddle_customer_id
   HAVING COUNT(DISTINCT hashed_user_id) > 1;
   ```

4. **Review API Access Patterns**
   ```bash
   # Check for API abuse (automated credit farming)
   fields @timestamp, hashed_user_id, endpoint, status_code
   | filter hashed_user_id in ["<flagged_user_hashes>"]
   | stats count() as request_count by endpoint, bin(1m)
   | filter request_count > 100
   ```

### Phase 3: Threat Validation (15-30 minutes)

1. **Verify Payment Method Legitimacy**
   - Cross-reference Paddle customer_id with multiple Scribe accounts (family sharing vs. fraud)
   - Check if payment method reported stolen (contact Paddle support)
   - Review chargeback/dispute history for payment method

2. **Check for Account Network**
   ```sql
   -- Detect fraud rings (shared payment methods, similar creation times)
   WITH payment_method_groups AS (
     SELECT
       paddle_customer_id,
       ARRAY_AGG(DISTINCT hashed_user_id) as user_group,
       MIN(created_at) as first_account,
       MAX(created_at) as last_account
     FROM subscriptions
     WHERE paddle_customer_id IS NOT NULL
     GROUP BY paddle_customer_id
     HAVING COUNT(DISTINCT hashed_user_id) > 2
   )
   SELECT *
   FROM payment_method_groups
   WHERE last_account - first_account < INTERVAL '7 days';
   ```

3. **Analyze Credit Consumption Patterns**
   ```sql
   -- Detect credit laundering (rapid add + consume)
   SELECT
     hashed_user_id,
     DATE_TRUNC('hour', created_at) as hour,
     SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END) as added,
     SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END) as consumed,
     COUNT(*) as operations
   FROM payment_audit_logs
   WHERE hashed_user_id IN ('<flagged_user_hashes>')
   AND created_at > NOW() - INTERVAL '48 hours'
   GROUP BY hashed_user_id, hour
   HAVING SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END) > 10000
   AND SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END) > 5000;
   ```

4. **Check for Data Exfiltration**
   - High credit consumption + unusual chat/character access patterns → Data harvesting
   - Rapid character creation + credit depletion → Training data collection

## Containment Actions

### Immediate (0-5 minutes)

1. **Freeze Suspicious Accounts**
   ```sql
   -- Set account freeze flag (prevent new operations)
   UPDATE users
   SET account_frozen = true,
       frozen_reason = 'Payment fraud investigation',
       frozen_at = NOW()
   WHERE hashed_user_id IN ('<flagged_user_hashes>');
   ```

   ```rust
   // backend/src/middleware/account_freeze_check.rs

   pub async fn check_account_freeze(
       session: Session,
       req: Request<Body>,
       next: Next,
   ) -> Result<Response, AppError> {
       let user_id = session.get_user_id()?;

       let user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id)
           .fetch_one(&state.pool)
           .await?;

       if user.account_frozen {
           return Err(AppError::Forbidden(format!(
               "Account temporarily frozen: {}. Contact support@sanguinescribe.com",
               user.frozen_reason.unwrap_or_default()
           )));
       }

       Ok(next.run(req).await)
   }
   ```

2. **Revoke Active Sessions**
   ```sql
   -- Invalidate all sessions for frozen accounts
   DELETE FROM sessions
   WHERE user_id IN (
     SELECT id FROM users WHERE hashed_user_id IN ('<flagged_user_hashes>')
   );
   ```

   ```rust
   // Clear DEK cache
   for hashed_id in flagged_user_hashes {
       if let Some(user_id) = resolve_hashed_to_uuid(hashed_id).await? {
           auth_backend.remove_dek_from_cache(user_id).await;
       }
   }
   ```

3. **Prevent New Credit Operations**
   ```rust
   // backend/src/services/payment/credit_service.rs

   pub async fn add_credits(
       &self,
       hashed_user_id: &str,
       amount: i64,
       reason: &str,
   ) -> Result<(), AppError> {
       // Check account freeze status before ANY credit operation
       let is_frozen = sqlx::query_scalar!(
           "SELECT account_frozen FROM users WHERE hashed_user_id = $1",
           hashed_user_id
       )
       .fetch_one(&self.pool)
       .await?;

       if is_frozen.unwrap_or(false) {
           return Err(AppError::Forbidden("Account frozen - credit operations prohibited".into()));
       }

       // ... proceed with credit addition
   }
   ```

### Short-Term (5-30 minutes)

1. **Audit All Recent Transactions**
   ```sql
   -- Generate comprehensive audit report
   SELECT
     pal.hashed_user_id,
     pal.event_type,
     pal.amount,
     pal.external_reference_hash,
     pal.reason,
     pal.created_at,
     cb.balance as current_balance,
     sub.paddle_subscription_id,
     sub.status as subscription_status
   FROM payment_audit_logs pal
   LEFT JOIN credit_balances cb ON pal.hashed_user_id = cb.hashed_user_id
   LEFT JOIN subscriptions sub ON pal.hashed_user_id = sub.hashed_user_id
   WHERE pal.created_at > '<investigation_start_time>'
   AND pal.hashed_user_id IN ('<flagged_user_hashes>')
   ORDER BY pal.created_at DESC;
   ```

2. **Contact Paddle Support**
   - Report suspected fraudulent transactions
   - Request payment method verification
   - Initiate dispute resolution for confirmed fraud
   - Request chargeback protection (if applicable)

3. **Implement Velocity Limits**
   ```rust
   // backend/src/services/payment/fraud_detection.rs

   pub async fn check_credit_operation_velocity(
       &self,
       hashed_user_id: &str,
   ) -> Result<(), AppError> {
       // Count operations in last 5 minutes
       let recent_ops = sqlx::query_scalar!(
           "SELECT COUNT(*) FROM payment_audit_logs
            WHERE hashed_user_id = $1
            AND created_at > NOW() - INTERVAL '5 minutes'",
           hashed_user_id
       )
       .fetch_one(&self.pool)
       .await?;

       if recent_ops > 50 {
           // Log security event
           tracing::error!(
               hashed_user_id = %loggable_user_id_from_hash(hashed_user_id),
               operation_count = recent_ops,
               "Credit operation velocity limit exceeded"
           );
           return Err(AppError::TooManyRequests(
               "Too many credit operations. Please try again later.".into()
           ));
       }

       Ok(())
   }
   ```

4. **Enable Enhanced Monitoring**
   ```hcl
   # Terraform: Lower alert thresholds for related accounts
   resource "aws_cloudwatch_metric_alarm" "credit_operations_strict" {
     alarm_name          = "P0-CreditOperationsStrictMode"
     comparison_operator = "GreaterThanThreshold"
     evaluation_periods  = "1"
     metric_name         = "CreditOperationsRate"
     namespace           = "Scribe/Payment"
     period              = "300"
     statistic           = "Sum"
     threshold           = "25"  # Reduced from 50

     dimensions = {
       UserId = "<flagged_user_hash>"
     }
   }
   ```

### Long-Term (30min - 7 days)

1. **Dispute Resolution with Paddle**
   - File formal dispute for fraudulent transactions
   - Provide evidence (audit logs, anomaly patterns)
   - Request refund reversal if payment method was stolen
   - Coordinate chargeback defense

2. **Credit Recovery** (if fraud confirmed)
   ```sql
   -- Claw back fraudulent credits (set balance to 0)
   BEGIN;

   -- Log recovery action
   INSERT INTO payment_audit_logs (
     hashed_user_id, event_type, amount, reason, created_at
   )
   SELECT
     hashed_user_id,
     'credit_recovery_fraud',
     -balance,
     'Fraudulent credit allocation - full recovery',
     NOW()
   FROM credit_balances
   WHERE hashed_user_id IN ('<confirmed_fraud_hashes>')
   AND balance > 0;

   -- Zero out balance
   UPDATE credit_balances
   SET balance = 0
   WHERE hashed_user_id IN ('<confirmed_fraud_hashes>');

   COMMIT;
   ```

3. **Account Termination** (confirmed fraud)
   ```sql
   -- Mark account for deletion (GDPR right to erasure)
   UPDATE users
   SET
     account_status = 'terminated',
     termination_reason = 'Payment fraud',
     terminated_at = NOW(),
     deletion_scheduled_at = NOW() + INTERVAL '30 days'
   WHERE hashed_user_id IN ('<confirmed_fraud_hashes>');

   -- Cancel active subscriptions
   UPDATE subscriptions
   SET
     status = 'cancelled',
     cancellation_reason = 'Payment fraud',
     cancelled_at = NOW()
   WHERE hashed_user_id IN ('<confirmed_fraud_hashes>')
   AND status = 'active';
   ```

4. **Refund Coordination**
   - Initiate refunds for legitimate users affected by fraud (if any)
   - Coordinate with finance team for accounting adjustments
   - Update revenue projections for fraudulent transaction reversals

## Recovery Procedures

### Financial Reconciliation

1. **Calculate Total Fraud Impact**
   ```sql
   -- Aggregate financial loss from fraud incident
   WITH fraud_summary AS (
     SELECT
       hashed_user_id,
       SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END) as fraudulent_credits,
       SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END) as consumed_credits,
       COUNT(*) as transaction_count
     FROM payment_audit_logs
     WHERE hashed_user_id IN ('<confirmed_fraud_hashes>')
     AND created_at BETWEEN '<fraud_start>' AND '<fraud_end>'
     GROUP BY hashed_user_id
   )
   SELECT
     SUM(fraudulent_credits) as total_fraudulent_credits,
     SUM(consumed_credits) as total_consumed_credits,
     SUM(fraudulent_credits) * 0.01 as estimated_loss_usd,  -- $0.01 per 1000 tokens
     SUM(transaction_count) as total_fraudulent_transactions
   FROM fraud_summary;
   ```

2. **Paddle Transaction Reconciliation**
   - Export Paddle transaction report for fraud timeframe
   - Match Scribe audit logs with Paddle transactions
   - Identify discrepancies (credits without Paddle transaction)
   - File dispute for any unauthorized Paddle transactions

3. **Update Financial Reports**
   - Adjust revenue recognition for reversed transactions
   - Document fraud losses for tax/insurance purposes
   - Update monthly recurring revenue (MRR) calculations
   - Notify stakeholders (CFO, board) if impact >$10k

### Service Restoration

1. **Unfreeze Legitimate Accounts** (false positives)
   ```sql
   -- Restore accounts after investigation clears them
   UPDATE users
   SET
     account_frozen = false,
     frozen_reason = NULL,
     frozen_at = NULL
   WHERE hashed_user_id IN ('<cleared_user_hashes>');
   ```

2. **Restore Velocity Limits** (after fraud subsides)
   - Return to normal credit operation limits (50/5min)
   - Remove enhanced monitoring for cleared accounts
   - Adjust baseline calculations to exclude fraud window

3. **User Communication** (if legitimate users impacted)
   **Email Template:**
   ```
   Subject: Account Freeze Resolved

   Thank you for your patience during our recent security review. Your account
   has been restored to full functionality.

   As a precaution, we recommend reviewing your recent transactions:
   [Link to Transaction History]

   If you notice any unauthorized activity, please contact us immediately at
   security@sanguinescribe.com.

   Thank you for your understanding.
   ```

## Post-Incident Review

### Evidence Collection

1. **Archive Fraud Logs**
   ```bash
   # Export payment audit logs to S3 (tamper-proof)
   aws logs create-export-task \
     --log-group-name /aws/scribe/payment \
     --from <fraud_start_epoch> \
     --to <fraud_end_epoch> \
     --destination scribe-security-incident-logs \
     --destination-prefix payment-fraud-$(date +%Y%m%d)
   ```

2. **Extract Fraud Indicators**
   ```bash
   # Document fraud patterns for ML training
   {
     "fraud_type": "high_velocity_credit_operations",
     "user_count": <count>,
     "total_fraudulent_credits": <amount>,
     "detection_time_minutes": <MTTD>,
     "containment_time_minutes": <MTTR>,
     "financial_impact_usd": <amount>,
     "paddle_transactions_disputed": <count>,
     "successful_recovery_percentage": <percentage>
   } > fraud_incident_$(date +%Y%m%d).json
   ```

3. **Paddle Evidence Package**
   - Scribe audit log excerpts (hashed user IDs)
   - CloudWatch alert screenshots
   - Transaction timeline visualization
   - Financial impact summary
   - Requested dispute resolution actions

### Root Cause Analysis

**Questions to Answer:**
1. How did fraudster obtain credits? (Webhook bypass, stolen card, trial abuse)
2. Why didn't velocity limits prevent fraud? (Threshold too high, bypass mechanism)
3. Was there a code vulnerability? (Race condition, validation bypass)
4. Could ML/anomaly detection have caught it earlier?
5. Did monitoring alerts fire correctly? (MTTD analysis)

### Preventive Measures

1. **Code-Level Improvements**
   ```rust
   // Implement ML-based fraud detection
   // backend/src/services/payment/ml_fraud_detector.rs

   pub struct FraudRiskScore {
       pub risk_level: f32,  // 0.0 - 1.0
       pub contributing_factors: Vec<String>,
   }

   pub async fn calculate_fraud_risk(
       &self,
       hashed_user_id: &str,
       operation_type: &str,
       amount: i64,
   ) -> Result<FraudRiskScore, AppError> {
       // Features for ML model
       let features = FraudFeatures {
           operation_count_5min: self.get_recent_operation_count(hashed_user_id, 300).await?,
           operation_count_1hr: self.get_recent_operation_count(hashed_user_id, 3600).await?,
           balance_change_velocity: self.get_balance_velocity(hashed_user_id).await?,
           account_age_days: self.get_account_age(hashed_user_id).await?,
           subscription_status: self.get_subscription_status(hashed_user_id).await?,
           geographic_change: self.detect_geographic_anomaly(hashed_user_id).await?,
           time_of_day_anomaly: self.detect_time_anomaly(hashed_user_id).await?,
       };

       // Score using trained model (AWS SageMaker, local model, etc.)
       let risk_score = self.ml_model.predict(features).await?;

       Ok(FraudRiskScore {
           risk_level: risk_score,
           contributing_factors: identify_risk_factors(&features),
       })
   }
   ```

2. **Infrastructure Hardening**
   - Implement distributed rate limiting (Redis cluster) to prevent bypass
   - Add credit operation approval workflow for high-risk transactions (>$100 value)
   - Enable Paddle's built-in fraud detection features
   - Implement CAPTCHA for subscription creation from flagged IPs

3. **Monitoring Enhancements**
   - Add real-time fraud risk scoring to all credit operations
   - Create ML model for payment anomaly detection (AWS SageMaker)
   - Implement behavioral baseline per user (90-day rolling average)
   - Add correlation with external fraud databases (Sift, Stripe Radar)

4. **Process Improvements**
   - Implement manual review for subscriptions >$500/month
   - Require identity verification for high-value accounts
   - Enable 2FA/MFA for all payment-related operations (future)
   - Implement subscription cooling-off period (24hr delay before first charge)

### Compliance Reporting

**PCI DSS Requirement 12.10:** Document fraud incident with:
- Date/time of incident
- Type of fraud (credit manipulation, card testing, etc.)
- Financial impact
- Response actions taken
- Preventive measures implemented

**SOC 2 Type II:** Update incident response controls documentation

**Incident Report Template:**
```markdown
## Payment Fraud Incident Report

**Incident ID:** INC-FRAUD-<YYYYMMDD>-<seq>
**Date/Time:** <UTC timestamp>
**Severity:** P0/P1
**MTTD:** <actual minutes>
**MTTR:** <actual minutes>
**Financial Impact:** $<amount> USD

### Summary
[Brief description of fraud type and mechanism]

### Timeline
- [HH:MM] Fraud detected via CloudWatch alarm
- [HH:MM] Accounts frozen, sessions revoked
- [HH:MM] Financial impact assessed
- [HH:MM] Paddle support contacted
- [HH:MM] Credits recovered, accounts terminated
- [HH:MM] Dispute filed with Paddle

### Impact
- Total fraudulent credits: <amount> tokens
- Consumed credits: <amount> tokens
- Financial loss: $<amount> USD
- Users affected: <count>
- Transactions reversed: <count>

### Root Cause
[Analysis from RCA section]

### Preventive Actions
[List of code/process improvements]

### Compliance Notes
- PCI DSS Req 12.10: Documented in audit trail
- All fraud logs archived to tamper-proof storage (S3 Object Lock)
- Finance team notified for revenue adjustments
```

## Escalation Matrix

| Condition | Escalate To | Timeline |
|-----------|-------------|----------|
| Fraud detected (any amount) | Security Ops Manager, Finance Manager | Immediate |
| Financial impact >$1,000 | CFO, VP Engineering | Within 15min |
| Financial impact >$10,000 | CEO, Board, Legal | Within 30min |
| Ongoing fraud (>1 hour) | Paddle Support, Law Enforcement | Within 1hr |
| Suspected insider fraud | CISO, HR, Legal, External Auditor | Within 2hrs |

## Checklist

- [ ] Alert received and acknowledged
- [ ] Fraud pattern identified and validated
- [ ] Financial impact calculated
- [ ] Suspicious accounts frozen
- [ ] Active sessions revoked
- [ ] Credit operations blocked for frozen accounts
- [ ] Cross-reference with Paddle completed
- [ ] Fraud confirmed or ruled out
- [ ] Fraudulent credits recovered
- [ ] Accounts terminated (confirmed fraud)
- [ ] Paddle dispute filed
- [ ] Finance team notified
- [ ] Evidence archived
- [ ] Post-incident review scheduled
- [ ] Preventive measures implemented
- [ ] Compliance reporting completed
- [ ] ML fraud detection model updated

## References

- [SECURITY_MONITORING.md](../SECURITY_MONITORING.md) - Full architecture
- [FIX_PLAN.md](../FIX_PLAN.md) - Payment security implementation plan
- [Paddle Fraud Prevention](https://www.paddle.com/help/fraud-prevention)
- [PCI DSS Requirement 12.10](https://www.pcisecuritystandards.org/document_library)
- [AWS Fraud Detector](https://aws.amazon.com/fraud-detector/)
