# CloudWatch Alarms for Security Monitoring
# All alarms created in CALIBRATION MODE (actions_enabled = false)
# Enable after 7-14 day baseline collection period

# =============================================================================
# P0 ALARMS - CRITICAL (15min SLA)
# =============================================================================

# P0: Webhook Attack Detection
# Triggers on 5+ signature failures in 5 minutes
resource "aws_cloudwatch_metric_alarm" "webhook_attack_p0" {
  alarm_name          = "${var.environment}-P0-WebhookAttackDetected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "WebhookSignatureFailureCount"
  namespace           = "Scribe/Security"
  period              = "300"  # 5 minutes
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "CRITICAL: Possible webhook replay/spoofing attack - 5+ signature failures in 5 minutes"
  treat_missing_data  = "notBreaching"

  # CALIBRATION MODE: Alarms disabled until baseline established
  actions_enabled = var.enable_security_alarms

  alarm_actions = [aws_sns_topic.security_alerts_p0.arn]
  ok_actions    = [aws_sns_topic.security_alerts_p0.arn]

  tags = {
    Name        = "${var.environment}-P0-WebhookAttack"
    Environment = var.environment
    Project     = "scribe"
    Severity    = "P0"
    SLA         = "15min"
    AttackType  = "webhook_spoofing"
  }
}

# P0: Account Takeover Detection
# Triggers on 10+ failed auth attempts in 5 minutes (brute force)
resource "aws_cloudwatch_metric_alarm" "account_takeover_p0" {
  alarm_name          = "${var.environment}-P0-AccountTakeoverDetected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "AuthFailureCount"
  namespace           = "Scribe/Security"
  period              = "300"  # 5 minutes
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "CRITICAL: Possible account takeover - 10+ failed auth attempts in 5 minutes"
  treat_missing_data  = "notBreaching"

  # CALIBRATION MODE: Alarms disabled until baseline established
  actions_enabled = var.enable_security_alarms

  alarm_actions = [aws_sns_topic.security_alerts_p0.arn]
  ok_actions    = [aws_sns_topic.security_alerts_p0.arn]

  tags = {
    Name        = "${var.environment}-P0-AccountTakeover"
    Environment = var.environment
    Project     = "scribe"
    Severity    = "P0"
    SLA         = "15min"
    AttackType  = "brute_force"
  }
}

# =============================================================================
# P1 ALARMS - HIGH (1hr SLA)
# =============================================================================

# P1: Payment Fraud Detection
# Triggers on 50+ credit operations in 5 minutes
resource "aws_cloudwatch_metric_alarm" "payment_fraud_p1" {
  alarm_name          = "${var.environment}-P1-PaymentFraudDetected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "CreditOperationRate"
  namespace           = "Scribe/Security"
  period              = "300"  # 5 minutes
  statistic           = "Sum"
  threshold           = "50"
  alarm_description   = "HIGH: Possible payment fraud - 50+ credit operations in 5 minutes"
  treat_missing_data  = "notBreaching"

  # CALIBRATION MODE: Alarms disabled until baseline established
  actions_enabled = var.enable_security_alarms

  alarm_actions = [aws_sns_topic.security_alerts_p1.arn]
  ok_actions    = [aws_sns_topic.security_alerts_p1.arn]

  tags = {
    Name        = "${var.environment}-P1-PaymentFraud"
    Environment = var.environment
    Project     = "scribe"
    Severity    = "P1"
    SLA         = "1hr"
    AttackType  = "payment_fraud"
  }
}

# P1: Data Exfiltration Detection
# Triggers on 5+ data exfiltration events in 15 minutes
resource "aws_cloudwatch_metric_alarm" "data_exfiltration_p1" {
  alarm_name          = "${var.environment}-P1-DataExfiltrationDetected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "DataExfiltrationCount"
  namespace           = "Scribe/Security"
  period              = "900"  # 15 minutes
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "HIGH: Possible data exfiltration - bulk data access detected"
  treat_missing_data  = "notBreaching"

  # CALIBRATION MODE: Alarms disabled until baseline established
  actions_enabled = var.enable_security_alarms

  alarm_actions = [aws_sns_topic.security_alerts_p1.arn]
  ok_actions    = [aws_sns_topic.security_alerts_p1.arn]

  tags = {
    Name        = "${var.environment}-P1-DataExfiltration"
    Environment = var.environment
    Project     = "scribe"
    Severity    = "P1"
    SLA         = "1hr"
    AttackType  = "data_exfiltration"
  }
}

# P1: DEK Scraping Detection
# Triggers on any DEK scraping attempt (should never happen in normal operation)
resource "aws_cloudwatch_metric_alarm" "dek_scraping_p1" {
  alarm_name          = "${var.environment}-P1-DekScrapingDetected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "DekScrapingAttemptCount"
  namespace           = "Scribe/Security"
  period              = "300"  # 5 minutes
  statistic           = "Sum"
  threshold           = "1"  # Any attempt is critical
  alarm_description   = "HIGH: Encryption key scraping attempt - bulk DEK cache access detected"
  treat_missing_data  = "notBreaching"

  # CALIBRATION MODE: Alarms disabled until baseline established
  actions_enabled = var.enable_security_alarms

  alarm_actions = [aws_sns_topic.security_alerts_p1.arn]
  ok_actions    = [aws_sns_topic.security_alerts_p1.arn]

  tags = {
    Name        = "${var.environment}-P1-DekScraping"
    Environment = var.environment
    Project     = "scribe"
    Severity    = "P1"
    SLA         = "1hr"
    AttackType  = "key_scraping"
  }
}

# P1: Replay Attack Detection
# Triggers on any replay attack (duplicate transaction IDs)
resource "aws_cloudwatch_metric_alarm" "replay_attack_p1" {
  alarm_name          = "${var.environment}-P1-ReplayAttackDetected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "ReplayAttackCount"
  namespace           = "Scribe/Security"
  period              = "300"  # 5 minutes
  statistic           = "Sum"
  threshold           = "1"  # Any replay attempt is suspicious
  alarm_description   = "HIGH: Webhook replay attack - duplicate transaction ID detected"
  treat_missing_data  = "notBreaching"

  # CALIBRATION MODE: Alarms disabled until baseline established
  actions_enabled = var.enable_security_alarms

  alarm_actions = [aws_sns_topic.security_alerts_p1.arn]
  ok_actions    = [aws_sns_topic.security_alerts_p1.arn]

  tags = {
    Name        = "${var.environment}-P1-ReplayAttack"
    Environment = var.environment
    Project     = "scribe"
    Severity    = "P1"
    SLA         = "1hr"
    AttackType  = "replay_attack"
  }
}

# =============================================================================
# P2 ALARMS - MEDIUM (4hr SLA)
# =============================================================================

# P2: Encryption Failure Detection
# Triggers on 5+ encryption errors in 15 minutes
resource "aws_cloudwatch_metric_alarm" "encryption_failure_p2" {
  alarm_name          = "${var.environment}-P2-EncryptionFailureDetected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "EncryptionErrorCount"
  namespace           = "Scribe/Security"
  period              = "900"  # 15 minutes
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "MEDIUM: Multiple encryption failures - possible key compromise or system issue"
  treat_missing_data  = "notBreaching"

  # CALIBRATION MODE: Alarms disabled until baseline established
  actions_enabled = var.enable_security_alarms

  alarm_actions = [aws_sns_topic.security_alerts_p2.arn]
  ok_actions    = [aws_sns_topic.security_alerts_p2.arn]

  tags = {
    Name        = "${var.environment}-P2-EncryptionFailure"
    Environment = var.environment
    Project     = "scribe"
    Severity    = "P2"
    SLA         = "4hr"
    AttackType  = "encryption_failure"
  }
}

# P2: Credit Anomaly Detection
# Triggers on unusual credit operation patterns
resource "aws_cloudwatch_metric_alarm" "credit_anomaly_p2" {
  alarm_name          = "${var.environment}-P2-CreditAnomalyDetected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "CreditAnomalyCount"
  namespace           = "Scribe/Security"
  period              = "900"  # 15 minutes
  statistic           = "Sum"
  threshold           = "3"
  alarm_description   = "MEDIUM: Credit anomaly detected - unusual patterns in credit operations"
  treat_missing_data  = "notBreaching"

  # CALIBRATION MODE: Alarms disabled until baseline established
  actions_enabled = var.enable_security_alarms

  alarm_actions = [aws_sns_topic.security_alerts_p2.arn]
  ok_actions    = [aws_sns_topic.security_alerts_p2.arn]

  tags = {
    Name        = "${var.environment}-P2-CreditAnomaly"
    Environment = var.environment
    Project     = "scribe"
    Severity    = "P2"
    SLA         = "4hr"
    AttackType  = "credit_anomaly"
  }
}

# P2: Webhook Processing Slowdown (potential DDoS)
# Triggers on high webhook processing time (>2 seconds average)
resource "aws_cloudwatch_metric_alarm" "webhook_slowdown_p2" {
  alarm_name          = "${var.environment}-P2-WebhookSlowdownDetected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"  # 2 consecutive periods
  metric_name         = "WebhookProcessingDuration"
  namespace           = "Scribe/Security"
  period              = "300"  # 5 minutes
  statistic           = "Average"
  threshold           = "2000"  # 2 seconds in milliseconds
  alarm_description   = "MEDIUM: Webhook processing slowdown - possible DDoS or resource exhaustion"
  treat_missing_data  = "notBreaching"

  # CALIBRATION MODE: Alarms disabled until baseline established
  actions_enabled = var.enable_security_alarms

  alarm_actions = [aws_sns_topic.security_alerts_p2.arn]
  ok_actions    = [aws_sns_topic.security_alerts_p2.arn]

  tags = {
    Name        = "${var.environment}-P2-WebhookSlowdown"
    Environment = var.environment
    Project     = "scribe"
    Severity    = "P2"
    SLA         = "4hr"
    AttackType  = "ddos"
  }
}

# =============================================================================
# COMPOSITE ALARMS - Correlation Detection
# =============================================================================

# Composite Alarm: Credential Stuffing Attack
# Triggers when both high auth failures AND webhook attacks detected
resource "aws_cloudwatch_composite_alarm" "credential_stuffing_p1" {
  alarm_name          = "${var.environment}-P1-CredentialStuffingDetected"
  alarm_description   = "HIGH: Credential stuffing attack - correlated auth failures and suspicious activity"

  # Correlation rule: High auth failures + webhook anomalies
  alarm_rule = join(" OR ", [
    "ALARM(${aws_cloudwatch_metric_alarm.account_takeover_p0.alarm_name})",
    join(" AND ", [
      "ALARM(${aws_cloudwatch_metric_alarm.account_takeover_p0.alarm_name})",
      "ALARM(${aws_cloudwatch_metric_alarm.webhook_attack_p0.alarm_name})"
    ])
  ])

  # CALIBRATION MODE: Alarms disabled until baseline established
  actions_enabled = var.enable_security_alarms

  alarm_actions = [aws_sns_topic.security_alerts_p1.arn]
  ok_actions    = [aws_sns_topic.security_alerts_p1.arn]

  tags = {
    Name        = "${var.environment}-P1-CredentialStuffing"
    Environment = var.environment
    Project     = "scribe"
    Severity    = "P1"
    SLA         = "1hr"
    AttackType  = "credential_stuffing"
  }

  depends_on = [
    aws_cloudwatch_metric_alarm.account_takeover_p0,
    aws_cloudwatch_metric_alarm.webhook_attack_p0
  ]
}

# Composite Alarm: APT-Style Attack Pattern
# Triggers on multiple simultaneous indicators (data exfiltration + encryption errors + anomalies)
resource "aws_cloudwatch_composite_alarm" "apt_attack_p0" {
  alarm_name          = "${var.environment}-P0-APTAttackDetected"
  alarm_description   = "CRITICAL: Advanced Persistent Threat detected - multiple attack indicators"

  # Correlation rule: 2+ security alarms active simultaneously
  alarm_rule = join(" OR ", [
    join(" AND ", [
      "ALARM(${aws_cloudwatch_metric_alarm.data_exfiltration_p1.alarm_name})",
      "ALARM(${aws_cloudwatch_metric_alarm.dek_scraping_p1.alarm_name})"
    ]),
    join(" AND ", [
      "ALARM(${aws_cloudwatch_metric_alarm.data_exfiltration_p1.alarm_name})",
      "ALARM(${aws_cloudwatch_metric_alarm.encryption_failure_p2.alarm_name})"
    ]),
    join(" AND ", [
      "ALARM(${aws_cloudwatch_metric_alarm.payment_fraud_p1.alarm_name})",
      "ALARM(${aws_cloudwatch_metric_alarm.credit_anomaly_p2.alarm_name})"
    ])
  ])

  # CALIBRATION MODE: Alarms disabled until baseline established
  actions_enabled = var.enable_security_alarms

  alarm_actions = [aws_sns_topic.security_alerts_p0.arn]
  ok_actions    = [aws_sns_topic.security_alerts_p0.arn]

  tags = {
    Name        = "${var.environment}-P0-APTAttack"
    Environment = var.environment
    Project     = "scribe"
    Severity    = "P0"
    SLA         = "15min"
    AttackType  = "apt"
  }

  depends_on = [
    aws_cloudwatch_metric_alarm.data_exfiltration_p1,
    aws_cloudwatch_metric_alarm.dek_scraping_p1,
    aws_cloudwatch_metric_alarm.encryption_failure_p2,
    aws_cloudwatch_metric_alarm.payment_fraud_p1,
    aws_cloudwatch_metric_alarm.credit_anomaly_p2
  ]
}
