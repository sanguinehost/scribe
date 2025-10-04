# SNS Topics for Security Alert Routing
# Severity-based alert distribution (P0-P3)

# P0: Critical - 15min SLA
# Examples: Webhook attacks, auth takeover, payment fraud in progress
resource "aws_sns_topic" "security_alerts_p0" {
  name         = "${var.environment}-scribe-security-alerts-p0"
  display_name = "Scribe Security Alerts - P0 Critical (15min SLA)"

  tags = {
    Name        = "${var.environment}-scribe-security-alerts-p0"
    Environment = var.environment
    Project     = "scribe"
    Severity    = "P0"
    SLA         = "15min"
  }
}

# P1: High - 1hr SLA
# Examples: Data exfiltration attempts, credential stuffing, encryption failures
resource "aws_sns_topic" "security_alerts_p1" {
  name         = "${var.environment}-scribe-security-alerts-p1"
  display_name = "Scribe Security Alerts - P1 High (1hr SLA)"

  tags = {
    Name        = "${var.environment}-scribe-security-alerts-p1"
    Environment = var.environment
    Project     = "scribe"
    Severity    = "P1"
    SLA         = "1hr"
  }
}

# P2: Medium - 4hr SLA
# Examples: Geographic anomalies, DEK cache anomalies, rate limit violations
resource "aws_sns_topic" "security_alerts_p2" {
  name         = "${var.environment}-scribe-security-alerts-p2"
  display_name = "Scribe Security Alerts - P2 Medium (4hr SLA)"

  tags = {
    Name        = "${var.environment}-scribe-security-alerts-p2"
    Environment = var.environment
    Project     = "scribe"
    Severity    = "P2"
    SLA         = "4hr"
  }
}

# P3: Low - 24hr SLA
# Examples: Info-level events, baseline deviations, audit log anomalies
resource "aws_sns_topic" "security_alerts_p3" {
  name         = "${var.environment}-scribe-security-alerts-p3"
  display_name = "Scribe Security Alerts - P3 Low (24hr SLA)"

  tags = {
    Name        = "${var.environment}-scribe-security-alerts-p3"
    Environment = var.environment
    Project     = "scribe"
    Severity    = "P3"
    SLA         = "24hr"
  }
}

# Email subscriptions (optional - only created if email addresses provided)

resource "aws_sns_topic_subscription" "security_alerts_p0_email" {
  count     = var.alert_email_p0 != "" ? 1 : 0
  topic_arn = aws_sns_topic.security_alerts_p0.arn
  protocol  = "email"
  endpoint  = var.alert_email_p0
}

resource "aws_sns_topic_subscription" "security_alerts_p1_email" {
  count     = var.alert_email_p1 != "" ? 1 : 0
  topic_arn = aws_sns_topic.security_alerts_p1.arn
  protocol  = "email"
  endpoint  = var.alert_email_p1
}

resource "aws_sns_topic_subscription" "security_alerts_p2_email" {
  count     = var.alert_email_p2 != "" ? 1 : 0
  topic_arn = aws_sns_topic.security_alerts_p2.arn
  protocol  = "email"
  endpoint  = var.alert_email_p2
}

resource "aws_sns_topic_subscription" "security_alerts_p3_email" {
  count     = var.alert_email_p3 != "" ? 1 : 0
  topic_arn = aws_sns_topic.security_alerts_p3.arn
  protocol  = "email"
  endpoint  = var.alert_email_p3
}
