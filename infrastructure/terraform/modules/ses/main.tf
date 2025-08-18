# SES module for email verification
# This module sets up AWS SES for sending verification emails

# SES domain identity for the configured domain
resource "aws_ses_domain_identity" "main" {
  domain = var.domain
}

# Email address identity for noreply email
resource "aws_ses_email_identity" "noreply" {
  email = "noreply@${var.domain}"
}

# Email address identity for operations email
resource "aws_ses_email_identity" "operations" {
  email = "operations@${var.domain}"
}

# SES domain verification record
resource "aws_ses_domain_dkim" "main" {
  domain = aws_ses_domain_identity.main.domain
}

# Configuration set for tracking
resource "aws_ses_configuration_set" "main" {
  name = "${var.environment}-scribe-emails"

  delivery_options {
    tls_policy = "Require"
  }
}

# IAM role for ECS to send emails via SES
resource "aws_iam_role_policy" "ses_send_policy" {
  name = "${var.environment}-scribe-ses-send"
  role = var.ecs_task_role_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ses:SendEmail",
          "ses:SendRawEmail"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "ses:FromAddress" = [
              "noreply@${var.domain}",
              "operations@${var.domain}"
            ]
          }
        }
      }
    ]
  })
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}