output "database_secret_arn" {
  description = "ARN of the database credentials secret"
  value       = aws_secretsmanager_secret.database_credentials.arn
}

output "app_secrets_arn" {
  description = "ARN of the application secrets"
  value       = aws_secretsmanager_secret.app_secrets.arn
}

output "app_secret_arn" {
  description = "Alias for app_secrets_arn (deprecated)"
  value       = aws_secretsmanager_secret.app_secrets.arn
}

# Construct list of secrets for ECS container definition
locals {
  base_secrets = [
    {
      name      = "DATABASE_URL"
      valueFrom = "${aws_secretsmanager_secret.database_credentials.arn}:url::"
    },
    {
      name      = "GEMINI_API_KEY"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:gemini_api_key::"
    },
    {
      name      = "JWT_SECRET"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:jwt_secret::"
    },
    {
      name      = "ENCRYPTION_KEY"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:encryption_key::"
    },
    {
      name      = "SESSION_SECRET"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:session_secret::"
    },
    {
      name      = "COOKIE_SIGNING_KEY"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:cookie_signing_key::"
    },
    {
      name      = "QDRANT_API_KEY"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:qdrant_api_key::"
    },
    {
      name      = "TLS_CERT_PEM"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:tls_cert_pem::"
    },
    {
      name      = "TLS_KEY_PEM"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:tls_key_pem::"
    }
  ]

  payment_secrets = [
    {
      name      = "PAYMENT_PADDLE_API_KEY"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:paddle_api_key::"
    },
    {
      name      = "PAYMENT_PADDLE_WEBHOOK_SECRET"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:paddle_webhook_secret::"
    },
    {
      name      = "PAYMENT_DATA_ENCRYPTION_KEY"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:PAYMENT_DATA_ENCRYPTION_KEY::"
    },
    {
      name      = "PAYMENT_PADDLE_BASIC_MONTHLY_PRICE_ID"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:paddle_basic_monthly_price_id::"
    },
    {
      name      = "PAYMENT_PADDLE_BASIC_YEARLY_PRICE_ID"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:paddle_basic_yearly_price_id::"
    }
  ]
}

output "backend_secrets_list" {
  description = "List of secrets for ECS container definition"
  value       = concat(local.base_secrets, var.enable_payments ? local.payment_secrets : [])
}
