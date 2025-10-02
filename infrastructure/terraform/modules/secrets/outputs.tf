output "database_secret_arn" {
  description = "ARN of the database credentials secret"
  value       = aws_secretsmanager_secret.database_credentials.arn
}


output "app_secret_arn" {
  description = "ARN of the application secrets"
  value       = aws_secretsmanager_secret.app_secrets.arn
}

output "backend_secrets_list" {
  description = "List of secrets for ECS backend container"
  value = concat([
    {
      name      = "DATABASE_URL"
      valueFrom = "${aws_secretsmanager_secret.database_credentials.arn}:url::"
    },
    {
      name      = "GEMINI_API_KEY"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:gemini_api_key::"
    },
    {
      name      = "QDRANT_API_KEY"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:qdrant_api_key::"
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
      name      = "TLS_CERT_PEM"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:tls_cert_pem::"
    },
    {
      name      = "TLS_KEY_PEM"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:tls_key_pem::"
    }
  ], var.enable_payments ? [
    # Payment secrets (only included if payments are enabled)
    {
      name      = "PAYMENT_PADDLE_API_KEY"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:paddle_api_key::"
    },
    {
      name      = "PAYMENT_PADDLE_WEBHOOK_SECRET"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:paddle_webhook_secret::"
    },
    {
      name      = "PAYMENT_PADDLE_SANDBOX_MODE"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:paddle_sandbox_mode::"
    },
    {
      name      = "PAYMENT_PAYMENT_BASE_URL"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:payment_base_url::"
    },
    {
      name      = "PAYMENT_FREE_TIER_TOKEN_LIMIT"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:free_tier_token_limit::"
    },
    {
      name      = "PAYMENT_ENFORCE_LIMITS"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:enforce_payment_limits::"
    },
    {
      name      = "PAYMENT_GRACE_PERIOD_DAYS"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:payment_grace_period_days::"
    },
    {
      name      = "CREDITS_ENABLED"
      valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:CREDITS_ENABLED::"
    }
  ] : [])
}
