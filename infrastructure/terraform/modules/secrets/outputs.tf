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
  value = [
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
  ]
}