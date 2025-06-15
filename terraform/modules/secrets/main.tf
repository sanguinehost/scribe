# Secrets module for Scribe application
# Manages secrets in AWS Secrets Manager

# Database credentials secret
resource "aws_secretsmanager_secret" "database_credentials" {
  name                    = "${var.environment}/scribe/database"
  description             = "Database credentials for Scribe ${var.environment} environment"
  recovery_window_in_days = 0  # Immediate deletion for ephemeral infrastructure

  tags = {
    Name        = "${var.environment}-scribe-database-secret"
    Environment = var.environment
    Project     = "scribe"
  }
}

resource "aws_secretsmanager_secret_version" "database_credentials" {
  secret_id = aws_secretsmanager_secret.database_credentials.id
  secret_string = jsonencode({
    username    = var.database_username
    password    = var.database_password
    engine      = "postgres"
    host        = var.database_host
    port        = var.database_port
    dbname      = var.database_name
    url         = var.database_url
  })
}

# Redis credentials secret
resource "aws_secretsmanager_secret" "redis_credentials" {
  name                    = "${var.environment}/scribe/redis"
  description             = "Redis credentials for Scribe ${var.environment} environment"
  recovery_window_in_days = 0  # Immediate deletion for ephemeral infrastructure

  tags = {
    Name        = "${var.environment}-scribe-redis-secret"
    Environment = var.environment
    Project     = "scribe"
  }
}

resource "aws_secretsmanager_secret_version" "redis_credentials" {
  secret_id = aws_secretsmanager_secret.redis_credentials.id
  secret_string = jsonencode({
    auth_token = var.redis_auth_token
    host       = var.redis_host
    port       = var.redis_port
    url        = var.redis_url
  })
}

# Application secrets (API keys, etc.)
resource "aws_secretsmanager_secret" "app_secrets" {
  name                    = "${var.environment}/scribe/app"
  description             = "Application secrets for Scribe ${var.environment} environment"
  recovery_window_in_days = 0  # Immediate deletion for ephemeral infrastructure

  tags = {
    Name        = "${var.environment}-scribe-app-secret"
    Environment = var.environment
    Project     = "scribe"
  }
}

resource "aws_secretsmanager_secret_version" "app_secrets" {
  secret_id = aws_secretsmanager_secret.app_secrets.id
  secret_string = jsonencode({
    gemini_api_key      = var.gemini_api_key
    jwt_secret          = var.jwt_secret
    encryption_key      = var.encryption_key
    session_secret      = var.session_secret
    cookie_signing_key  = var.cookie_signing_key
    tls_cert_pem        = var.tls_cert_pem
    tls_key_pem         = var.tls_key_pem
    from_email          = var.from_email
  })
}