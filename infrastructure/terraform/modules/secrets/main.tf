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

# Application secrets (API keys, etc.)
resource "random_password" "jwt_secret" {
  length  = 32
  special = true
}

resource "random_password" "encryption_key" {
  length  = 32
  special = false # Often needs to be a specific length/format for encryption libs
}

resource "random_password" "session_secret" {
  length  = 64
  special = true
}

resource "random_id" "cookie_signing_key" {
  byte_length = 64
}

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
  secret_string = jsonencode(merge({
    gemini_api_key      = var.gemini_api_key
    qdrant_api_key      = var.qdrant_api_key
    jwt_secret          = var.jwt_secret != "" ? var.jwt_secret : random_password.jwt_secret.result
    encryption_key      = var.encryption_key != "" ? var.encryption_key : random_password.encryption_key.result
    session_secret      = var.session_secret != "" ? var.session_secret : random_password.session_secret.result
    cookie_signing_key  = var.cookie_signing_key != "" ? var.cookie_signing_key : random_id.cookie_signing_key.hex
    tls_cert_pem        = var.tls_cert_pem
    tls_key_pem         = var.tls_key_pem
    from_email          = var.from_email
  }, var.enable_payments ? {
    # Payment configuration (only included if payments are enabled)
    paddle_api_key           = var.paddle_api_key
    paddle_webhook_secret    = var.paddle_webhook_secret
    paddle_sandbox_mode      = tostring(var.paddle_sandbox_mode)
    payment_base_url         = var.payment_base_url
    free_tier_token_limit    = tostring(var.free_tier_token_limit)
    enforce_payment_limits   = tostring(var.enforce_payment_limits)
    payment_grace_period_days = tostring(var.payment_grace_period_days)
    # Paddle subscription price IDs
    paddle_basic_monthly_price_id  = var.paddle_basic_monthly_price_id
    paddle_basic_yearly_price_id   = var.paddle_basic_yearly_price_id
    paddle_premium_monthly_price_id = var.paddle_premium_monthly_price_id
    paddle_premium_yearly_price_id = var.paddle_premium_yearly_price_id
    # Paddle credit package price IDs
    paddle_credits_250_price_id  = var.paddle_credits_250_price_id
    paddle_credits_500_price_id  = var.paddle_credits_500_price_id
    paddle_credits_1500_price_id = var.paddle_credits_1500_price_id
    paddle_credits_3500_price_id = var.paddle_credits_3500_price_id
    paddle_credits_8000_price_id = var.paddle_credits_8000_price_id
    # OpenObserve credentials
    openobserve_admin_password     = var.openobserve_admin_password
    openobserve_auth_token         = var.openobserve_auth_token
  } : {}))
}
