resource "aws_kms_key" "state_key" {
  description             = "KMS key for OpenTofu state encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = {
    Name        = "scribe-state-key"
    Environment = var.environment
    Project     = "scribe"
  }
}

resource "aws_kms_alias" "state_key_alias" {
  name          = var.alias_name
  target_key_id = aws_kms_key.state_key.key_id
}
