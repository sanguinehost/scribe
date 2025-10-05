# Kinesis Data Firehose for SIEM Integration
# Streams CloudWatch Logs to S3 for long-term retention and SIEM ingestion
# Supports Datadog, Splunk, ELK, and other SIEM tools

# S3 Bucket for SIEM Log Archival
resource "aws_s3_bucket" "siem_logs" {
  count  = var.enable_kinesis_firehose ? 1 : 0
  bucket = "${var.environment}-scribe-siem-logs"

  tags = {
    Name        = "${var.environment}-scribe-siem-logs"
    Environment = var.environment
    Project     = "scribe"
    Purpose     = "siem_log_archival"
  }
}

# S3 Bucket Versioning
resource "aws_s3_bucket_versioning" "siem_logs" {
  count  = var.enable_kinesis_firehose ? 1 : 0
  bucket = aws_s3_bucket.siem_logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

# S3 Bucket Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "siem_logs" {
  count  = var.enable_kinesis_firehose ? 1 : 0
  bucket = aws_s3_bucket.siem_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket Lifecycle Policy (automatic cleanup)
resource "aws_s3_bucket_lifecycle_configuration" "siem_logs" {
  count  = var.enable_kinesis_firehose ? 1 : 0
  bucket = aws_s3_bucket.siem_logs[0].id

  rule {
    id     = "delete_old_logs"
    status = "Enabled"

    # Apply to all objects in bucket
    filter {}

    expiration {
      days = var.siem_log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# S3 Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "siem_logs" {
  count  = var.enable_kinesis_firehose ? 1 : 0
  bucket = aws_s3_bucket.siem_logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# IAM Role for Kinesis Firehose
resource "aws_iam_role" "firehose_role" {
  count = var.enable_kinesis_firehose ? 1 : 0
  name  = "${var.environment}-scribe-firehose-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "firehose.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name        = "${var.environment}-scribe-firehose-role"
    Environment = var.environment
    Project     = "scribe"
  }
}

# IAM Policy for Firehose to write to S3
resource "aws_iam_role_policy" "firehose_s3_policy" {
  count = var.enable_kinesis_firehose ? 1 : 0
  name  = "${var.environment}-scribe-firehose-s3-policy"
  role  = aws_iam_role.firehose_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.siem_logs[0].arn,
          "${aws_s3_bucket.siem_logs[0].arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

# Kinesis Firehose Delivery Stream
resource "aws_kinesis_firehose_delivery_stream" "security_logs" {
  count       = var.enable_kinesis_firehose ? 1 : 0
  name        = "${var.environment}-scribe-security-logs"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn           = aws_iam_role.firehose_role[0].arn
    bucket_arn         = aws_s3_bucket.siem_logs[0].arn
    prefix             = "security-logs/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
    error_output_prefix = "errors/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/!{firehose:error-output-type}/"

    # Buffering configuration
    buffering_size     = var.firehose_buffer_size_mb
    buffering_interval = var.firehose_buffer_interval_seconds

    # Compression for cost savings
    compression_format = "GZIP"

    # CloudWatch logging for delivery stream errors
    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = "/aws/kinesisfirehose/${var.environment}-scribe-security-logs"
      log_stream_name = "S3Delivery"
    }
  }

  tags = {
    Name        = "${var.environment}-scribe-security-logs"
    Environment = var.environment
    Project     = "scribe"
    Purpose     = "siem_integration"
  }
}

# CloudWatch Log Group for Firehose errors
resource "aws_cloudwatch_log_group" "firehose_logs" {
  count             = var.enable_kinesis_firehose ? 1 : 0
  name              = "/aws/kinesisfirehose/${var.environment}-scribe-security-logs"
  retention_in_days = 7

  tags = {
    Name        = "${var.environment}-scribe-firehose-logs"
    Environment = var.environment
    Project     = "scribe"
  }
}

# CloudWatch Log Stream for Firehose
resource "aws_cloudwatch_log_stream" "firehose_s3_delivery" {
  count          = var.enable_kinesis_firehose ? 1 : 0
  name           = "S3Delivery"
  log_group_name = aws_cloudwatch_log_group.firehose_logs[0].name
}

# IAM Role for CloudWatch Logs to write to Firehose
resource "aws_iam_role" "cloudwatch_to_firehose_role" {
  count = var.enable_kinesis_firehose ? 1 : 0
  name  = "${var.environment}-scribe-cloudwatch-to-firehose-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.aws_region}.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name        = "${var.environment}-scribe-cloudwatch-to-firehose-role"
    Environment = var.environment
    Project     = "scribe"
  }
}

# IAM Policy for CloudWatch Logs to write to Firehose
resource "aws_iam_role_policy" "cloudwatch_to_firehose_policy" {
  count = var.enable_kinesis_firehose ? 1 : 0
  name  = "${var.environment}-scribe-cloudwatch-to-firehose-policy"
  role  = aws_iam_role.cloudwatch_to_firehose_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "firehose:PutRecord",
          "firehose:PutRecordBatch"
        ]
        Resource = aws_kinesis_firehose_delivery_stream.security_logs[0].arn
      }
    ]
  })
}

# CloudWatch Logs Subscription Filter (pipes backend logs to Firehose)
resource "aws_cloudwatch_log_subscription_filter" "backend_to_firehose" {
  count           = var.enable_kinesis_firehose ? 1 : 0
  name            = "${var.environment}-scribe-backend-to-firehose"
  log_group_name  = var.backend_log_group_name
  filter_pattern  = ""  # Empty pattern = all logs
  destination_arn = aws_kinesis_firehose_delivery_stream.security_logs[0].arn
  role_arn        = aws_iam_role.cloudwatch_to_firehose_role[0].arn

  depends_on = [
    aws_iam_role_policy.cloudwatch_to_firehose_policy
  ]
}
