variable "environment" {
  description = "Environment name (e.g., staging, production)"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "alb_arn_suffix" {
  description = "ALB ARN suffix for CloudWatch metrics"
  type        = string
}

variable "ecs_cluster_name" {
  description = "ECS cluster name"
  type        = string
}

variable "backend_service_name" {
  description = "Backend ECS service name"
  type        = string
}

variable "rds_instance_identifier" {
  description = "RDS instance identifier"
  type        = string
}


variable "sns_topic_arn" {
  description = "SNS topic ARN for alarm notifications (optional)"
  type        = string
  default     = ""
}

variable "create_sns_topic" {
  description = "Whether to create an SNS topic for alerts"
  type        = bool
  default     = false
}

variable "enable_cloudtrail" {
  description = "Whether to enable CloudTrail"
  type        = bool
  default     = false
}

variable "cloudtrail_bucket_name" {
  description = "S3 bucket name for CloudTrail logs"
  type        = string
  default     = ""
}

# Security Monitoring Variables (Task 10)

variable "backend_log_group_name" {
  description = "CloudWatch log group name for backend logs (required for metric filters)"
  type        = string
}

variable "enable_security_alarms" {
  description = "Enable security alarm actions (set to false for calibration mode)"
  type        = bool
  default     = false
}

variable "alert_email_p0" {
  description = "Email address for P0 critical security alerts"
  type        = string
  default     = ""
}

variable "alert_email_p1" {
  description = "Email address for P1 high security alerts"
  type        = string
  default     = ""
}

variable "alert_email_p2" {
  description = "Email address for P2 medium security alerts"
  type        = string
  default     = ""
}

variable "alert_email_p3" {
  description = "Email address for P3 low security alerts"
  type        = string
  default     = ""
}

variable "enable_kinesis_firehose" {
  description = "Enable Kinesis Firehose for SIEM log streaming"
  type        = bool
  default     = true
}

variable "firehose_buffer_size_mb" {
  description = "Kinesis Firehose buffer size in MB (1-128)"
  type        = number
  default     = 5
}

variable "firehose_buffer_interval_seconds" {
  description = "Kinesis Firehose buffer interval in seconds (60-900)"
  type        = number
  default     = 60
}

variable "siem_log_retention_days" {
  description = "S3 log retention period in days for SIEM integration"
  type        = number
  default     = 365
}
