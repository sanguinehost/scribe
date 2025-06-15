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

variable "redis_cluster_id" {
  description = "Redis cluster identifier"
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