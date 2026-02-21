variable "environment" {
  description = "Environment name"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "alb_arn_suffix" {
  description = "ARN suffix of the ALB for metrics"
  type        = string
  default     = ""
}

variable "backend_service_name" {
  description = "Name of the backend ECS service"
  type        = string
}

variable "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  type        = string
}

variable "rds_instance_identifier" {
  description = "Identifier of the RDS instance"
  type        = string
}

variable "sns_topic_arn" {
  description = "ARN of the SNS topic for alarms"
  type        = string
  default     = ""
}

variable "create_sns_topic" {
  description = "Whether to create a new SNS topic"
  type        = bool
  default     = true
}

variable "enable_cloudtrail" {
  description = "Whether to enable CloudTrail"
  type        = bool
  default     = false
}

variable "cloudtrail_bucket_name" {
  description = "Name of the S3 bucket for CloudTrail"
  type        = string
  default     = ""
}
