variable "environment" {
  description = "Environment name (e.g., staging, production)"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs"
  type        = list(string)
}

variable "backend_security_group_id" {
  description = "Security group ID for backend ECS tasks"
  type        = string
}

variable "qdrant_security_group_id" {
  description = "Security group ID for Qdrant ECS tasks"
  type        = string
}

variable "efs_security_group_id" {
  description = "Security group ID for EFS"
  type        = string
}

variable "backend_target_group_arn" {
  description = "Target group ARN for backend ALB"
  type        = string
}

variable "alb_listener_arn" {
  description = "ALB listener ARN for dependency"
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 7
}

variable "backend_cpu" {
  description = "CPU units for backend task (1024 = 1 vCPU)"
  type        = number
  default     = 512
}

variable "backend_memory" {
  description = "Memory for backend task in MiB"
  type        = number
  default     = 1024
}

variable "backend_desired_count" {
  description = "Desired number of backend tasks"
  type        = number
  default     = 2
}

variable "qdrant_cpu" {
  description = "CPU units for Qdrant task (1024 = 1 vCPU)"
  type        = number
  default     = 512
}

variable "qdrant_memory" {
  description = "Memory for Qdrant task in MiB"
  type        = number
  default     = 1024
}

variable "qdrant_desired_count" {
  description = "Desired number of Qdrant tasks"
  type        = number
  default     = 1
}

variable "efs_provisioned_throughput" {
  description = "Provisioned throughput for EFS in MiB/s"
  type        = number
  default     = 10
}

variable "database_url" {
  description = "PostgreSQL database URL"
  type        = string
}

variable "backend_secrets" {
  description = "List of secrets for backend container"
  type = list(object({
    name      = string
    valueFrom = string
  }))
  default = []
}

variable "from_email" {
  description = "From email address for SES"
  type        = string
  default     = ""
}

variable "domain_name" {
  description = "Primary domain name for the frontend"
  type        = string
}

variable "api_domain_name" {
  description = "API domain name (extracted from subject_alternative_names)"
  type        = string
}