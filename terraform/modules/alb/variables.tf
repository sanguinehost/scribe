variable "environment" {
  description = "Environment name (e.g., staging, production)"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "public_subnet_ids" {
  description = "List of public subnet IDs"
  type        = list(string)
}

variable "alb_security_group_id" {
  description = "Security group ID for ALB"
  type        = string
}

variable "domain_name" {
  description = "Primary domain name for SSL certificate"
  type        = string
}

variable "subject_alternative_names" {
  description = "List of alternative domain names for SSL certificate"
  type        = list(string)
  default     = []
}

variable "access_logs_bucket" {
  description = "S3 bucket for ALB access logs (optional)"
  type        = string
  default     = ""
}

variable "rate_limit_per_5min" {
  description = "Rate limit per IP per 5 minutes"
  type        = number
  default     = 2000
}