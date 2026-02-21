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

variable "frontend_security_group_id" {
  description = "Security group ID for frontend ECS tasks"
  type        = string
}


# EFS security group no longer needed - using EBS volumes instead
# variable "efs_security_group_id" {
#   description = "Security group ID for EFS"
#   type        = string
# }

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

# EFS provisioned throughput no longer needed - using EBS volumes instead
# variable "efs_provisioned_throughput" {
#   description = "Provisioned throughput for EFS in MiB/s"
#   type        = number
#   default     = 10
# }

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

variable "enable_execute_command" {
  description = "Enable ECS Exec for the backend service"
  type        = bool
  default     = false
}

variable "domain_name" {
  description = "Primary domain name for the frontend"
  type        = string
}

variable "api_domain_name" {
  description = "API domain name (extracted from subject_alternative_names)"
  type        = string
}


variable "backend_env_vars" {
  description = "List of environment variables for backend container"
  type = list(object({
    name  = string
    value = string
  }))
  default = []
}

variable "docker_labels" {
  description = "Docker labels for the backend container (used for Traefik routing)"
  type        = map(string)
  default     = {}
}

variable "frontend_cpu" {
  description = "CPU units for frontend task (1024 = 1 vCPU)"
  type        = number
  default     = 256
}

variable "frontend_memory" {
  description = "Memory for frontend task in MiB"
  type        = number
  default     = 512
}

variable "frontend_desired_count" {
  description = "Desired number of frontend tasks"
  type        = number
  default     = 1
}

variable "frontend_docker_labels" {
  description = "Docker labels for the frontend container (used for Traefik routing)"
  type        = map(string)
  default     = {}
}

variable "frontend_env_vars" {
  description = "List of environment variables for frontend container"
  type = list(object({
    name  = string
    value = string
  }))
  default = []
}
