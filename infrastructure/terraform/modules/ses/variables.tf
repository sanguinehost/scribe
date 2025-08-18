# Variables for SES module

variable "environment" {
  description = "Environment name (staging, production)"
  type        = string
}

variable "domain" {
  description = "Domain for SES identity"
  type        = string
}

variable "ecs_task_role_name" {
  description = "Name of the ECS task role to grant SES permissions"
  type        = string
}