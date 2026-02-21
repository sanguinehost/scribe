variable "environment" {
  description = "Environment name"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "public_subnet_ids" {
  description = "List of public subnet IDs for the NLB"
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs for the Traefik ECS service"
  type        = list(string)
}

variable "ecs_cluster_id" {
  description = "ECS cluster ID"
  type        = string
}

variable "domain_name" {
  description = "Primary domain name for Traefik"
  type        = string
}

variable "route53_zone_id" {
  description = "Route 53 hosted zone ID"
  type        = string
}

variable "traefik_cpu" {
  description = "CPU units for Traefik task"
  type        = number
  default     = 256
}

variable "traefik_memory" {
  description = "Memory for Traefik task in MiB"
  type        = number
  default     = 512
}

variable "desired_count" {
  description = "Desired number of Traefik tasks"
  type        = number
  default     = 1
}

variable "execution_role_arn" {
  description = "ARN of the ECS task execution role"
  type        = string
}

variable "task_role_arn" {
  description = "ARN of the ECS task role"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "subject_alternative_names" {
  description = "List of additional domain names for the certificate"
  type        = list(string)
  default     = []
}
variable "additional_domains" {
  description = "List of additional subdomains to point to the NLB"
  type        = list(string)
  default     = []
}
