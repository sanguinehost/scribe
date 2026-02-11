variable "environment" {
  description = "Environment name"
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

variable "ecs_cluster_id" {
  description = "ECS cluster ID"
  type        = string
}

variable "service_discovery_namespace_id" {
  description = "ID of the service discovery namespace"
  type        = string
}

variable "openobserve_cpu" {
  description = "CPU units for OpenObserve"
  type        = number
  default     = 512
}

variable "openobserve_memory" {
  description = "Memory for OpenObserve in MiB"
  type        = number
  default     = 1024
}

variable "openobserve_admin_email" {
  description = "Admin email for OpenObserve"
  type        = string
}

variable "openobserve_admin_password" {
  description = "Admin password for OpenObserve"
  type        = string
  sensitive   = true
}

variable "domain_name" {
  description = "Domain name for OpenObserve UI"
  type        = string
}

variable "traefik_security_group_id" {
  description = "Security group ID of Traefik (to allow access)"
  type        = string
}

variable "backend_security_group_id" {
  description = "Security group ID of the backend service"
  type        = string
  default     = ""
}
