variable "environment" {
  description = "Environment name"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "public_subnet_id" {
  description = "Public subnet ID for the Tailscale router"
  type        = string
}

variable "tailscale_auth_key" {
  description = "Tailscale authentication key (ephemeral/reusable)"
  type        = string
  sensitive   = true
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.nano"
}

variable "key_name" {
  description = "EC2 key pair name"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR to advertise as a subnet route"
  type        = string
}
