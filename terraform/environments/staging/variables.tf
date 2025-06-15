# Variables for the staging environment
# Define default values here or override via terraform.tfvars

# General configuration
variable "environment" {
  description = "Environment name"
  type        = string
  default     = "staging"
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "ec2_key_pair_name" {
  description = "Name of the EC2 key pair for SSH access to Tailscale router"
  type        = string
  default     = "staging-scribe-key"  # Update this to match your key pair name
}

# Networking configuration
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.11.0/24"]
}

# Domain configuration
variable "domain_name" {
  description = "Primary domain name for SSL certificate"
  type        = string
  default     = "staging.scribe.sanguinehost.com"
}

variable "subject_alternative_names" {
  description = "List of alternative domain names for SSL certificate"
  type        = list(string)
  default     = ["api.staging.scribe.sanguinehost.com"]
}

# Database configuration
variable "postgres_version" {
  description = "PostgreSQL version"
  type        = string
  default     = "15.4"
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t4g.micro"
}

variable "allocated_storage" {
  description = "Initial allocated storage in GB"
  type        = number
  default     = 20
}

variable "max_allocated_storage" {
  description = "Maximum allocated storage in GB"
  type        = number
  default     = 100
}

variable "database_name" {
  description = "Name of the database to create"
  type        = string
  default     = "scribe"
}

variable "master_username" {
  description = "Master username for the database"
  type        = string
  default     = "scribe_admin"
}

variable "backup_retention_period" {
  description = "Backup retention period in days"
  type        = number
  default     = 7
}

variable "multi_az_enabled" {
  description = "Enable Multi-AZ deployment for RDS"
  type        = bool
  default     = false  # Disabled for staging to save costs
}

variable "monitoring_interval" {
  description = "Enhanced monitoring interval for RDS (0 to disable)"
  type        = number
  default     = 0  # Disabled for staging to save costs
}

variable "performance_insights_enabled" {
  description = "Enable Performance Insights for RDS"
  type        = bool
  default     = false  # Disabled for staging to save costs
}

# Redis configuration
variable "redis_version" {
  description = "Redis version"
  type        = string
  default     = "7.0"
}

variable "redis_node_type" {
  description = "ElastiCache node type"
  type        = string
  default     = "cache.t4g.micro"
}

variable "redis_num_cache_nodes" {
  description = "Number of cache nodes"
  type        = number
  default     = 1  # Single node for staging
}

variable "redis_snapshot_retention_limit" {
  description = "Number of days to retain Redis snapshots"
  type        = number
  default     = 3  # Reduced for staging
}

# ECS configuration
variable "backend_cpu" {
  description = "CPU units for backend task (1024 = 1 vCPU)"
  type        = number
  default     = 256  # Lower for staging
}

variable "backend_memory" {
  description = "Memory for backend task in MiB"
  type        = number
  default     = 512  # Lower for staging
}

variable "backend_desired_count" {
  description = "Desired number of backend tasks"
  type        = number
  default     = 1  # Single instance for staging
}

variable "qdrant_cpu" {
  description = "CPU units for Qdrant task (1024 = 1 vCPU)"
  type        = number
  default     = 256  # Lower for staging
}

variable "qdrant_memory" {
  description = "Memory for Qdrant task in MiB"
  type        = number
  default     = 512  # Lower for staging
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

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 7  # Reduced for staging
}

# ALB configuration
variable "access_logs_bucket" {
  description = "S3 bucket for ALB access logs (optional)"
  type        = string
  default     = ""  # Disabled for staging
}

variable "rate_limit_per_5min" {
  description = "Rate limit per IP per 5 minutes"
  type        = number
  default     = 1000  # Lower for staging
}

# Monitoring configuration
variable "create_sns_topic" {
  description = "Whether to create an SNS topic for alerts"
  type        = bool
  default     = false  # Disabled for staging
}

variable "enable_cloudtrail" {
  description = "Whether to enable CloudTrail"
  type        = bool
  default     = false  # Disabled for staging
}

variable "cloudtrail_bucket_name" {
  description = "S3 bucket name for CloudTrail logs"
  type        = string
  default     = ""
}

# Application secrets (should be provided via terraform.tfvars or environment variables)
variable "gemini_api_key" {
  description = "Gemini API key"
  type        = string
  sensitive   = true
  default     = ""
}