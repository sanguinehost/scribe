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
  default     = "ap-southeast-4"
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
variable "base_domain" {
  description = "Base domain for the application (e.g., example.com)"
  type        = string
  # No default - must be provided via terraform.tfvars
}

variable "subdomain_prefix" {
  description = "Subdomain prefix (e.g., 'staging', 'prod'). Leave empty for production"
  type        = string
  default     = "staging"
}

variable "app_subdomain" {
  description = "Application subdomain (e.g., 'scribe')"
  type        = string
  default     = "scribe"
}

variable "from_email" {
  description = "From email address for SES (overrides computed email)"
  type        = string
  default     = ""
}

# Computed domain names
locals {
  # Construct full domain dynamically
  full_domain = var.subdomain_prefix != "" ? "${var.subdomain_prefix}.${var.app_subdomain}.${var.base_domain}" : "${var.app_subdomain}.${var.base_domain}"

  api_domain = var.subdomain_prefix != "" ? "api.${var.subdomain_prefix}.${var.app_subdomain}.${var.base_domain}" : "api.${var.app_subdomain}.${var.base_domain}"

  from_email = var.from_email != "" ? var.from_email : "noreply@${var.app_subdomain}.${var.base_domain}"
}

variable "domain_name" {
  description = "Primary domain name for SSL certificate (computed from base_domain)"
  type        = string
  default     = ""  # Will be computed in locals
}

variable "subject_alternative_names" {
  description = "List of alternative domain names for SSL certificate (computed from base_domain)"
  type        = list(string)
  default     = []  # Will be computed in locals
}

# Database configuration
variable "postgres_version" {
  description = "PostgreSQL version"
  type        = string
  default     = "16.8"
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

variable "qdrant_api_key" {
  description = "Qdrant API key for vector database authentication"
  type        = string
  sensitive   = true
  default     = ""
}

# Payment configuration (optional - only used if payment features are enabled)
variable "enable_payments" {
  description = "Whether to enable payment features in the deployment"
  type        = bool
  default     = false
}

variable "paddle_api_key" {
  description = "Paddle API key for payment processing (required if enable_payments is true)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "paddle_webhook_secret" {
  description = "Paddle webhook secret for signature verification (required if enable_payments is true)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "paddle_sandbox_mode" {
  description = "Whether to use Paddle sandbox mode (recommended for staging)"
  type        = bool
  default     = true
}

variable "payment_base_url" {
  description = "Base URL for payment completion redirects (will be computed from domain if not specified)"
  type        = string
  default     = ""
}

variable "free_tier_token_limit" {
  description = "Monthly token limit for free tier users"
  type        = number
  default     = 50000
}

variable "enforce_payment_limits" {
  description = "Whether to enforce payment limits (can disable for testing)"
  type        = bool
  default     = false  # Disabled by default for staging
}

variable "payment_grace_period_days" {
  description = "Grace period in days after subscription expires"
  type        = number
  default     = 7
}

# Paddle subscription price IDs (should be provided via terraform.tfvars or environment variables)
variable "paddle_basic_monthly_price_id" {
  description = "Paddle price ID for Basic plan - monthly billing"
  type        = string
  sensitive   = true
  default     = "pri_01k4qbyetvn495nzv9nkqhxz02"  # From .env PADDLE_BASIC_MONTHLY_PRICE_ID
}

variable "paddle_basic_yearly_price_id" {
  description = "Paddle price ID for Basic plan - yearly billing"
  type        = string
  sensitive   = true
  default     = "pri_01k5ejs7h9zmw4d888r3pjjqna"  # From .env PADDLE_BASIC_YEARLY_PRICE_ID
}

variable "paddle_premium_monthly_price_id" {
  description = "Paddle price ID for Premium plan - monthly billing"
  type        = string
  sensitive   = true
  default     = "pri_01k5ej7wzvpcj6j65vcbpam6t4"  # From .env PADDLE_PREMIUM_MONTHLY_PRICE_ID
}

variable "paddle_premium_yearly_price_id" {
  description = "Paddle price ID for Premium plan - yearly billing"
  type        = string
  sensitive   = true
  default     = "pri_01k5ejva0cwqzbtgzd2c9qk0d4"  # From .env PADDLE_PREMIUM_YEARLY_PRICE_ID
}

# Paddle credit package price IDs
variable "paddle_credits_250_price_id" {
  description = "Paddle price ID for 250 credits package"
  type        = string
  sensitive   = true
  default     = "pri_01k5ej9f8281rvnzybmpxc9hpm"  # From .env PADDLE_CREDITS_250_PRICE_ID
}

variable "paddle_credits_500_price_id" {
  description = "Paddle price ID for 500/550 credits package"
  type        = string
  sensitive   = true
  default     = "pri_01k5ejc7dkwxfty64nfvenj8yq"  # From .env PADDLE_CREDITS_500_PRICE_ID
}

variable "paddle_credits_1500_price_id" {
  description = "Paddle price ID for 1500 credits package"
  type        = string
  sensitive   = true
  default     = "pri_01k5ejdg0hzzem86wzd28zmd2q"  # From .env PADDLE_CREDITS_1500_PRICE_ID
}

variable "paddle_credits_3500_price_id" {
  description = "Paddle price ID for 3500 credits package"
  type        = string
  sensitive   = true
  default     = "pri_01k5ejenme5xjtje37jwfpbxe2"  # From .env PADDLE_CREDITS_3500_PRICE_ID
}

variable "paddle_credits_8000_price_id" {
  description = "Paddle price ID for 8000 credits package"
  type        = string
  sensitive   = true
  default     = "pri_01k5ejfy6t65v6d28fqf0c4kmr"  # From .env PADDLE_CREDITS_8000_PRICE_ID
}
