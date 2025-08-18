# Staging environment for Scribe application
# This is the main entrypoint for the staging environment.
# It calls the reusable modules with staging-specific parameters.

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# SES provider for ap-southeast-2 (Sydney) region
provider "aws" {
  alias  = "ses"
  region = "ap-southeast-2"
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Get Route 53 hosted zone for domain validation
data "aws_route53_zone" "main" {
  name         = var.base_domain
  private_zone = false
}

# Add CAA record to allow Amazon to issue certificates
resource "aws_route53_record" "caa_amazon" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = var.base_domain
  type    = "CAA"
  ttl     = 300

  records = [
    "0 issue \"amazon.com\"",
    "0 issuewild \"amazon.com\""
  ]

  lifecycle {
    create_before_destroy = true
  }
}

# Generate random secrets for application
resource "random_password" "jwt_secret" {
  length  = 64
  special = true
}

resource "random_password" "encryption_key" {
  length  = 32
  special = false
}

resource "random_password" "session_secret" {
  length  = 64
  special = true
}

# Generate hex-encoded cookie signing key (32 bytes = 64 hex characters)
resource "random_password" "cookie_signing_key" {
  length  = 64
  special = false
  upper   = false
  numeric = true
  lower   = true
  # This will generate only alphanumeric chars, but we need hex
}

# Convert to proper hex format
locals {
  # Generate a proper 64-byte (128 hex character) signing key
  cookie_signing_key_hex = random_id.cookie_signing_key.hex
}

resource "random_id" "cookie_signing_key" {
  byte_length = 64  # 64 bytes = 512 bits = 128 hex characters
}

# Networking module
module "networking" {
  source = "../../modules/networking"

  environment            = var.environment
  vpc_cidr              = var.vpc_cidr
  public_subnet_cidrs   = var.public_subnet_cidrs
  private_subnet_cidrs  = var.private_subnet_cidrs
}

# RDS and ElastiCache module
module "rds" {
  source = "../../modules/rds"

  environment                    = var.environment
  private_subnet_ids            = module.networking.private_subnet_ids
  rds_security_group_id         = module.networking.rds_security_group_id

  # PostgreSQL configuration
  postgres_version            = var.postgres_version
  db_instance_class          = var.db_instance_class
  allocated_storage          = var.allocated_storage
  max_allocated_storage      = var.max_allocated_storage
  database_name              = var.database_name
  master_username            = var.master_username
  backup_retention_period    = var.backup_retention_period
  multi_az_enabled          = var.multi_az_enabled
  monitoring_interval       = var.monitoring_interval
  performance_insights_enabled = var.performance_insights_enabled
}

# Secrets Manager module
module "secrets" {
  source = "../../modules/secrets"

  environment = var.environment

  # Database credentials
  database_username = module.rds.master_username
  database_password = module.rds.master_password
  database_host     = module.rds.rds_instance_endpoint
  database_port     = module.rds.rds_instance_port
  database_name     = module.rds.database_name
  database_url      = module.rds.database_url

  # Application secrets
  gemini_api_key     = var.gemini_api_key
  qdrant_api_key     = var.qdrant_api_key
  jwt_secret         = random_password.jwt_secret.result
  encryption_key     = random_password.encryption_key.result
  session_secret     = random_password.session_secret.result
  cookie_signing_key = local.cookie_signing_key_hex
  tls_cert_pem       = file("${path.module}/../../../../.internal-certs/internal-cert.pem")
  tls_key_pem        = file("${path.module}/../../../../.internal-certs/internal-key.pem")
}

# Application Load Balancer module
module "alb" {
  source = "../../modules/alb"

  environment               = var.environment
  vpc_id                   = module.networking.vpc_id
  public_subnet_ids        = module.networking.public_subnet_ids
  alb_security_group_id    = module.networking.alb_security_group_id

  # Only request SSL certificate for API domain (backend)
  # Frontend SSL is handled by Vercel
  domain_name              = local.api_domain
  subject_alternative_names = []
  access_logs_bucket       = var.access_logs_bucket
  rate_limit_per_5min      = var.rate_limit_per_5min
  route53_zone_id          = data.aws_route53_zone.main.zone_id
}

# ECS module
module "ecs" {
  source = "../../modules/ecs"

  environment    = var.environment
  aws_region     = var.aws_region
  vpc_id         = module.networking.vpc_id
  private_subnet_ids = module.networking.private_subnet_ids

  # Security groups
  backend_security_group_id = module.networking.backend_security_group_id
  qdrant_security_group_id  = module.networking.qdrant_security_group_id
  efs_security_group_id     = module.networking.efs_security_group_id

  # ALB integration
  backend_target_group_arn = module.alb.backend_target_group_arn
  alb_listener_arn        = module.alb.https_listener_arn

  # Database URL
  database_url = module.rds.database_url

  # ECS configuration
  log_retention_days       = var.log_retention_days
  backend_cpu             = var.backend_cpu
  backend_memory          = var.backend_memory
  backend_desired_count   = var.backend_desired_count
  qdrant_cpu              = var.qdrant_cpu
  qdrant_memory           = var.qdrant_memory
  qdrant_desired_count    = var.qdrant_desired_count
  efs_provisioned_throughput = var.efs_provisioned_throughput

  # Backend secrets
  backend_secrets = module.secrets.backend_secrets_list
  
  # Email configuration
  from_email = local.from_email
  
  # Domain configuration
  domain_name     = local.full_domain
  api_domain_name = local.api_domain

  depends_on = [module.alb]
}

# Monitoring module
module "monitoring" {
  source = "../../modules/monitoring"

  environment = var.environment
  aws_region  = var.aws_region

  # Resource identifiers for monitoring
  alb_arn_suffix            = join("/", slice(split("/", module.alb.alb_arn), 1, length(split("/", module.alb.alb_arn))))  # Extract suffix from ALB ARN
  ecs_cluster_name          = module.ecs.ecs_cluster_name
  backend_service_name      = module.ecs.backend_service_name
  rds_instance_identifier   = module.rds.rds_instance_identifier

  # Notification settings
  create_sns_topic     = var.create_sns_topic
  enable_cloudtrail    = var.enable_cloudtrail
  cloudtrail_bucket_name = var.cloudtrail_bucket_name

  depends_on = [module.ecs, module.alb, module.rds]
}

# SES module for email verification (deployed to ap-southeast-2)
module "ses" {
  source = "../../modules/ses"

  providers = {
    aws = aws.ses
  }

  environment         = var.environment
  domain             = var.base_domain
  ecs_task_role_name = module.ecs.ecs_task_role_name

  depends_on = [module.ecs]
}

