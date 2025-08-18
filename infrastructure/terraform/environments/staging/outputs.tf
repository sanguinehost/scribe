# Outputs for the staging environment
# These outputs expose key information about the deployed infrastructure

# Networking outputs
output "vpc_id" {
  description = "ID of the VPC"
  value       = module.networking.vpc_id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = module.networking.public_subnet_ids
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = module.networking.private_subnet_ids
}

# Load balancer outputs
output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = module.alb.alb_dns_name
}

output "alb_zone_id" {
  description = "Zone ID of the Application Load Balancer"
  value       = module.alb.alb_zone_id
}

output "ssl_certificate_arn" {
  description = "ARN of the SSL certificate"
  value       = module.alb.ssl_certificate_arn
}

output "ssl_certificate_validation_options" {
  description = "SSL certificate validation options for DNS validation"
  value       = module.alb.ssl_certificate_validation_options
  sensitive   = true
}

# ECS outputs
output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = module.ecs.ecs_cluster_name
}

output "backend_ecr_repository_url" {
  description = "URL of the backend ECR repository"
  value       = module.ecs.backend_ecr_repository_url
}

output "qdrant_ecr_repository_url" {
  description = "URL of the Qdrant ECR repository"
  value       = module.ecs.qdrant_ecr_repository_url
}

# Database outputs
output "rds_endpoint" {
  description = "RDS instance endpoint"
  value       = module.rds.rds_instance_endpoint
}

# Secrets outputs
output "database_secret_arn" {
  description = "ARN of the database credentials secret"
  value       = module.secrets.database_secret_arn
}

output "app_secret_arn" {
  description = "ARN of the application secrets"
  value       = module.secrets.app_secret_arn
}

# Monitoring outputs
output "cloudwatch_dashboard_url" {
  description = "URL of the CloudWatch dashboard"
  value       = module.monitoring.dashboard_url
}

# Domain configuration instructions
output "dns_validation_instructions" {
  description = "Instructions for DNS validation of SSL certificate"
  value = "To complete SSL certificate validation, add the following DNS records to your domain:"
}

# Connection information
output "api_endpoint" {
  description = "API endpoint URL"
  value       = "https://${var.domain_name}"
}

output "environment_info" {
  description = "Environment information"
  value = {
    environment    = var.environment
    aws_region     = var.aws_region
    domain_name    = var.domain_name
    cluster_name   = module.ecs.ecs_cluster_name
  }
}

