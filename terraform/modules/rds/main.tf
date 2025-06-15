# RDS module for Scribe application
# Creates PostgreSQL RDS instance with proper security and backup configuration

# DB Subnet Group
resource "aws_db_subnet_group" "scribe_db_subnet_group" {
  name       = "${var.environment}-scribe-db-subnet-group"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name        = "${var.environment}-scribe-db-subnet-group"
    Environment = var.environment
    Project     = "scribe"
  }
}

# Random password for database master user
resource "random_password" "db_master_password" {
  length  = 32
  special = true
  # Exclude characters that RDS doesn't accept: /, @, ", and space
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# RDS PostgreSQL Instance
resource "aws_db_instance" "scribe_postgres" {
  identifier             = "${var.environment}-scribe-postgres"
  engine                 = "postgres"
  engine_version         = var.postgres_version
  instance_class         = var.db_instance_class
  allocated_storage      = var.allocated_storage
  max_allocated_storage  = var.max_allocated_storage
  storage_type           = "gp3"
  storage_encrypted      = true

  db_name  = var.database_name
  username = var.master_username
  password = random_password.db_master_password.result

  vpc_security_group_ids = [var.rds_security_group_id]
  db_subnet_group_name   = aws_db_subnet_group.scribe_db_subnet_group.name

  # Backup configuration
  backup_retention_period = var.backup_retention_period
  backup_window          = var.backup_window
  maintenance_window     = var.maintenance_window

  # Multi-AZ for high availability (can be disabled for cost savings in staging)
  multi_az = var.multi_az_enabled

  # Monitoring
  monitoring_interval = var.monitoring_interval
  monitoring_role_arn = var.monitoring_interval > 0 ? aws_iam_role.rds_enhanced_monitoring[0].arn : null

  # Performance Insights
  performance_insights_enabled = var.performance_insights_enabled

  # Deletion protection (disabled for ephemeral infrastructure)
  deletion_protection = false
  skip_final_snapshot = true

  # Enable automated minor version upgrades
  auto_minor_version_upgrade = true

  tags = {
    Name        = "${var.environment}-scribe-postgres"
    Environment = var.environment
    Project     = "scribe"
  }
}

# IAM Role for RDS Enhanced Monitoring (conditional)
resource "aws_iam_role" "rds_enhanced_monitoring" {
  count = var.monitoring_interval > 0 ? 1 : 0
  name  = "${var.environment}-scribe-rds-enhanced-monitoring"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "${var.environment}-scribe-rds-enhanced-monitoring"
    Environment = var.environment
    Project     = "scribe"
  }
}

# IAM Role Policy Attachment for RDS Enhanced Monitoring
resource "aws_iam_role_policy_attachment" "rds_enhanced_monitoring" {
  count      = var.monitoring_interval > 0 ? 1 : 0
  role       = aws_iam_role.rds_enhanced_monitoring[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# ElastiCache Subnet Group
resource "aws_elasticache_subnet_group" "scribe_cache_subnet_group" {
  name       = "${var.environment}-scribe-cache-subnet-group"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name        = "${var.environment}-scribe-cache-subnet-group"
    Environment = var.environment
    Project     = "scribe"
  }
}

# ElastiCache Redis Replication Group
resource "aws_elasticache_replication_group" "scribe_redis" {
  replication_group_id       = "${var.environment}-scribe-redis"
  description                = "Redis cluster for Scribe ${var.environment} environment"
  
  port                       = 6379
  parameter_group_name       = "default.redis7"
  node_type                  = var.redis_node_type
  num_cache_clusters         = var.redis_num_cache_nodes
  
  engine_version             = var.redis_version
  
  subnet_group_name          = aws_elasticache_subnet_group.scribe_cache_subnet_group.name
  security_group_ids         = [var.elasticache_security_group_id]
  
  # Encryption
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = random_password.redis_auth_token.result
  
  # Backup
  snapshot_retention_limit   = var.redis_snapshot_retention_limit
  snapshot_window           = var.redis_snapshot_window
  
  # Maintenance
  maintenance_window        = var.redis_maintenance_window
  
  # Auto failover (requires num_cache_clusters >= 2)
  automatic_failover_enabled = var.redis_num_cache_nodes >= 2
  multi_az_enabled          = var.redis_num_cache_nodes >= 2
  
  tags = {
    Name        = "${var.environment}-scribe-redis"
    Environment = var.environment
    Project     = "scribe"
  }
}

# Random auth token for Redis
resource "random_password" "redis_auth_token" {
  length  = 32
  special = false # Redis auth tokens can't contain special characters
}