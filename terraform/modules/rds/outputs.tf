output "rds_instance_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.scribe_postgres.endpoint
}

output "rds_instance_port" {
  description = "RDS instance port"
  value       = aws_db_instance.scribe_postgres.port
}

output "rds_instance_identifier" {
  description = "RDS instance identifier"
  value       = aws_db_instance.scribe_postgres.identifier
}

output "database_name" {
  description = "Database name"
  value       = aws_db_instance.scribe_postgres.db_name
}

output "master_username" {
  description = "Master username"
  value       = aws_db_instance.scribe_postgres.username
  sensitive   = true
}

output "master_password" {
  description = "Master password"
  value       = random_password.db_master_password.result
  sensitive   = true
}

output "database_url" {
  description = "Full database URL"
  value       = "postgresql://${aws_db_instance.scribe_postgres.username}:${random_password.db_master_password.result}@${aws_db_instance.scribe_postgres.endpoint}/${aws_db_instance.scribe_postgres.db_name}"
  sensitive   = true
}

output "redis_endpoint" {
  description = "Redis primary endpoint"
  value       = aws_elasticache_replication_group.scribe_redis.primary_endpoint_address
}

output "redis_port" {
  description = "Redis port"
  value       = aws_elasticache_replication_group.scribe_redis.port
}

output "redis_auth_token" {
  description = "Redis auth token"
  value       = random_password.redis_auth_token.result
  sensitive   = true
}

output "redis_url" {
  description = "Redis connection URL"
  value       = "redis://:${random_password.redis_auth_token.result}@${aws_elasticache_replication_group.scribe_redis.primary_endpoint_address}:${aws_elasticache_replication_group.scribe_redis.port}"
  sensitive   = true
}