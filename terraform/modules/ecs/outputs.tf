output "ecs_cluster_id" {
  description = "ID of the ECS cluster"
  value       = aws_ecs_cluster.scribe_cluster.id
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = aws_ecs_cluster.scribe_cluster.name
}

output "backend_ecr_repository_url" {
  description = "URL of the backend ECR repository"
  value       = aws_ecr_repository.backend_repo.repository_url
}

output "qdrant_ecr_repository_url" {
  description = "URL of the Qdrant ECR repository"
  value       = aws_ecr_repository.qdrant_repo.repository_url
}

output "backend_service_name" {
  description = "Name of the backend ECS service"
  value       = aws_ecs_service.backend_service.name
}

output "qdrant_service_name" {
  description = "Name of the Qdrant ECS service"
  value       = aws_ecs_service.qdrant_service.name
}

output "efs_file_system_id" {
  description = "ID of the EFS file system for Qdrant"
  value       = aws_efs_file_system.qdrant_efs.id
}

output "service_discovery_namespace_id" {
  description = "ID of the service discovery namespace"
  value       = aws_service_discovery_private_dns_namespace.scribe.id
}

output "qdrant_service_discovery_arn" {
  description = "ARN of the Qdrant service discovery service"
  value       = aws_service_discovery_service.qdrant.arn
}

output "ecs_task_role_name" {
  description = "Name of the ECS task role"
  value       = aws_iam_role.ecs_task_role.name
}