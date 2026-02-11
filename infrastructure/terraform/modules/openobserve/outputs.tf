output "openobserve_endpoint" {
  description = "Internal endpoint for OpenObserve"
  value       = "http://openobserve.${var.environment}.local:5080"
}

output "openobserve_service_arn" {
  description = "ARN of the OpenObserve ECS service"
  value       = aws_ecs_service.openobserve.id
}
