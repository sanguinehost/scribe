output "nlb_dns_name" {
  description = "DNS name of the NLB"
  value       = aws_lb.traefik_nlb.dns_name
}

output "nlb_zone_id" {
  description = "Zone ID of the NLB"
  value       = aws_lb.traefik_nlb.zone_id
}

output "traefik_service_name" {
  description = "Name of the Traefik ECS service"
  value       = aws_ecs_service.traefik.name
}

output "traefik_security_group_id" {
  description = "ID of the Traefik security group"
  value       = aws_security_group.traefik_sg.id
}
