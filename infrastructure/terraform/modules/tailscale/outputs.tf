output "tailscale_instance_id" {
  description = "Tailscale router instance ID"
  value       = aws_instance.tailscale_router.id
}

output "tailscale_public_ip" {
  description = "Tailscale router public IP"
  value       = aws_instance.tailscale_router.public_ip
}

output "tailscale_private_ip" {
  description = "Tailscale router private IP"
  value       = aws_instance.tailscale_router.private_ip
}
