output "alb_arn" {
  description = "ARN of the Application Load Balancer"
  value       = aws_lb.scribe_alb.arn
}

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.scribe_alb.dns_name
}

output "alb_zone_id" {
  description = "Zone ID of the Application Load Balancer"
  value       = aws_lb.scribe_alb.zone_id
}

output "backend_target_group_arn" {
  description = "ARN of the backend target group"
  value       = aws_lb_target_group.backend_tg_https.arn
}

output "target_group_arn" {
  description = "Legacy ARN of the backend target group for compatibility"
  value       = aws_lb_target_group.backend_tg_https.arn
}

output "https_listener_arn" {
  description = "ARN of the HTTPS listener"
  value       = aws_lb_listener.scribe_https.arn
}

output "http_listener_arn" {
  description = "ARN of the HTTP listener"
  value       = aws_lb_listener.scribe_http.arn
}

output "ssl_certificate_arn" {
  description = "ARN of the SSL certificate"
  value       = aws_acm_certificate.scribe_cert.arn
}

output "waf_web_acl_arn" {
  description = "ARN of the WAF Web ACL"
  value       = aws_wafv2_web_acl.scribe_waf.arn
}

output "ssl_certificate_validation_options" {
  description = "SSL certificate validation options for DNS validation"
  value       = aws_acm_certificate.scribe_cert.domain_validation_options
}

output "api_dns_record_fqdn" {
  description = "FQDN of the API endpoint DNS record"
  value       = aws_route53_record.api_endpoint.fqdn
}