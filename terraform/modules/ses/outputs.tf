# Outputs for SES module

output "domain_identity_arn" {
  description = "ARN of the SES domain identity"
  value       = aws_ses_domain_identity.main.arn
}

output "domain_identity_verification_token" {
  description = "Verification token for the domain identity"
  value       = aws_ses_domain_identity.main.verification_token
}

output "domain_dkim_tokens" {
  description = "DKIM tokens for domain verification"
  value       = aws_ses_domain_dkim.main.dkim_tokens
}

output "email_identity_arn" {
  description = "ARN of the email identity"
  value       = aws_ses_email_identity.noreply.arn
}

output "from_email" {
  description = "From email address for the application"
  value       = aws_ses_email_identity.noreply.email
}

output "configuration_set_name" {
  description = "Name of the SES configuration set"
  value       = aws_ses_configuration_set.main.name
}