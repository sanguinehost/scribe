output "key_arn" {
  description = "ARN of the KMS key"
  value       = aws_kms_key.state_key.arn
}

output "key_id" {
  description = "ID of the KMS key"
  value       = aws_kms_key.state_key.key_id
}

output "alias_arn" {
  description = "ARN of the KMS alias"
  value       = aws_kms_alias.state_key_alias.arn
}
