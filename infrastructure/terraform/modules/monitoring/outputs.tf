output "dashboard_url" {
  description = "URL of the CloudWatch dashboard"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.scribe_dashboard.dashboard_name}"
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for alerts (if created)"
  value       = var.create_sns_topic ? aws_sns_topic.scribe_alerts[0].arn : ""
}

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail (if created)"
  value       = var.enable_cloudtrail ? aws_cloudtrail.scribe_trail[0].arn : ""
}

# Security Monitoring Outputs (Task 10)

output "security_alerts_p0_topic_arn" {
  description = "ARN of the P0 (Critical) security alerts SNS topic"
  value       = aws_sns_topic.security_alerts_p0.arn
}

output "security_alerts_p1_topic_arn" {
  description = "ARN of the P1 (High) security alerts SNS topic"
  value       = aws_sns_topic.security_alerts_p1.arn
}

output "security_alerts_p2_topic_arn" {
  description = "ARN of the P2 (Medium) security alerts SNS topic"
  value       = aws_sns_topic.security_alerts_p2.arn
}

output "security_alerts_p3_topic_arn" {
  description = "ARN of the P3 (Low) security alerts SNS topic"
  value       = aws_sns_topic.security_alerts_p3.arn
}

output "kinesis_firehose_stream_name" {
  description = "Name of the Kinesis Firehose delivery stream for SIEM integration"
  value       = var.enable_kinesis_firehose ? aws_kinesis_firehose_delivery_stream.security_logs[0].name : ""
}

output "kinesis_firehose_stream_arn" {
  description = "ARN of the Kinesis Firehose delivery stream for SIEM integration"
  value       = var.enable_kinesis_firehose ? aws_kinesis_firehose_delivery_stream.security_logs[0].arn : ""
}

output "siem_bucket_name" {
  description = "Name of the S3 bucket for SIEM log archival"
  value       = var.enable_kinesis_firehose ? aws_s3_bucket.siem_logs[0].id : ""
}

output "siem_bucket_arn" {
  description = "ARN of the S3 bucket for SIEM log archival"
  value       = var.enable_kinesis_firehose ? aws_s3_bucket.siem_logs[0].arn : ""
}
