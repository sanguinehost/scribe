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