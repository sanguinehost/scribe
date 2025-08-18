# Monitoring module for Scribe application
# Creates CloudWatch dashboards, alarms, and log groups

# CloudWatch Dashboard
resource "aws_cloudwatch_dashboard" "scribe_dashboard" {
  dashboard_name = "${var.environment}-scribe-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", var.alb_arn_suffix],
            [".", "TargetResponseTime", ".", "."],
            [".", "HTTPCode_Target_2XX_Count", ".", "."],
            [".", "HTTPCode_Target_4XX_Count", ".", "."],
            [".", "HTTPCode_Target_5XX_Count", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "ALB Metrics"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/ECS", "CPUUtilization", "ServiceName", var.backend_service_name, "ClusterName", var.ecs_cluster_name],
            [".", "MemoryUtilization", ".", ".", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "ECS Backend Metrics"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", var.rds_instance_identifier],
            [".", "DatabaseConnections", ".", "."],
            [".", "FreeableMemory", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "RDS Metrics"
          period  = 300
        }
      },
    ]
  })

}

# CloudWatch Alarms
# ALB High Response Time
resource "aws_cloudwatch_metric_alarm" "alb_high_response_time" {
  alarm_name          = "${var.environment}-scribe-alb-high-response-time"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = "120"
  statistic           = "Average"
  threshold           = "2.0"
  alarm_description   = "This metric monitors ALB response time"
  alarm_actions       = var.sns_topic_arn != "" ? [var.sns_topic_arn] : []

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
  }

  tags = {
    Name        = "${var.environment}-scribe-alb-high-response-time"
    Environment = var.environment
    Project     = "scribe"
  }
}

# ALB High 5XX Errors
resource "aws_cloudwatch_metric_alarm" "alb_high_5xx_errors" {
  alarm_name          = "${var.environment}-scribe-alb-high-5xx-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = "120"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "This metric monitors ALB 5XX errors"
  alarm_actions       = var.sns_topic_arn != "" ? [var.sns_topic_arn] : []

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
  }

  tags = {
    Name        = "${var.environment}-scribe-alb-high-5xx-errors"
    Environment = var.environment
    Project     = "scribe"
  }
}

# ECS High CPU Utilization
resource "aws_cloudwatch_metric_alarm" "ecs_high_cpu" {
  alarm_name          = "${var.environment}-scribe-ecs-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = "120"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors ECS CPU utilization"
  alarm_actions       = var.sns_topic_arn != "" ? [var.sns_topic_arn] : []

  dimensions = {
    ServiceName = var.backend_service_name
    ClusterName = var.ecs_cluster_name
  }

  tags = {
    Name        = "${var.environment}-scribe-ecs-high-cpu"
    Environment = var.environment
    Project     = "scribe"
  }
}

# ECS High Memory Utilization
resource "aws_cloudwatch_metric_alarm" "ecs_high_memory" {
  alarm_name          = "${var.environment}-scribe-ecs-high-memory"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = "120"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors ECS memory utilization"
  alarm_actions       = var.sns_topic_arn != "" ? [var.sns_topic_arn] : []

  dimensions = {
    ServiceName = var.backend_service_name
    ClusterName = var.ecs_cluster_name
  }

  tags = {
    Name        = "${var.environment}-scribe-ecs-high-memory"
    Environment = var.environment
    Project     = "scribe"
  }
}

# RDS High CPU Utilization
resource "aws_cloudwatch_metric_alarm" "rds_high_cpu" {
  alarm_name          = "${var.environment}-scribe-rds-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = "120"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors RDS CPU utilization"
  alarm_actions       = var.sns_topic_arn != "" ? [var.sns_topic_arn] : []

  dimensions = {
    DBInstanceIdentifier = var.rds_instance_identifier
  }

  tags = {
    Name        = "${var.environment}-scribe-rds-high-cpu"
    Environment = var.environment
    Project     = "scribe"
  }
}

# RDS Low Free Memory
resource "aws_cloudwatch_metric_alarm" "rds_low_memory" {
  alarm_name          = "${var.environment}-scribe-rds-low-memory"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "FreeableMemory"
  namespace           = "AWS/RDS"
  period              = "120"
  statistic           = "Average"
  threshold           = "100000000"  # 100MB in bytes
  alarm_description   = "This metric monitors RDS free memory"
  alarm_actions       = var.sns_topic_arn != "" ? [var.sns_topic_arn] : []

  dimensions = {
    DBInstanceIdentifier = var.rds_instance_identifier
  }

  tags = {
    Name        = "${var.environment}-scribe-rds-low-memory"
    Environment = var.environment
    Project     = "scribe"
  }
}

# SNS Topic for notifications (optional)
resource "aws_sns_topic" "scribe_alerts" {
  count = var.create_sns_topic ? 1 : 0
  name  = "${var.environment}-scribe-alerts"

  tags = {
    Name        = "${var.environment}-scribe-alerts"
    Environment = var.environment
    Project     = "scribe"
  }
}

# CloudTrail for API auditing
resource "aws_cloudtrail" "scribe_trail" {
  count                         = var.enable_cloudtrail ? 1 : 0
  name                          = "${var.environment}-scribe-trail"
  s3_bucket_name               = var.cloudtrail_bucket_name
  include_global_service_events = true
  is_multi_region_trail        = true
  enable_logging               = true

  event_selector {
    read_write_type                 = "All"
    include_management_events       = true
    exclude_management_event_sources = []

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${var.cloudtrail_bucket_name}/*"]
    }
  }

  tags = {
    Name        = "${var.environment}-scribe-trail"
    Environment = var.environment
    Project     = "scribe"
  }
}