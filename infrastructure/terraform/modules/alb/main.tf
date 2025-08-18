# Application Load Balancer
resource "aws_lb" "scribe_alb" {
  name               = "${var.environment}-scribe-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [var.alb_security_group_id]
  subnets            = var.public_subnet_ids

  enable_deletion_protection = false
  enable_http2              = true
  idle_timeout              = 300  # Increase timeout to 5 minutes for file uploads

  tags = {
    Name        = "${var.environment}-scribe-alb"
    Environment = var.environment
    Project     = "scribe"
  }
}

# New HTTPS Target group
resource "aws_lb_target_group" "backend_tg_https" {
  name        = "${var.environment}-scribe-be-https-tg"
  port        = 8080
  protocol    = "HTTPS"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    path                = "/api/health"
    matcher             = "200"
    port                = "traffic-port"
    protocol            = "HTTPS"
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name        = "${var.environment}-scribe-be-https-tg"
    Environment = var.environment
    Project     = "scribe"
  }
}

# SSL Certificate (ACM)
resource "aws_acm_certificate" "scribe_cert" {
  domain_name       = var.domain_name
  validation_method = "DNS"

  subject_alternative_names = var.subject_alternative_names

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name        = "${var.environment}-scribe-cert"
    Environment = var.environment
    Project     = "scribe"
  }
}

# DNS validation records for SSL certificate
resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.scribe_cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.route53_zone_id
}

# SSL Certificate validation
resource "aws_acm_certificate_validation" "scribe_cert" {
  certificate_arn         = aws_acm_certificate.scribe_cert.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]

  timeouts {
    create = "10m"
  }
}

# HTTPS Listener
resource "aws_lb_listener" "scribe_https" {
  load_balancer_arn = aws_lb.scribe_alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = aws_acm_certificate_validation.scribe_cert.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.backend_tg_https.arn
  }

  tags = {
    Name        = "${var.environment}-scribe-https-listener"
    Environment = var.environment
    Project     = "scribe"
  }
}

# HTTP Listener (redirect to HTTPS)
resource "aws_lb_listener" "scribe_http" {
  load_balancer_arn = aws_lb.scribe_alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }

  tags = {
    Name        = "${var.environment}-scribe-http-listener"
    Environment = var.environment
    Project     = "scribe"
  }
}

# WAF Web ACL
resource "aws_wafv2_web_acl" "scribe_waf" {
  name  = "${var.environment}-scribe-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # Allow large uploads for character endpoint
  rule {
    name     = "AllowLargeCharacterUploads"
    priority = 1

    action {
      allow {}
    }

    statement {
      byte_match_statement {
        search_string = "/api/characters/upload"
        field_to_match {
          uri_path {}
        }
        text_transformation {
          priority = 0
          type     = "NONE"
        }
        positional_constraint = "CONTAINS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "${var.environment}-scribe-large-upload"
      sampled_requests_enabled   = true
    }
  }

  # Rate limiting rule
  rule {
    name     = "RateLimitRule"
    priority = 2

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "${var.environment}-scribe-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name               = "${var.environment}-scribe-waf"
    sampled_requests_enabled   = true
  }

  tags = {
    Name        = "${var.environment}-scribe-waf"
    Environment = var.environment
    Project     = "scribe"
  }
}

# Associate WAF with ALB
resource "aws_wafv2_web_acl_association" "scribe_waf_association" {
  resource_arn = aws_lb.scribe_alb.arn
  web_acl_arn  = aws_wafv2_web_acl.scribe_waf.arn
}

# DNS record for API endpoint
resource "aws_route53_record" "api_endpoint" {
  zone_id = var.route53_zone_id
  name    = var.domain_name  # api.staging.scribe.sanguinehost.com
  type    = "CNAME"
  ttl     = 60
  records = [aws_lb.scribe_alb.dns_name]
}