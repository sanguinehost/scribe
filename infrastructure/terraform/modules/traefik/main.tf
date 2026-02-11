# Traefik Ingress Module
# Deploys Traefik as an ECS Service behind an NLB with ACM SSL termination

# --- IAM Roles ---

resource "aws_iam_role" "traefik_task_execution_role" {
  name = "${var.environment}-scribe-traefik-task-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "traefik_task_execution_policy" {
  role       = aws_iam_role.traefik_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "traefik_execution_logs_policy" {
  name = "${var.environment}-scribe-traefik-execution-logs"
  role = aws_iam_role.traefik_task_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "traefik_task_role" {
  name = "${var.environment}-scribe-traefik-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
}

# Values for Traefik ECS Provider
resource "aws_iam_role_policy" "traefik_ecs_policy" {
  name = "${var.environment}-scribe-traefik-ecs-policy"
  role = aws_iam_role.traefik_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecs:ListClusters",
          "ecs:DescribeClusters",
          "ecs:ListTasks",
          "ecs:DescribeTasks",
          "ecs:DescribeContainerInstances",
          "ecs:DescribeTaskDefinition",
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeNetworkInterfaces"
        ]
        # Traefik needs broad read access to discover services
        Resource = "*"
      }
    ]
  })
}

# --- Security Groups ---

resource "aws_security_group" "traefik_sg" {
  name        = "${var.environment}-scribe-traefik-sg"
  description = "Security group for Traefik Ingress"
  vpc_id      = var.vpc_id

  # Inbound from NLB (Health checks & Traffic) works via VPC CIDR or specific rules.
  # Since NLB preserves client IP, we might want to open HTTP/HTTPS to world
  # IF the target type is instance. But for Fargate 'awsvpc', the target type is IP.
  # For NLB -> Fargate, the security group is on the Task ENI.
  # We should allow traffic from the NLB (which has no SG) -> Client IP preservation.
  # So we must allow 0.0.0.0/0 on the container ports.

  ingress {
    description = "Allow HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  ingress {
    description = "Allow HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  ingress {
    description = "Allow Traefik Dashboard (Internal)"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"] # Restrict to VPC (e.g. Tailscale)
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- Network Load Balancer (Layer 4) ---

resource "aws_lb" "traefik_nlb" {
  name               = "${var.environment}-scribe-nlb"
  internal           = true # Reverted to internal for secure VPN-only access
  load_balancer_type = "network"
  subnets            = var.private_subnet_ids # Use private subnets for internal LB
  enable_deletion_protection = false
}

resource "aws_lb_target_group" "traefik_http" {
  name        = "${var.environment}-scribe-traefik-http"
  port        = 80
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    enabled  = true
    protocol = "TCP"
  }
}

resource "aws_route53_record" "additional_records" {
  for_each = toset(var.additional_domains)

  zone_id = var.route53_zone_id
  name    = each.value
  type    = "A"

  alias {
    name                   = aws_lb.traefik_nlb.dns_name
    zone_id                = aws_lb.traefik_nlb.zone_id
    evaluate_target_health = true
  }
}


# SSL Certificate for NLB (TLS Termination)
# Note: For NLB, we terminate TLS at the NLB using a TLS listener
# OR we pass through (TCP) and let Traefik handle it.
# DECISION: We decided "Platform-Managed TLS (ACM)".
# So NLB will have a TLS listener.

resource "aws_acm_certificate" "cert" {
  domain_name               = var.domain_name
  subject_alternative_names = var.subject_alternative_names
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.cert.domain_validation_options : dvo.domain_name => {
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

resource "aws_acm_certificate_validation" "cert" {
  certificate_arn         = aws_acm_certificate.cert.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

resource "aws_lb_listener" "nlb_http" {
  load_balancer_arn = aws_lb.traefik_nlb.arn
  port              = "80"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.traefik_http.arn
  }
}

resource "aws_lb_listener" "nlb_https" {
  load_balancer_arn = aws_lb.traefik_nlb.arn
  port              = "443"
  protocol          = "TLS"
  certificate_arn   = aws_acm_certificate_validation.cert.certificate_arn
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.traefik_https.arn
  }
}

resource "aws_lb_target_group" "traefik_https" {
  name        = "${var.environment}-scribe-traefik-https"
  port        = 443
  protocol    = "TLS"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    enabled  = true
    protocol = "TCP"
  }
}

resource "aws_cloudwatch_log_group" "traefik" {
  name              = "/ecs/${var.environment}-scribe-traefik"
  retention_in_days = 7
}

# --- ECS Service (Traefik) ---

resource "aws_ecs_task_definition" "traefik" {
  family                   = "${var.environment}-scribe-traefik"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.traefik_cpu
  memory                   = var.traefik_memory
  execution_role_arn       = aws_iam_role.traefik_task_execution_role.arn
  task_role_arn           = aws_iam_role.traefik_task_role.arn

  container_definitions = jsonencode([
    {
      name      = "traefik"
      image     = "traefik:v3.0"
      essential = true

      command = [
        "--api.dashboard=true",
        "--api.insecure=true", # Internal only
        "--providers.ecs=true",
        "--providers.ecs.region=${var.aws_region}",
        "--providers.ecs.clusters=staging-scribe-cluster",
        "--providers.ecs.exposedByDefault=false",
        "--entrypoints.web.address=:80",
        "--entrypoints.websecure.address=:443",
        "--entrypoints.websecure.http.tls=true",
        # Logging
        "--log.level=DEBUG",
        "--accesslog=true",
        "--serverstransport.insecureskipverify=true"
      ]

      portMappings = [
        {
          containerPort = 80
          protocol      = "tcp"
        },
        {
          containerPort = 443
          protocol      = "tcp"
        },
        {
          containerPort = 8080
          protocol      = "tcp"
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.traefik.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "traefik" {
  name            = "${var.environment}-scribe-traefik"
  cluster         = var.ecs_cluster_id
  task_definition = aws_ecs_task_definition.traefik.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.traefik_sg.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.traefik_http.arn
    container_name   = "traefik"
    container_port   = 80
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.traefik_https.arn
    container_name   = "traefik"
    container_port   = 443
  }

  depends_on = [
    aws_lb_listener.nlb_http,
    aws_lb_listener.nlb_https
  ]
}

# --- DNS ---

resource "aws_route53_record" "ingress" {
  zone_id = var.route53_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_lb.traefik_nlb.dns_name
    zone_id                = aws_lb.traefik_nlb.zone_id
    evaluate_target_health = true
  }
}
