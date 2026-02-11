# OpenObserve Module (Observability)

resource "aws_s3_bucket" "openobserve_data" {
  bucket = "${var.environment}-scribe-openobserve-data"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "openobserve_data" {
  bucket = aws_s3_bucket.openobserve_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_iam_policy" "openobserve_s3_policy" {
  name = "${var.environment}-scribe-openobserve-s3-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:DeleteObject"
        ]
        Resource = [
          aws_s3_bucket.openobserve_data.arn,
          "${aws_s3_bucket.openobserve_data.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "openobserve_s3_attachment" {
  role       = aws_iam_role.openobserve_task_role.name
  policy_arn = aws_iam_policy.openobserve_s3_policy.arn
}

# IAM Role for ECS Infrastructure (EBS Management)
resource "aws_iam_role" "ecs_infrastructure_role" {
  name = "${var.environment}-scribe-openobserve-infra-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_infrastructure_policy" {
  role       = aws_iam_role.ecs_infrastructure_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSInfrastructureRolePolicyForVolumes"
}

# Security Group for OpenObserve
resource "aws_security_group" "openobserve_sg" {
  name        = "${var.environment}-scribe-openobserve-sg"
  description = "Security group for OpenObserve"
  vpc_id      = var.vpc_id

  # Inbound from Traefik
  ingress {
    from_port       = 5080
    to_port         = 5080
    protocol        = "tcp"
    security_groups = [var.traefik_security_group_id]
  }

  # Inbound from dentro VPC (for backend/qdrant telemetry gRPC)
  ingress {
    from_port   = 4317
    to_port     = 4317
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # Inbound from specific backend security group for gRPC
  ingress {
    from_port       = 4317
    to_port         = 4317
    protocol        = "tcp"
    security_groups = var.backend_security_group_id != "" ? [var.backend_security_group_id] : []
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.environment}-scribe-openobserve-sg"
    Environment = var.environment
    Project     = "scribe"
  }
}

# IAM Roles (Reuse or create specific)
resource "aws_iam_role" "openobserve_task_execution_role" {
  name = "${var.environment}-scribe-openobserve-task-execution-role"

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

resource "aws_iam_role_policy_attachment" "openobserve_task_execution_policy" {
  role       = aws_iam_role.openobserve_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "openobserve_task_role" {
  name = "${var.environment}-scribe-openobserve-task-role"

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

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "openobserve_logs" {
  name              = "/ecs/${var.environment}-scribe-openobserve"
  retention_in_days = 7

  tags = {
    Name        = "${var.environment}-scribe-openobserve-logs"
    Environment = var.environment
    Project     = "scribe"
  }
}

# ECS Task Definition
resource "aws_ecs_task_definition" "openobserve" {
  family                   = "${var.environment}-scribe-openobserve"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.openobserve_cpu
  memory                   = var.openobserve_memory
  execution_role_arn       = aws_iam_role.openobserve_task_execution_role.arn
  task_role_arn            = aws_iam_role.openobserve_task_role.arn


  container_definitions = jsonencode([
    {
      name  = "openobserve"
      image = "openobserve/openobserve:latest"
      essential = true

      portMappings = [
        {
          containerPort = 5080
          protocol      = "tcp"
        },
        {
          containerPort = 4317
          protocol      = "tcp"
        }
      ]

      environment = [
        {
          name  = "ZO_ROOT_USER_EMAIL"
          value = var.openobserve_admin_email
        },
        {
          name  = "ZO_ROOT_USER_PASSWORD"
          value = var.openobserve_admin_password
        },
        {
          name  = "ZO_S3_BUCKET"
          value = aws_s3_bucket.openobserve_data.id
        },
        {
          name  = "ZO_S3_REGION"
          value = var.aws_region
        },
        {
          name  = "ZO_STORAGE_TYPE"
          value = "s3"
        },
        {
          name  = "ZO_GRPC_PORT"
          value = "4317"
        }
      ]

      mountPoints = []

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.openobserve_logs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }

      # Traefik Labels
      dockerLabels = {
        "traefik.enable" = "true"
        "traefik.http.routers.openobserve.rule" = "Host(`obs.${var.domain_name}`)"
        "traefik.http.routers.openobserve.entrypoints" = "websecure"
        "traefik.http.routers.openobserve.tls" = "true"
        # Restrict UI to Tailscale and VPC Internal CIDR
        "traefik.http.middlewares.tailscale-allowlist.ipallowlist.sourcerange" = "100.64.0.0/10,127.0.0.1/32,10.0.0.0/16"
        "traefik.http.routers.openobserve.middlewares" = "tailscale-allowlist"
        "traefik.http.services.openobserve.loadbalancer.server.port" = "5080"
      }
    }
  ])
}

# Service Discovery
resource "aws_service_discovery_service" "openobserve" {
  name = "openobserve"

  dns_config {
    namespace_id = var.service_discovery_namespace_id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }
}

# ECS Service
resource "aws_ecs_service" "openobserve" {
  name            = "${var.environment}-scribe-openobserve"
  cluster         = var.ecs_cluster_id
  task_definition = aws_ecs_task_definition.openobserve.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.openobserve_sg.id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.openobserve.arn
  }

  # Persistence handled via S3
}
