# ECS module for Scribe application
# Creates ECS cluster, task definitions, and services for backend and Qdrant

# ECR Repository for backend
resource "aws_ecr_repository" "backend_repo" {
  name                 = "${var.environment}-scribe-backend"
  image_tag_mutability = "MUTABLE"

  # Force delete on destroy - ensures complete ephemeral infrastructure
  force_delete = true

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name        = "${var.environment}-scribe-backend-repo"
    Environment = var.environment
    Project     = "scribe"
  }
}

# ECR Repository for Qdrant (using official Qdrant image)
resource "aws_ecr_repository" "qdrant_repo" {
  name                 = "${var.environment}-scribe-qdrant"
  image_tag_mutability = "MUTABLE"

  # Force delete on destroy - ensures complete ephemeral infrastructure
  force_delete = true

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name        = "${var.environment}-scribe-qdrant-repo"
    Environment = var.environment
    Project     = "scribe"
  }
}

# ECS Cluster
resource "aws_ecs_cluster" "scribe_cluster" {
  name = "${var.environment}-scribe-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name        = "${var.environment}-scribe-cluster"
    Environment = var.environment
    Project     = "scribe"
  }
}

# CloudWatch Log Group for backend
resource "aws_cloudwatch_log_group" "backend_logs" {
  name              = "/ecs/${var.environment}-scribe-backend"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${var.environment}-scribe-backend-logs"
    Environment = var.environment
    Project     = "scribe"
  }
}

# CloudWatch Log Group for Qdrant
resource "aws_cloudwatch_log_group" "qdrant_logs" {
  name              = "/ecs/${var.environment}-scribe-qdrant"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${var.environment}-scribe-qdrant-logs"
    Environment = var.environment
    Project     = "scribe"
  }
}

# IAM Role for ECS Task Execution
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "${var.environment}-scribe-ecs-task-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "${var.environment}-scribe-ecs-task-execution-role"
    Environment = var.environment
    Project     = "scribe"
  }
}

# IAM Role Policy Attachment for ECS Task Execution
resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Additional IAM policy for accessing Secrets Manager
resource "aws_iam_role_policy" "ecs_secrets_policy" {
  name = "${var.environment}-scribe-ecs-secrets-policy"
  role = aws_iam_role.ecs_task_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = "*"
      }
    ]
  })
}

# IAM Role for ECS Tasks (runtime permissions)
resource "aws_iam_role" "ecs_task_role" {
  name = "${var.environment}-scribe-ecs-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "${var.environment}-scribe-ecs-task-role"
    Environment = var.environment
    Project     = "scribe"
  }
}

# EFS File System for Qdrant data persistence
resource "aws_efs_file_system" "qdrant_efs" {
  creation_token = "${var.environment}-scribe-qdrant-efs"
  encrypted      = true

  # Performance mode: generalPurpose is sufficient for most workloads
  performance_mode = "generalPurpose"
  throughput_mode  = "provisioned"
  provisioned_throughput_in_mibps = var.efs_provisioned_throughput

  tags = {
    Name        = "${var.environment}-scribe-qdrant-efs"
    Environment = var.environment
    Project     = "scribe"
  }
}

# EFS Mount Targets for each private subnet
resource "aws_efs_mount_target" "qdrant_efs_mount" {
  count = length(var.private_subnet_ids)

  file_system_id  = aws_efs_file_system.qdrant_efs.id
  subnet_id       = var.private_subnet_ids[count.index]
  security_groups = [var.efs_security_group_id]
}

# Backend ECS Task Definition
resource "aws_ecs_task_definition" "backend_task" {
  family                   = "${var.environment}-scribe-backend"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.backend_cpu
  memory                   = var.backend_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn           = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name  = "backend"
      image = "${aws_ecr_repository.backend_repo.repository_url}:latest"
      
      portMappings = [
        {
          containerPort = 8080
          protocol      = "tcp"
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.backend_logs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }

      environment = [
        {
          name  = "ENVIRONMENT"
          value = var.environment
        },
        {
          name  = "QDRANT_URL"
          value = "http://qdrant.${var.environment}.local:6334"
        },
        {
          name  = "FROM_EMAIL"
          value = var.from_email
        },
        {
          name  = "FRONTEND_BASE_URL"
          value = "https://${var.domain_name}"
        },
        {
          name  = "API_BASE_URL"
          value = "https://${var.api_domain_name}"
        },
        {
          name  = "COOKIE_DOMAIN"
          value = ".${var.domain_name}"
        }
      ]

      secrets = var.backend_secrets

      essential = true
    }
  ])

  tags = {
    Name        = "${var.environment}-scribe-backend-task"
    Environment = var.environment
    Project     = "scribe"
  }
}

# Qdrant ECS Task Definition
resource "aws_ecs_task_definition" "qdrant_task" {
  family                   = "${var.environment}-scribe-qdrant"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.qdrant_cpu
  memory                   = var.qdrant_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn           = aws_iam_role.ecs_task_role.arn

  volume {
    name = "qdrant-data"
    efs_volume_configuration {
      file_system_id = aws_efs_file_system.qdrant_efs.id
      root_directory = "/"
    }
  }

  container_definitions = jsonencode([
    {
      name  = "qdrant"
      image = "qdrant/qdrant:latest"
      
      portMappings = [
        {
          containerPort = 6333
          protocol      = "tcp"
        }
      ]

      mountPoints = [
        {
          sourceVolume  = "qdrant-data"
          containerPath = "/qdrant/storage"
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.qdrant_logs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }

      essential = true
    }
  ])

  tags = {
    Name        = "${var.environment}-scribe-qdrant-task"
    Environment = var.environment
    Project     = "scribe"
  }
}

# Backend ECS Service
resource "aws_ecs_service" "backend_service" {
  name            = "${var.environment}-scribe-backend"
  cluster         = aws_ecs_cluster.scribe_cluster.id
  task_definition = aws_ecs_task_definition.backend_task.arn
  desired_count   = var.backend_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.backend_security_group_id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = var.backend_target_group_arn
    container_name   = "backend"
    container_port   = 8080
  }

  depends_on = [var.alb_listener_arn]

  tags = {
    Name        = "${var.environment}-scribe-backend-service"
    Environment = var.environment
    Project     = "scribe"
  }
}

# Qdrant ECS Service
resource "aws_ecs_service" "qdrant_service" {
  name            = "${var.environment}-scribe-qdrant"
  cluster         = aws_ecs_cluster.scribe_cluster.id
  task_definition = aws_ecs_task_definition.qdrant_task.arn
  desired_count   = var.qdrant_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.qdrant_security_group_id]
    assign_public_ip = false
  }

  # Service discovery for internal communication
  service_registries {
    registry_arn = aws_service_discovery_service.qdrant.arn
  }

  depends_on = [aws_efs_mount_target.qdrant_efs_mount]

  tags = {
    Name        = "${var.environment}-scribe-qdrant-service"
    Environment = var.environment
    Project     = "scribe"
  }
}

# Service Discovery for Qdrant
resource "aws_service_discovery_private_dns_namespace" "scribe" {
  name        = "${var.environment}.local"
  description = "Service discovery namespace for Scribe services"
  vpc         = var.vpc_id

  tags = {
    Name        = "${var.environment}-scribe-service-discovery"
    Environment = var.environment
    Project     = "scribe"
  }
}

resource "aws_service_discovery_service" "qdrant" {
  name = "qdrant"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.scribe.id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  tags = {
    Name        = "${var.environment}-scribe-qdrant-discovery"
    Environment = var.environment
    Project     = "scribe"
  }
}