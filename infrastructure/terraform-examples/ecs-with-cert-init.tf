# Example Terraform Configuration for ECS with Certificate Init Container
# This file provides templates for integrating the certificate init container pattern
# with AWS ECS Fargate deployments

# ECR Repository for Certificate Init Container
resource "aws_ecr_repository" "cert_init_repo" {
  name                 = "${var.environment}-scribe-cert-init"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name        = "${var.environment}-scribe-cert-init-repo"
    Environment = var.environment
    Project     = "scribe"
  }
}

# Backend ECS Task Definition with Certificate Init Container
resource "aws_ecs_task_definition" "backend_task_with_cert_init" {
  family                   = "${var.environment}-scribe-backend"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.backend_cpu
  memory                   = var.backend_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn           = aws_iam_role.ecs_task_role.arn

  # Shared volume for certificates
  volume {
    name = "certificates"
  }

  container_definitions = jsonencode([
    {
      # Certificate Initialization Container (runs first)
      name      = "cert-init"
      image     = "${aws_ecr_repository.cert_init_repo.repository_url}:latest"
      essential = false  # Not essential - allows backend to start after this completes
      
      # Environment variables for certificate setup
      environment = [
        {
          name  = "ENVIRONMENT"
          value = var.environment
        },
        {
          name  = "CERT_DIR" 
          value = "/shared/certs"
        }
      ]

      # Secrets from AWS Secrets Manager
      secrets = [
        {
          name      = "TLS_CERT_PEM"
          valueFrom = "${var.secrets_manager_app_secret_arn}:tls_cert_pem::"
        },
        {
          name      = "TLS_KEY_PEM"
          valueFrom = "${var.secrets_manager_app_secret_arn}:tls_key_pem::"
        }
      ]

      # Mount shared certificate volume
      mountPoints = [
        {
          sourceVolume  = "certificates"
          containerPath = "/shared/certs"
          readOnly      = false
        }
      ]

      # Logging configuration
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.backend_log_group.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "cert-init"
        }
      }

      # Health check for certificate initialization
      healthCheck = {
        command = [
          "CMD-SHELL",
          "test -f /shared/certs/cert.pem && test -f /shared/certs/key.pem || exit 1"
        ]
        interval    = 10
        timeout     = 5
        startPeriod = 30
        retries     = 3
      }
    },
    {
      # Main Backend Container
      name  = "backend"
      image = "${aws_ecr_repository.backend_repo.repository_url}:latest"
      essential = true

      # Backend depends on successful certificate initialization
      dependsOn = [
        {
          containerName = "cert-init"
          condition     = "SUCCESS"
        }
      ]

      portMappings = [
        {
          containerPort = 8080
          protocol      = "tcp"
        }
      ]

      # Environment variables for backend
      environment = [
        {
          name  = "ENVIRONMENT"
          value = var.environment
        },
        {
          name  = "PORT"
          value = "8080"
        },
        {
          name  = "RUST_LOG"
          value = "info"
        },
        {
          name  = "QDRANT_URL"
          value = "https://qdrant.${var.environment}.local:6334"
        }
      ]

      # Secrets from AWS Secrets Manager
      secrets = [
        {
          name      = "DATABASE_URL"
          valueFrom = "${var.secrets_manager_db_secret_arn}:url::"
        },
        {
          name      = "GEMINI_API_KEY"
          valueFrom = "${var.secrets_manager_app_secret_arn}:gemini_api_key::"
        },
        {
          name      = "JWT_SECRET"
          valueFrom = "${var.secrets_manager_app_secret_arn}:jwt_secret::"
        },
        {
          name      = "ENCRYPTION_KEY"
          valueFrom = "${var.secrets_manager_app_secret_arn}:encryption_key::"
        },
        {
          name      = "SESSION_SECRET"
          valueFrom = "${var.secrets_manager_app_secret_arn}:session_secret::"
        },
        {
          name      = "COOKIE_SIGNING_KEY"
          valueFrom = "${var.secrets_manager_app_secret_arn}:cookie_signing_key::"
        }
      ]

      # Mount certificates as read-only
      mountPoints = [
        {
          sourceVolume  = "certificates"
          containerPath = "/app/certs"
          readOnly      = true
        }
      ]

      # Logging configuration
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.backend_log_group.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "backend"
        }
      }

      # Health check for backend service
      healthCheck = {
        command = [
          "CMD-SHELL", 
          "curl -f -k https://localhost:8080/health || exit 1"
        ]
        interval    = 30
        timeout     = 10
        startPeriod = 60
        retries     = 3
      }
    }
  ])

  tags = {
    Name        = "${var.environment}-scribe-backend-task"
    Environment = var.environment
    Project     = "scribe"
  }
}

# Alternative: Qdrant Task Definition with Certificate Init
resource "aws_ecs_task_definition" "qdrant_task_with_cert_init" {
  family                   = "${var.environment}-scribe-qdrant"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.qdrant_cpu
  memory                   = var.qdrant_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn           = aws_iam_role.ecs_task_role.arn

  # Shared volume for certificates
  volume {
    name = "certificates"
  }

  # EFS volume for Qdrant data
  volume {
    name = "qdrant_data"
    efs_volume_configuration {
      file_system_id = aws_efs_file_system.qdrant_efs.id
      root_directory = "/qdrant"
    }
  }

  container_definitions = jsonencode([
    {
      # Certificate init container for Qdrant
      name      = "cert-init"
      image     = "${aws_ecr_repository.cert_init_repo.repository_url}:latest"
      essential = false

      environment = [
        {
          name  = "ENVIRONMENT"
          value = var.environment
        }
      ]

      secrets = [
        {
          name      = "TLS_CERT_PEM"
          valueFrom = "${var.secrets_manager_app_secret_arn}:tls_cert_pem::"
        },
        {
          name      = "TLS_KEY_PEM"
          valueFrom = "${var.secrets_manager_app_secret_arn}:tls_key_pem::"
        }
      ]

      mountPoints = [
        {
          sourceVolume  = "certificates"
          containerPath = "/shared/certs"
          readOnly      = false
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.qdrant_log_group.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "cert-init"
        }
      }
    },
    {
      # Qdrant container
      name      = "qdrant"
      image     = "docker.io/qdrant/qdrant:v1.14.0"
      essential = true

      dependsOn = [
        {
          containerName = "cert-init"
          condition     = "SUCCESS"
        }
      ]

      portMappings = [
        {
          containerPort = 6333
          protocol      = "tcp"
        },
        {
          containerPort = 6334
          protocol      = "tcp"
        }
      ]

      environment = [
        {
          name  = "QDRANT__SERVICE__ENABLE_TLS"
          value = "true"
        },
        {
          name  = "QDRANT__TLS__CERT"
          value = "/shared/certs/cert.pem"
        },
        {
          name  = "QDRANT__TLS__KEY"
          value = "/shared/certs/key.pem"
        }
      ]

      mountPoints = [
        {
          sourceVolume  = "certificates"
          containerPath = "/shared/certs"
          readOnly      = true
        },
        {
          sourceVolume  = "qdrant_data"
          containerPath = "/qdrant/storage"
          readOnly      = false
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.qdrant_log_group.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "qdrant"
        }
      }
    }
  ])

  tags = {
    Name        = "${var.environment}-scribe-qdrant-task"
    Environment = var.environment
    Project     = "scribe"
  }
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "backend_log_group" {
  name              = "/ecs/${var.environment}-scribe-backend"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${var.environment}-scribe-backend-logs"
    Environment = var.environment
    Project     = "scribe"
  }
}

resource "aws_cloudwatch_log_group" "qdrant_log_group" {
  name              = "/ecs/${var.environment}-scribe-qdrant"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${var.environment}-scribe-qdrant-logs"
    Environment = var.environment
    Project     = "scribe"
  }
}

# Build and Push Script for Certificate Init Container
resource "null_resource" "build_cert_init_image" {
  triggers = {
    dockerfile_hash = filemd5("${path.module}/../../../infrastructure/containers/cert-init/Dockerfile")
    script_hash     = filemd5("${path.module}/../../../infrastructure/containers/cert-init/manage.sh")
  }

  provisioner "local-exec" {
    command = <<-EOT
      cd ${path.module}/../../../infrastructure/containers/cert-init
      
      # Build the certificate init container
      docker build -t scribe-cert-init:latest .
      
      # Tag for ECR
      docker tag scribe-cert-init:latest ${aws_ecr_repository.cert_init_repo.repository_url}:latest
      
      # Login to ECR
      aws ecr get-login-password --region ${var.aws_region} | \
        docker login --username AWS --password-stdin ${aws_ecr_repository.cert_init_repo.repository_url}
      
      # Push to ECR
      docker push ${aws_ecr_repository.cert_init_repo.repository_url}:latest
    EOT
  }

  depends_on = [aws_ecr_repository.cert_init_repo]
}

# Variables needed for this configuration
variable "secrets_manager_app_secret_arn" {
  description = "ARN of the AWS Secrets Manager secret containing application secrets"
  type        = string
}

variable "secrets_manager_db_secret_arn" {
  description = "ARN of the AWS Secrets Manager secret containing database credentials"
  type        = string
}

variable "log_retention_days" {
  description = "Number of days to retain logs in CloudWatch"
  type        = number
  default     = 7
}