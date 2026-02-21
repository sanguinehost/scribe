# ECS module configuration for staging
include "root" {
  path = find_in_parent_folders("root.hcl")
}

terraform {
  source = "../../../../terraform/modules/ecs"
}

locals {
  env_vars = read_terragrunt_config(find_in_parent_folders("env.hcl"))
}

dependency "networking" {
  config_path = "../networking"

  mock_outputs = {
    vpc_id             = "vpc-12345"
    private_subnet_ids = ["subnet-12345", "subnet-67890"]
    backend_security_group_id  = "sg-backend"
    frontend_security_group_id = "sg-frontend"
    qdrant_security_group_id   = "sg-qdrant"
  }
}

dependency "rds" {
  config_path = "../rds"

  mock_outputs = {
    database_url = "postgresql://..."
  }
}

dependency "secrets" {
  config_path = "../secrets"

  mock_outputs = {
    backend_secrets_list = []
    app_secrets_arn      = "arn:aws:secretsmanager:ap-southeast-4:123456789012:secret:mock-secret"
  }
}

# Dependency on ALB is now OPTIONAL.
# We don't include it here because we are moving to Traefik.
# Traefik will depend on ECS, not the other way around.

inputs = {
  environment               = local.env_vars.locals.environment
  aws_region                = local.env_vars.locals.aws_region
  vpc_id                    = dependency.networking.outputs.vpc_id
  private_subnet_ids        = dependency.networking.outputs.private_subnet_ids

  backend_security_group_id = dependency.networking.outputs.backend_security_group_id
  qdrant_security_group_id  = dependency.networking.outputs.qdrant_security_group_id
  frontend_security_group_id = dependency.networking.outputs.frontend_security_group_id

  database_url              = dependency.rds.outputs.database_url
  backend_secrets           = concat(dependency.secrets.outputs.backend_secrets_list, [
    {
      name      = "OTEL_EXPORTER_OTLP_HEADERS"
      valueFrom = "${dependency.secrets.outputs.app_secrets_arn}:openobserve_auth_token::"
    }
  ])

  # Domain configuration
  domain_name               = "staging.scribe.sanguinehost.com"
  api_domain_name           = "api.staging.scribe.sanguinehost.com"
  from_email                = "operations@sanguinehost.com"
  enable_execute_command    = true

  # Traefik labels for service discovery
  docker_labels = {
    "traefik.enable" = "true"
    "traefik.http.routers.api-router.rule" = "Host(`api.staging.scribe.sanguinehost.com`)"
    "traefik.http.routers.api-router.entrypoints" = "websecure"
    "traefik.http.routers.api-router.tls" = "true"
    "traefik.http.services.backend.loadbalancer.server.port" = "8080"
    "traefik.http.services.backend.loadbalancer.server.scheme" = "https"
  }

  # No ALB integration
  backend_target_group_arn = null
  alb_listener_arn        = null

  # Frontend configuration
  frontend_cpu           = 256
  frontend_memory        = 512
  frontend_desired_count = 1
  frontend_docker_labels = {
    "traefik.enable" = "true"
    "traefik.http.routers.frontend-router.rule" = "Host(`staging.scribe.sanguinehost.com`)"
    "traefik.http.routers.frontend-router.entrypoints" = "websecure"
    "traefik.http.routers.frontend-router.tls" = "true"
    "traefik.http.services.frontend.loadbalancer.server.port" = "3000"
  }

  frontend_env_vars = [
    {
      name  = "PUBLIC_API_URL"
      value = "https://api.staging.scribe.sanguinehost.com"
    },
    {
      name  = "NODE_ENV"
      value = "production"
    }
  ]

  # Extra environment variables for backend
  backend_env_vars = [
    {
      name  = "OTEL_EXPORTER_OTLP_ENDPOINT"
      value = "http://openobserve.staging.local:4317"
    },

    {
      name  = "OTEL_SERVICE_NAME"
      value = "scribe_backend"
    },
    {
      name  = "TOKENIZER_MODEL_PATH"
      value = "/app/backend/resources/tokenizers/tokenizer.json"
    },
    {
      name  = "PAYMENT_SUBSCRIPTION_CONFIG_PATH"
      value = "/app/backend/config/subscription_tiers.json"
    },
    {
      name  = "RUST_LOG"
      value = "info"
    },
  ]
}
