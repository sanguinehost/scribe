# OpenObserve module configuration for staging
include "root" {
  path = find_in_parent_folders("root.hcl")
}

terraform {
  source = "../../../../terraform/modules/openobserve"
}

locals {
  env_vars = read_terragrunt_config(find_in_parent_folders("env.hcl"))
}

dependency "networking" {
  config_path = "../networking"

  mock_outputs = {
    vpc_id                    = "vpc-12345"
    private_subnet_ids        = ["subnet-12345", "subnet-67890"]
    backend_security_group_id = "sg-backend"
  }
}

dependency "ecs" {
  config_path = "../ecs"

  mock_outputs = {
    ecs_cluster_id                 = "arn:aws:ecs:us-east-1:123456789012:cluster/staging-scribe-cluster"
    service_discovery_namespace_id = "ns-123456789"
  }
}

dependency "traefik" {
  config_path = "../traefik"

  mock_outputs = {
    traefik_security_group_id = "sg-traefik"
  }
}

dependency "secrets" {
  config_path = "../secrets"

  mock_outputs = {
    app_secrets_map = {
      openobserve_admin_password = "mock-secret" # gitleaks:allow
    }
  }
}

inputs = {
  environment                    = local.env_vars.locals.environment
  aws_region                     = local.env_vars.locals.aws_region
  vpc_id                         = dependency.networking.outputs.vpc_id
  private_subnet_ids             = dependency.networking.outputs.private_subnet_ids

  ecs_cluster_id                 = dependency.ecs.outputs.ecs_cluster_id
  service_discovery_namespace_id = dependency.ecs.outputs.service_discovery_namespace_id

  traefik_security_group_id      = dependency.traefik.outputs.traefik_security_group_id
  backend_security_group_id      = dependency.networking.outputs.backend_security_group_id

  openobserve_admin_email        = "admin@sanguinehost.com"
  openobserve_admin_password     = dependency.secrets.outputs.app_secrets_map["openobserve_admin_password"] # gitleaks:allow
  domain_name                    = "staging.sanguinehost.com"

  # Traefik labels are now primarily defined in the module for security defaults
  docker_labels = {}
}
