# Traefik module configuration for staging
include "root" {
  path = find_in_parent_folders("root.hcl")
}

terraform {
  source = "../../../../terraform/modules/traefik"
}

locals {
  env_vars = read_terragrunt_config(find_in_parent_folders("env.hcl"))
}

dependency "networking" {
  config_path = "../networking"

  mock_outputs = {
    vpc_id             = "vpc-12345"
    public_subnet_ids  = ["subnet-12345", "subnet-67890"]
    private_subnet_ids = ["subnet-abcde", "subnet-fghij"]
    route53_zone_id    = "Z123456789"
  }
}

dependency "ecs" {
  config_path = "../ecs"

  mock_outputs = {
    ecs_cluster_id   = "arn:aws:ecs:us-east-1:123456789012:cluster/staging-scribe-cluster"
    ecs_task_role_name = "staging-scribe-ecs-task-role"
  }
}

inputs = {
  environment         = local.env_vars.locals.environment
  aws_region          = local.env_vars.locals.aws_region
  vpc_id              = dependency.networking.outputs.vpc_id
  public_subnet_ids   = dependency.networking.outputs.public_subnet_ids
  private_subnet_ids  = dependency.networking.outputs.private_subnet_ids

  ecs_cluster_id      = dependency.ecs.outputs.ecs_cluster_id

  # Traefik needs to access ECS API, so we reuse the task role or create a new one.
  # The module creates its own execution and task roles.
  execution_role_arn  = "arn:aws:iam::${get_aws_account_id()}:role/${local.env_vars.locals.environment}-scribe-traefik-task-execution-role" # Helper to pass ARN if module doesn't create it, but module creates it.
  task_role_arn       = "arn:aws:iam::${get_aws_account_id()}:role/${local.env_vars.locals.environment}-scribe-traefik-task-role"

  # DNS
  domain_name         = "staging.scribe.sanguinehost.com"
  subject_alternative_names = [
    "api.staging.scribe.sanguinehost.com",
    "obs.staging.sanguinehost.com"
  ]
  additional_domains = [
    "api.staging.scribe.sanguinehost.com",
    "obs.staging.sanguinehost.com"
  ]
  route53_zone_id     = dependency.networking.outputs.route53_zone_id

  # Capacity
  desired_count       = 1
  traefik_cpu         = 256
  traefik_memory      = 512
}
