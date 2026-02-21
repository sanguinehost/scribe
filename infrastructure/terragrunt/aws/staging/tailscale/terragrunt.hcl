# Tailscale module configuration for staging
include "root" {
  path = find_in_parent_folders("root.hcl")
}

terraform {
  source = "../../../../terraform/modules/tailscale"
}

locals {
  env_vars = read_terragrunt_config(find_in_parent_folders("env.hcl"))
}

dependency "networking" {
  config_path = "../networking"

  mock_outputs = {
    vpc_id            = "vpc-12345"
    public_subnet_ids = ["subnet-12345"]
    vpc_cidr_block    = "10.0.0.0/16"
  }
}

inputs = {
  environment        = local.env_vars.locals.environment
  vpc_id             = dependency.networking.outputs.vpc_id
  public_subnet_id   = dependency.networking.outputs.public_subnet_ids[0]
  vpc_cidr           = dependency.networking.outputs.vpc_cidr_block

  # Get auth key from environment for security
  tailscale_auth_key = get_env("TAILSCALE_AUTH_KEY", "dummy")

  instance_type      = "t3.nano"
  key_name           = "scribe-staging-link" # Reusing existing key pair if available
}
