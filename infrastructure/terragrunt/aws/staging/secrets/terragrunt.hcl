# Secrets module configuration for staging
include "root" {
  path = find_in_parent_folders("root.hcl")
}

terraform {
  source = "../../../../terraform/modules/secrets"
}

locals {
  env_vars = read_terragrunt_config(find_in_parent_folders("env.hcl"))
}

dependency "rds" {
  config_path = "../rds"

  mock_outputs = {
    master_username       = "scribe_admin"
    master_password       = "password" # gitleaks:allow
    rds_instance_endpoint = "db:5432"
    rds_instance_port     = 5432
    database_name         = "scribe"
    database_url          = "postgresql://..."
  }
}

inputs = {
  environment       = local.env_vars.locals.environment
  database_username = dependency.rds.outputs.master_username
  database_password = dependency.rds.outputs.master_password
  database_host     = dependency.rds.outputs.rds_instance_endpoint
  database_port     = dependency.rds.outputs.rds_instance_port
  database_name     = dependency.rds.outputs.database_name
  database_url      = dependency.rds.outputs.database_url

  # These were previously generated in root main.tf
  # For now, we use dummy values or we can use Terragrunt to generate them
  # but Terragrunt inputs are better as static for reproducibility.
  # We should ideally move the random_password resources into the secrets module.

  # API Keys (from env or terraform.tfvars)
  gemini_api_key = get_env("GEMINI_API_KEY", "")

  # Email Configuration
  from_email = "operations@sanguinehost.com"
}
