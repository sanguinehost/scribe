# RDS module configuration for staging
include "root" {
  path = find_in_parent_folders("root.hcl")
}

terraform {
  source = "../../../../terraform/modules/rds"
}

locals {
  env_vars = read_terragrunt_config(find_in_parent_folders("env.hcl"))
}

dependency "networking" {
  config_path = "../networking"

  mock_outputs = {
    private_subnet_ids    = ["subnet-12345", "subnet-67890"]
    rds_security_group_id = "sg-12345678"
  }
}

inputs = {
  environment          = local.env_vars.locals.environment
  private_subnet_ids   = dependency.networking.outputs.private_subnet_ids
  rds_security_group_id = dependency.networking.outputs.rds_security_group_id

  # Staging-optimized settings
  postgres_version      = "15.10"
  db_instance_class     = "db.t4g.micro"
  multi_az_enabled      = false
  backup_retention_period = 7
}
