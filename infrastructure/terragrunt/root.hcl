# Root Terragrunt configuration
# This file centralizes provider configuration and remote state management for all modules.

locals {
  # Load environment-level variables if they exist
  # env_vars = read_terragrunt_config(find_in_parent_folders("env.hcl"))

  # Default region
  aws_region = "ap-southeast-4"

  # Check if we are in the KMS module to avoid circular dependency
  is_kms_module = strcontains(path_relative_to_include(), "kms")
}

# ... (omitted provider generation) ...

# OpenTofu 1.7+ Native Encryption Block Generation
# We use 'generate' to inject this into every module EXCEPT KMS.
generate "encryption" {
  path      = "encryption.tf"
  if_exists = "overwrite_terragrunt"
  contents  = local.is_kms_module ? "" : <<EOF
terraform {
  encryption {
    key_provider "aws_kms" "main" {
      kms_key_id = "alias/scribe-state-key"
      region     = "${local.aws_region}"
      key_spec   = "AES_256"
    }

    method "aes_gcm" "main" {
      keys = key_provider.aws_kms.main
    }

    state {
      method   = method.aes_gcm.main
      enforced = true
    }

    plan {
      method   = method.aes_gcm.main
      enforced = true
    }
  }
}
EOF
}

# Generate an AWS provider block
generate "provider" {
  path      = "provider.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<EOF
provider "aws" {
  region = "${local.aws_region}"
}

# Provider for global resources (ACM certificates for CloudFront, etc.)
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

# Provider for SES (Sydney)
provider "aws" {
  alias  = "ses"
  region = "ap-southeast-2"
}
EOF
}

# Configure Terragrunt to automatically store tfstate files in an S3 bucket
# and use OpenTofu state encryption.
remote_state {
  backend = "s3"
  generate = {
    path      = "backend.tf"
    if_exists = "overwrite_terragrunt"
  }
  config = {
    bucket         = "scribe-opentofu-state-${get_aws_account_id()}"
    key            = "${path_relative_to_include()}/terraform.tfstate"
    region         = local.aws_region
    encrypt        = true
    dynamodb_table = "scribe-opentofu-locks"

    # OpenTofu 1.7+ State Encryption configuration
    # Note: This is an example, real KMS key should be created first or managed here.
    # s3_bucket_query_parameters = {
    #   encryption = "{\"kms_key_id\":\"arn:aws:kms:${local.aws_region}:${get_aws_account_id()}:key/scribe-state-key\"}"
    # }
  }
}

# OpenTofu 1.7+ Native Encryption Block Generation
# We use 'generate' to inject this into every module.

# Global inputs across all modules
inputs = {
  aws_region  = local.aws_region
  environment = "staging"
  base_domain = "sanguinehost.com"
}
