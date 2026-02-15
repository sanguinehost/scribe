# Staging environment configuration
terraform {
  required_providers {
    source  = "hashicorp/aws"
    version = "~> 5.0"
  }

  required_version = ">= 1.0"

  # Include the ECR module
  dependencies {
    paths = ["./ecr"]
  }
}
