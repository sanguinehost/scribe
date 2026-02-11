variable "environment" {
  description = "Environment name"
  type        = string
}

variable "alias_name" {
  description = "Alias name for the KMS key"
  type        = string
  default     = "alias/scribe-state-key"
}
