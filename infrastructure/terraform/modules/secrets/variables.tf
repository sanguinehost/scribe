variable "environment" {
  description = "Environment name (e.g., staging, production)"
  type        = string
}

# Database credential variables
variable "database_username" {
  description = "Database master username"
  type        = string
  sensitive   = true
}

variable "database_password" {
  description = "Database master password"
  type        = string
  sensitive   = true
}

variable "database_host" {
  description = "Database host"
  type        = string
}

variable "database_port" {
  description = "Database port"
  type        = number
}

variable "database_name" {
  description = "Database name"
  type        = string
}

variable "database_url" {
  description = "Full database URL"
  type        = string
  sensitive   = true
}

# Application secret variables
variable "gemini_api_key" {
  description = "Gemini API key"
  type        = string
  sensitive   = true
  default     = ""
}

variable "jwt_secret" {
  description = "JWT secret for authentication"
  type        = string
  sensitive   = true
  default     = ""
}

variable "encryption_key" {
  description = "Encryption key for sensitive data"
  type        = string
  sensitive   = true
  default     = ""
}

variable "session_secret" {
  description = "Session secret for web sessions"
  type        = string
  sensitive   = true
  default     = ""
}

variable "cookie_signing_key" {
  description = "Hex-encoded cookie signing key"
  type        = string
  sensitive   = true
  default     = ""
}

variable "qdrant_api_key" {
  description = "Qdrant API key for vector database authentication"
  type        = string
  sensitive   = true
  default     = ""
}

variable "tls_cert_pem" {
  description = "TLS certificate in PEM format"
  type        = string
  sensitive   = true
  default     = ""
}

variable "tls_key_pem" {
  description = "TLS private key in PEM format"
  type        = string
  sensitive   = true
  default     = ""
}

variable "from_email" {
  description = "From email address for SES"
  type        = string
  default     = ""
}