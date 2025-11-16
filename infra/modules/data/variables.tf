# infra/modules/data/variables.tf

variable "project_prefix" {
  description = "Prefix for naming AWS resources"
  type        = string
}

variable "api_base_url" {
  description = "Base URL of the deployed API"
  type        = string
}

variable "cognito_issuer" {
  description = "Cognito issuer URL for JWT validation"
  type        = string
}