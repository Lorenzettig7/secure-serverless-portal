variable "project_prefix" { type = string }
variable "common_tags" {
  type    = map(string)
  default = {}
}
variable "api_base_url" {
  type        = string
  description = "Base URL of the deployed API (e.g., https://portal.secureschoolcloud.org/api)"
}

variable "cognito_issuer" {
  type        = string
  description = "Cognito issuer URL for JWT validation"
}
