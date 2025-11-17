variable "project_prefix" { type = string }
variable "region" { type = string }

variable "common_tags" {
  type    = map(string)
  default = {}
}
variable "api_base_url" {
  description = "Base URL of the deployed API"
  type        = string
  default     = ""
}

variable "cognito_issuer" {
  description = "Cognito issuer URL for JWT validation"
  type        = string
  default     = ""
}
variable "root_domain" {
  description = "Root domain, e.g. secureschoolcloud.org"
  type        = string
}