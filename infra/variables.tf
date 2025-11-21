# infra/variables.tf


variable "github_owner" { type = string }
variable "github_repo" { type = string }
variable "findings_table_name" { type = string }
variable "findings_table_arn" { type = string }

variable "domain_name" {
  description = "Public portal hostname used by Cognito redirects (e.g., portal.secureschoolcloud.org)"
  type        = string
}

variable "common_tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default     = {}
}

variable "env" {
  description = "Environment tag (e.g., dev, prod)"
  type        = string
  default     = "dev"
}
variable "hosted_zone_domain" {
  description = "Route53 hosted zone name (root), e.g., secureschoolcloud.org"
  type        = string
  default     = ""
}

variable "region" {
  description = "Primary AWS region for most resources"
  type        = string
  default     = "us-east-1"
}

variable "hosted_zone_id" {
  description = "Public Route53 hosted zone ID for the domain's DNS"
  type        = string
  default     = ""
}

variable "project_prefix" {
  description = "Prefix for naming (e.g., ssp)"
  type        = string
  default     = "ssp"
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