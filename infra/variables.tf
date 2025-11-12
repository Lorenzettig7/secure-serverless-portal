# infra/variables.tf
variable "project_prefix" {
  description = "Short name/prefix for all resources (e.g., ssp)"
  type        = string
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

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
}

