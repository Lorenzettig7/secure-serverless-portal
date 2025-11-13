variable "project_prefix" {
  type = string
}

variable "region" {
  type = string
}

variable "common_tags" {
  type    = map(string)
  default = {}
}

variable "domain_name" {
  # e.g., portal.secureschoolcloud.org
  type = string
}

variable "web_bucket_name" {
  type = string
}

variable "logs_bucket" {
  type = string
}

variable "acm_cert_arn" {
  type = string
}

variable "api_domain_name" {
  # e.g., bm25ryr7md.execute-api.us-east-1.amazonaws.com (host only)
  type = string
}
