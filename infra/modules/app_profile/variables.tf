variable "project_prefix" { type = string }
variable "region" { type = string }
variable "common_tags" { type = map(string) }
variable "user_pool_issuer_url" { type = string }
variable "user_pool_client_id" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "lambda_security_group_id" { type = string }
variable "domain_name" { type = string } # e.g., portal.secureschoolcloud.org
variable "issuer_url" { type = string }
variable "portal_kms_key_arn"       { type = string }
variable "profiles_table_name" {
  type        = string
  description = "DynamoDB table for user profiles"
}

variable "profiles_table_arn" {
  type        = string
  description = "ARN of DynamoDB profiles table"
}
variable "profiles_kms_key_arn" {
  type        = string
  description = "KMS key used to encrypt the profiles DynamoDB table"
}

variable "findings_table_name" {
  type        = string
  description = "DynamoDB findings table name"
}

variable "findings_table_arn" {
  type        = string
  description = "DynamoDB findings table ARN"
}
variable "allowed_origin" {
  type        = string
  description = "CORS origin for /findings"
}
variable "profiles_raw_bucket_name" {
  type = string
}
variable "portal_bucket_name" {
  type        = string
  description = "Name of the S3 bucket hosting the web portal"
}

variable "waf_web_acl_arn" {
  type        = string
  description = "ARN of the WAF web ACL protecting the portal"
}
