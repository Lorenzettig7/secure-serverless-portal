variable "project_prefix" { type = string }
variable "region" { type = string }
variable "common_tags" { type = map(string) }
variable "user_pool_issuer_url" { type = string }
variable "user_pool_client_id" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "lambda_security_group_id" { type = string }
variable "domain_name" { type = string } # e.g., portal.secureschoolcloud.org
variable "issuer_url" { type = string }
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
