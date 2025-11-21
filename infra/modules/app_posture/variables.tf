variable "project_prefix" {}
variable "region" {}
variable "common_tags" {
  type = map(string)
}
variable "api_id" {}
variable "authorizer_id" {}
variable "private_subnet_ids" {
  type = list(string)
}
variable "lambda_security_group_id" {}
variable "portal_bucket_name" {}
variable "profiles_table_name" {}
variable "portal_kms_key_arn" {}
variable "waf_web_acl_arn" {}
variable "allowed_origin" {
  default = "https://portal.secureschoolcloud.org"
}
