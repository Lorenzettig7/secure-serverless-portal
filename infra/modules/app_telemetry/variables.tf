variable "project_prefix" { type = string }
variable "region" { type = string }
variable "common_tags" { type = map(string) }
variable "api_id" { type = string }
variable "authorizer_id" { type = string }
variable "profile_log_group_name" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "lambda_security_group_id" { type = string }