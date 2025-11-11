variable "project_prefix" { type = string }
variable "github_owner"   { type = string } # e.g., "lorenzettig7"
variable "github_repo"    { type = string } # e.g., "secure-serverless-portal"
variable "region"         { type = string }
variable "common_tags"    { type = map(string) }

