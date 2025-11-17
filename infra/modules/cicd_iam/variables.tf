variable "project_prefix" { type = string }
variable "region" { type = string }

variable "github_owner" { type = string }
variable "github_repo" { type = string }

# Backend access for CI/CD
variable "tfstate_bucket" { type = string }     # e.g., "ssp-tfstate-giovanna-73048814"
variable "tfstate_key_prefix" { type = string } # e.g., "portal/"
variable "tf_lock_table" { type = string }      # e.g., "ssp-tf-locks"

# Optional: if your tfstate bucket uses SSE-KMS
variable "tf_kms_key_arn" {
  type    = string
  default = null
}
