terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4" # any recent 2.x is fine
    }
  }
}


locals {
  project_prefix = var.project_prefix
  common_tags = {
    Project = "SecureServerlessPortal"
    Owner   = "Giovanna"
    Env     = var.env
  }
}
