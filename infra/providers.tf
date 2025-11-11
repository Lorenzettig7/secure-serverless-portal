terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.61"
    }
  }
}

provider "aws" {
  region = var.region
}

locals {
  project_prefix = var.project_prefix
  common_tags = {
    Project = "SecureServerlessPortal"
    Owner   = "Giovanna"
    Env     = var.env
  }
}
