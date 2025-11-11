module "cicd_iam" {
  source         = "./modules/cicd_iam"
  project_prefix = var.project_prefix
  github_owner   = "<YOUR_GH_USERNAME>"
  github_repo    = "secure-serverless-portal"
  region         = var.region
  common_tags    = local.common_tags
}

module "foundations" {
  source         = "./modules/foundations"
  project_prefix = var.project_prefix
  region         = var.region
  common_tags    = local.common_tags
}

module "edge" {
  source         = "./modules/edge"
  project_prefix = var.project_prefix
  region         = var.region
  domain_name    = "portal.secureschoolcloud.org"
  hosted_zone_id = "<YOUR_HOSTED_ZONE_ID>" # e.g. Z123ABCDEF
  common_tags    = local.common_tags
}
