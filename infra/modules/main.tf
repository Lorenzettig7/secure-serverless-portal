module "cicd_iam" {
  source         = "./modules/cicd_iam"
  project_prefix = var.project_prefix
  github_owner   = "Lorenzettig7"
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
  hosted_zone_id = "Z09679523TY5GEYBHLDSS"
  common_tags    = local.common_tags
}
module "network" {
  source         = "./modules/network"
  project_prefix = var.project_prefix
  region         = var.region
  common_tags    = var.common_tags
}
module "app_profile" {
  source         = "./modules/app_profile"
  project_prefix = var.project_prefix
  region         = var.region
  common_tags    = var.common_tags

  user_pool_issuer_url = module.identity.issuer_url
  user_pool_client_id  = module.identity.user_pool_client_id

  private_subnet_ids       = module.network.private_subnet_ids
  lambda_security_group_id = module.network.lambda_security_group_id
}
module "app_telemetry" {
  source         = "./modules/app_telemetry"
  project_prefix = var.project_prefix
  region         = var.region
  common_tags    = var.common_tags

  api_id                 = module.app_profile.api_id
  authorizer_id          = module.app_profile.authorizer_id
  profile_log_group_name = module.app_profile.profile_log_group

  private_subnet_ids       = module.network.private_subnet_ids
  lambda_security_group_id = module.network.lambda_security_group_id
}
module "identity" {
  source         = "./modules/identity"
  project_prefix = var.project_prefix
  region         = var.region
  domain_name    = var.domain_name
  common_tags    = var.common_tags
}
