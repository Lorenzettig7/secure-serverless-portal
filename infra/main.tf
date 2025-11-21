provider "aws" {
  region = var.region
}

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

data "aws_caller_identity" "current" {}

data "aws_route53_zone" "primary" {
  name         = var.hosted_zone_domain
  private_zone = false
}
data "aws_route53_zone" "root" {
  name         = "${var.root_domain}."
  private_zone = false
}

locals {
  hosted_zone_id = var.hosted_zone_id != "" ? var.hosted_zone_id : data.aws_route53_zone.root.zone_id
  api_base_url   = var.api_base_url
  cognito_issuer = var.cognito_issuer
}

# Foundations (CloudTrail/Config/GuardDuty/SecHub/Logs)
module "foundations" {
  source         = "./modules/foundations"
  project_prefix = var.project_prefix
  region         = var.region
  common_tags    = local.common_tags
  alert_emails   = ["lorenzettig7@gmail.com"]
}

# CICD OIDC + deploy role (you already added this; keep it exactly like this)
module "cicd_iam" {
  source             = "./modules/cicd_iam"
  project_prefix     = var.project_prefix
  region             = var.region
  github_owner       = var.github_owner
  github_repo        = var.github_repo
  tfstate_bucket     = "ssp-tfstate-giovanna-73048814"
  tfstate_key_prefix = "portal/"      # from backend key = "portal/global.tfstate"
  tf_lock_table      = "ssp-tf-locks" # fill from step 1
  tf_kms_key_arn     = null
}

# Network (VPC + private subnets + gateway endpoints)
module "network" {
  source         = "./modules/network"
  project_prefix = var.project_prefix
  region         = var.region
  common_tags    = local.common_tags
}

# Edge (S3+OAC, CF, WAF, ACM, Route53)
data "aws_route53_zone" "public" {
  name         = "secureschoolcloud.org." # <-- your zone (note the trailing dot)
  private_zone = false
}
locals {
  web_bucket_name = "${var.project_prefix}-web-${data.aws_caller_identity.current.account_id}"
}

module "edge" {
  source          = "./modules/edge"
  project_prefix  = var.project_prefix
  region          = var.region
  domain_name     = var.domain_name
  web_bucket_name = "${var.project_prefix}-web-${data.aws_caller_identity.current.account_id}"
  logs_bucket     = module.foundations.logs_bucket
  api_domain_name = replace(module.app_profile.api_base_url, "https://", "")
  common_tags     = local.common_tags
  acm_cert_arn    = aws_acm_certificate.portal.arn

  providers = {
    aws           = aws           # default
    aws.us_east_1 = aws.us_east_1 # alias
  }
}

# Identity (Cognito)
module "identity" {
  source         = "./modules/identity"
  project_prefix = var.project_prefix
  region         = var.region
  domain_name    = var.domain_name
  common_tags    = local.common_tags
}

# App: Profile (Lambda + API + JWT authorizer)
module "app_profile" {
  source                   = "./modules/app_profile"
  project_prefix           = var.project_prefix
  region                   = var.region
  common_tags              = local.common_tags
  user_pool_issuer_url     = module.identity.issuer_url
  user_pool_client_id      = module.identity.user_pool_client_id
  private_subnet_ids       = module.network.private_subnet_ids
  lambda_security_group_id = module.network.lambda_security_group_id
  domain_name              = var.domain_name
  issuer_url               = module.identity.issuer_url
  profiles_table_name      = module.data.profiles_table_name
  profiles_table_arn       = module.data.profiles_table_arn
  profiles_kms_key_arn     = module.data.profiles_kms_key_arn
  findings_table_name      = module.data.findings_table_name
  findings_table_arn       = module.data.findings_table_arn
  allowed_origin           = "https://portal.secureschoolcloud.org"
  profiles_raw_bucket_name = module.data.profiles_raw_bucket_name
  portal_kms_key_arn       = module.data.portal_kms_key_arn
  portal_bucket_name       = module.edge.web_bucket
  waf_web_acl_arn          = module.edge.web_acl_arn

}
module "app_posture" {
  source                   = "./modules/app_posture"
  project_prefix           = var.project_prefix
  region                   = var.region
  common_tags              = local.common_tags
  api_id                   = module.app_profile.api_id
  authorizer_id            = module.app_profile.authorizer_id
  private_subnet_ids       = module.network.private_subnet_ids
  lambda_security_group_id = module.network.lambda_security_group_id
  profiles_table_name      = module.data.profiles_table_name
  portal_kms_key_arn       = module.data.portal_kms_key_arn
  portal_bucket_name       = module.edge.web_bucket
  waf_web_acl_arn          = module.edge.web_acl_arn
  allowed_origin           = "https://portal.secureschoolcloud.org"
}


# App: Telemetry (Lambda + API route; reuses app_profile’s API + authorizer)
module "app_telemetry" {
  source                   = "./modules/app_telemetry"
  project_prefix           = var.project_prefix
  region                   = var.region
  common_tags              = local.common_tags
  api_id                   = module.app_profile.api_id
  authorizer_id            = module.app_profile.authorizer_id
  profile_log_group_name   = module.app_profile.profile_log_group
  private_subnet_ids       = module.network.private_subnet_ids
  lambda_security_group_id = module.network.lambda_security_group_id
  telemetry_function_name  = "ssp-telemetry"
}

# Request cert in us-east-1 (CloudFront requirement)
resource "aws_acm_certificate" "portal" {
  provider                  = aws.us_east_1
  domain_name               = var.domain_name
  validation_method         = "DNS"
  subject_alternative_names = [] # add wildcards or extras if you want
  lifecycle {
    create_before_destroy = true
  }
}

# Create DNS validation records
resource "aws_route53_record" "portal_cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.portal.domain_validation_options :
    dvo.domain_name => {
      name  = dvo.resource_record_name
      type  = dvo.resource_record_type
      value = dvo.resource_record_value
    }
  }

  zone_id = data.aws_route53_zone.primary.zone_id
  name    = each.value.name
  type    = each.value.type
  ttl     = 60
  records = [each.value.value]
}

# Wait for validation to complete
resource "aws_acm_certificate_validation" "portal" {
  provider        = aws.us_east_1
  certificate_arn = aws_acm_certificate.portal.arn
  validation_record_fqdns = [
    for r in aws_route53_record.portal_cert_validation : r.fqdn
  ]
}

module "data" {
  source         = "./modules/data"
  project_prefix = var.project_prefix
  region         = var.region
  common_tags    = local.common_tags
  api_base_url   = local.api_base_url
  cognito_issuer = local.cognito_issuer
  root_domain    = var.root_domain
}