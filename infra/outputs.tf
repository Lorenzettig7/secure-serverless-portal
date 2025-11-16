output "web_bucket" {
  value = module.edge.web_bucket
}

output "cloudfront_distribution_id" {
  value = module.edge.distribution_id
}
output "user_pool_id" {
  value = module.identity.user_pool_id
}

output "user_pool_client_id" {
  value = module.identity.user_pool_client_id
}

output "hosted_ui_domain" {
  value = module.identity.hosted_ui_domain
}

output "issuer_url" {
  value = module.identity.issuer_url
}

# Helpful app outputs (optional but nice)
output "api_base_url" {
  value = module.app_profile.api_base_url
}
output "hosted_ui_login_url" {
  value = format(
    "https://%s/oauth2/authorize?client_id=%s&response_type=code&scope=openid+email+profile&redirect_uri=%s",
    module.identity.hosted_ui_domain,
    module.identity.user_pool_client_id,
    urlencode("https://${var.domain_name}/auth-callback.html")
  )
}