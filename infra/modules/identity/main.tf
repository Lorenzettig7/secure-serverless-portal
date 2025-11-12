resource "aws_cognito_user_pool" "main" {
  name                     = "${var.project_prefix}-user-pool"
  alias_attributes         = ["email"]
  auto_verified_attributes = ["email"]
  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = true
  }
  tags = var.common_tags
}


resource "aws_cognito_user_pool_client" "app" {
  name                                 = "${var.project_prefix}-app-client"
  user_pool_id                         = aws_cognito_user_pool.main.id
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  generate_secret                      = false
  callback_urls                        = ["https://${var.domain_name}/auth-callback.html"]
  logout_urls                          = ["https://${var.domain_name}/"]
  default_redirect_uri                 = "https://${var.domain_name}/auth-callback.html"
}


resource "aws_cognito_user_pool_domain" "main" {
  domain       = "${var.project_prefix}-portal"
  user_pool_id = aws_cognito_user_pool.main.id
}