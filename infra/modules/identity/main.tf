resource "aws_cognito_user_pool" "main" {
  name = "${var.project_prefix}-user-pool"

  # Allow users to sign in with email (canonical username will be an internal ID)
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  # Let users sign themselves up via Hosted UI
  admin_create_user_config {
    allow_admin_create_user_only = false
  }

  # (Optional, reasonable defaults)
  password_policy {
    minimum_length                   = 8
    require_numbers                  = true
    require_lowercase                = true
    require_uppercase                = true
    require_symbols                  = false
    temporary_password_validity_days = 7
  }

  tags = var.common_tags
}

# -------------------------------------
# App Client (Hosted UI + OAuth settings)
# -------------------------------------
resource "aws_cognito_user_pool_client" "app" {
  name         = "${var.project_prefix}-app-client"
  user_pool_id = aws_cognito_user_pool.main.id

  supported_identity_providers         = ["COGNITO"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  generate_secret                      = false

  callback_urls        = ["https://${var.domain_name}/auth/callback/"]
  default_redirect_uri = "https://${var.domain_name}/auth/callback/"
  logout_urls          = ["https://${var.domain_name}/"]
}



# --------------------
# Hosted UI subdomain
# --------------------
resource "aws_cognito_user_pool_domain" "main" {
  domain       = "${var.project_prefix}-portal" # e.g., ssp-portal
  user_pool_id = aws_cognito_user_pool.main.id
}