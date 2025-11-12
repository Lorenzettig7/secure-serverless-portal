output "user_pool_id" {
  value = aws_cognito_user_pool.main.id
}


output "user_pool_arn" {
  value = aws_cognito_user_pool.main.arn
}


output "user_pool_client_id" {
  value = aws_cognito_user_pool_client.app.id
}


output "issuer_url" {
  value = "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.main.id}"
}


output "hosted_ui_url" {
  value = "https://${aws_cognito_user_pool_domain.main.domain}.auth.${var.region}.amazoncognito.com/login?client_id=${aws_cognito_user_pool_client.app.id}&response_type=code&scope=openid+profile+email&redirect_uri=https://${var.domain_name}/auth-callback.html"
}