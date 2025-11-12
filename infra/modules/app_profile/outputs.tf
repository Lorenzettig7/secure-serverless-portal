output "api_id" {
  value = aws_apigatewayv2_api.api.id
}

output "api_base_url" {
  value = aws_apigatewayv2_api.api.api_endpoint
}

output "authorizer_id" {
  value = aws_apigatewayv2_authorizer.jwt.id
}

output "profile_function_name" {
  value = aws_lambda_function.profile.function_name
}

output "profile_log_group" {
  value = "/aws/lambda/${aws_lambda_function.profile.function_name}"
}
