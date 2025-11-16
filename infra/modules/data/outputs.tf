output "profiles_table_name" {
  value = aws_dynamodb_table.profiles.name
}

output "profiles_table_arn" {
  value = aws_dynamodb_table.profiles.arn
}
output "profiles_kms_key_arn" {
  value = aws_kms_key.portal.arn
}