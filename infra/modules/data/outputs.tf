output "profiles_table_name" {
  value = aws_dynamodb_table.profiles.name
}

output "profiles_table_arn" {
  value = aws_dynamodb_table.profiles.arn
}
output "profiles_kms_key_arn" {
  value = aws_kms_key.portal.arn
}
output "findings_table_name" {
  value = aws_dynamodb_table.findings.name
}

output "findings_table_arn" {
  value = aws_dynamodb_table.findings.arn
}
output "profiles_raw_bucket_name" {
  value = aws_s3_bucket.profiles_raw.bucket
}
output "portal_kms_key_arn" {
  value = aws_kms_key.portal.arn
}

