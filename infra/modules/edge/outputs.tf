output "acm_cert_arn" {
  value = var.acm_cert_arn
}

output "cloudfront_domain" {
  value = aws_cloudfront_distribution.dist.domain_name
}

output "distribution_id" {
  value = aws_cloudfront_distribution.dist.id
}

output "web_bucket" {
  value = aws_s3_bucket.web.bucket
}
