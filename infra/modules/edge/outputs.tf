output "web_bucket"         { value = aws_s3_bucket.web.bucket }
output "cloudfront_domain"  { value = aws_cloudfront_distribution.cdn.domain_name }
output "distribution_id"    { value = aws_cloudfront_distribution.cdn.id }
