############################################
# Edge module: S3 website + API via CF
############################################

# whoami (used only for naming if you need it later)
data "aws_caller_identity" "current" {}

# --- Website bucket (name is passed in) ---
resource "aws_s3_bucket" "web" {
  bucket = var.web_bucket_name
  tags   = var.common_tags
}

# Classic OAI for S3 origin (works with bucket policy)
resource "aws_cloudfront_origin_access_identity" "oai" {
  comment = "${var.project_prefix} web OAI"
}

# Allow CloudFront (OAI) to read from the web bucket
resource "aws_s3_bucket_policy" "web" {
  bucket = aws_s3_bucket.web.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudFrontRead"
        Effect    = "Allow"
        Principal = {
          AWS = aws_cloudfront_origin_access_identity.oai.iam_arn
        }
        Action   = ["s3:GetObject"]
        Resource = [
          "${aws_s3_bucket.web.arn}/*"
        ]
      }
    ]
  })
}

############################################
# CloudFront Distribution
############################################
resource "aws_cloudfront_distribution" "dist" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "${var.project_prefix} portal"
  default_root_object = "index.html"

  aliases = [var.domain_name]

  # --- Web (S3) origin via OAI ---
  origin {
    domain_name = "${aws_s3_bucket.web.bucket}.s3.${var.region}.amazonaws.com"
    origin_id   = "web-origin"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.oai.cloudfront_access_identity_path
    }
  }

  # --- API origin (API Gateway domain) ---
  origin {
    domain_name = var.api_domain_name   # e.g., gisdro12yf.execute-api.us-east-1.amazonaws.com
    origin_id   = "api-origin"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  # --- Behaviors ---

  # Static site default
  default_cache_behavior {
  target_origin_id       = "web-origin"
  viewer_protocol_policy = "redirect-to-https"
  allowed_methods        = ["GET", "HEAD", "OPTIONS"]
  cached_methods         = ["GET", "HEAD"]

  cache_policy_id          = "658327ea-f89d-4fab-a63d-7e88639e58f6" # CachingOptimized
  origin_request_policy_id = "88a5eaf4-2fd4-4709-b370-b4c650ea3fcf" # CORS-S3Origin
  response_headers_policy_id = "67f7725c-6f97-4210-82d7-5512b31e9d03" # SecurityHeaders

  compress = true

  function_association {
    event_type   = "viewer-request"
    function_arn = aws_cloudfront_function.rewrite_index.arn
  }
}

  # API under /api/*
  ordered_cache_behavior {
    path_pattern           = "/api/*"
    target_origin_id       = "api-origin"
    viewer_protocol_policy = "https-only"

    allowed_methods = ["GET","HEAD","OPTIONS","PUT","POST","PATCH","DELETE"]
    cached_methods  = ["GET","HEAD","OPTIONS"]

    cache_policy_id          = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"  # CachingDisabled
    origin_request_policy_id = "216adef6-5c7f-47e4-b989-5492eafa07d3"  # AllViewerExceptHostHeader

    compress = true
  }

  # Keep it simple: skip logging/price_class for now to avoid extra constraints

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = var.acm_cert_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  tags = var.common_tags
}
resource "aws_cloudfront_function" "rewrite_index" {
  name    = "ssp-rewrite-index"   # <- must match the existing function name
  runtime = "cloudfront-js-1.0"
  comment = "Append /index.html for extensionless paths"
  publish = true
  code    = file("${path.module}/rewrite-index.js")
}
