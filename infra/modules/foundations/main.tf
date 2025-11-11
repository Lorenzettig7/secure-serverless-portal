locals {
  logs_bucket = "${var.project_prefix}-logs-${data.aws_caller_identity.current.account_id}"
}

data "aws_caller_identity" "current" {}

# Logs bucket (CloudTrail/CF/WAF/etc.)
resource "aws_s3_bucket" "logs" {
  bucket = local.logs_bucket
  tags   = var.common_tags
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# CloudTrail (org-trail not required; single-account ok)
resource "aws_cloudtrail" "main" {
  name                          = "${var.project_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.logs.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
  tags                          = var.common_tags
}

# AWS Config
resource "aws_config_configuration_recorder" "rec" {
  name     = "${var.project_prefix}-rec"
  role_arn = aws_iam_role.config_role.arn
  recording_group {
    all_supported              = true
    include_global_resource_types = true
  }
  depends_on = [aws_iam_role_policy_attachment.config_attach]
}

resource "aws_config_delivery_channel" "chan" {
  name           = "${var.project_prefix}-chan"
  s3_bucket_name = aws_s3_bucket.logs.bucket
  depends_on     = [aws_config_configuration_recorder.rec]
}

resource "aws_config_configuration_recorder_status" "status" {
  name    = aws_config_configuration_recorder.rec.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.chan]
}

# Config role
data "aws_iam_policy_document" "config_trust" {
  statement {
    effect = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}
resource "aws_iam_role" "config_role" {
  name               = "${var.project_prefix}-config-role"
  assume_role_policy = data.aws_iam_policy_document.config_trust.json
  tags               = var.common_tags
}
resource "aws_iam_role_policy_attachment" "config_attach" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRole"
}

# GuardDuty
resource "aws_guardduty_detector" "main" {
  enable = true
  tags   = var.common_tags
}

# Security Hub
resource "aws_securityhub_account" "main" {
  enable_default_standards = false
  tags = var.common_tags
}

resource "aws_securityhub_standards_subscription" "aws_fsbp" {
  standards_arn = "arn:aws:securityhub:${var.region}:${data.aws_caller_identity.current.account_id}:standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:::standards/cis-aws-foundations-benchmark/v/1.4.0"
  depends_on    = [aws_securityhub_account.main]
}

# IAM Access Analyzer
resource "aws_accessanalyzer_analyzer" "account" {
  analyzer_name = "${var.project_prefix}-account-analyzer"
  type          = "ACCOUNT"
  tags          = var.common_tags
}
