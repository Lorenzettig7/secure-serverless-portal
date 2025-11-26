# infra/modules/data/main.tf
data "archive_file" "pii_scanner_zip" {
  type        = "zip"
  source_file = "${path.root}/../apps/lambda/pii_scanner.py"
  output_path = "${path.module}/build/pii_scanner.zip"
}
data "archive_file" "macie_ingest_zip" {
  type        = "zip"
  source_file = "${path.root}/../apps/lambda/macie_ingest.py"
  output_path = "${path.module}/build/macie_ingest.zip"
}
data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role_policy_attachment" "pii_scanner_basic" {
  role       = aws_iam_role.pii_scanner_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}


resource "aws_kms_key" "portal" {
  description             = "${var.project_prefix} profiles KMS"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = var.common_tags
}

resource "aws_kms_alias" "portal" {
  name          = "alias/${var.project_prefix}-app"
  target_key_id = aws_kms_key.portal.id
}

resource "aws_dynamodb_table" "profiles" {
  name         = "${var.project_prefix}-profiles"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  stream_enabled   = true
  stream_view_type = "NEW_IMAGE"

  attribute {
    name = "id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.portal.arn
  }

  tags = var.common_tags
}

resource "aws_ssm_parameter" "api_base_url" {
  name  = "/ssp/api_base_url"
  type  = "String"
  value = var.api_base_url
  tags  = var.common_tags
}

resource "aws_ssm_parameter" "cognito_issuer" {
  name  = "/ssp/cognito_issuer"
  type  = "String"
  value = var.cognito_issuer
  tags  = var.common_tags
}
resource "aws_dynamodb_table" "findings" {
  name         = "${var.project_prefix}-findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  attribute {
    name = "user_id"
    type = "S"
  }

  attribute {
    name = "created_at"
    type = "S"
  }

  global_secondary_index {
    name               = "by_user"
    hash_key           = "user_id"
    range_key          = "created_at"
    projection_type    = "ALL"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.portal.arn
  }

  tags = var.common_tags
}
resource "aws_iam_role" "pii_scanner_role" {
  name               = "${var.project_prefix}-pii-scanner-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = var.common_tags
}

resource "aws_iam_role_policy" "pii_scanner_policy" {
  name = "${var.project_prefix}-pii-scanner-ddb"
  role = aws_iam_role.pii_scanner_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # Write findings
      {
        Effect   = "Allow",
        Action   = ["dynamodb:PutItem"],
        Resource = aws_dynamodb_table.findings.arn
      },
      # Read from the profiles DynamoDB stream
      {
        Effect = "Allow",
        Action = [
          "dynamodb:GetRecords",
          "dynamodb:GetShardIterator",
          "dynamodb:DescribeStream"
        ],
        Resource = aws_dynamodb_table.profiles.stream_arn
      },
      {
        Effect   = "Allow",
        Action   = ["dynamodb:ListStreams"],
        Resource = "*"
      },
      # Use the KMS key that encrypts the findings table
      {
        Effect = "Allow",
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ],
        Resource = aws_kms_key.portal.arn
      }
    ]
  })
}


resource "aws_lambda_function" "pii_scanner" {
  function_name    = "${var.project_prefix}-pii-scanner"
  role             = aws_iam_role.pii_scanner_role.arn
  filename         = data.archive_file.pii_scanner_zip.output_path
  source_code_hash = data.archive_file.pii_scanner_zip.output_base64sha256
  handler          = "pii_scanner.handler"
  runtime          = "python3.11"
  timeout          = 10

  environment {
    variables = {
      FINDINGS_TABLE_NAME = aws_dynamodb_table.findings.name
    }
  }

  tags = var.common_tags
}

resource "aws_lambda_event_source_mapping" "profiles_stream" {
  event_source_arn  = aws_dynamodb_table.profiles.stream_arn
  function_name     = aws_lambda_function.pii_scanner.arn
  starting_position = "LATEST"
}
resource "aws_s3_bucket" "profiles_raw" {
  bucket = "${var.project_prefix}-profiles-raw"

  force_destroy = true

  tags = var.common_tags
}

resource "aws_s3_bucket_public_access_block" "profiles_raw" {
  bucket = aws_s3_bucket.profiles_raw.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "profiles_raw" {
  bucket = aws_s3_bucket.profiles_raw.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "profiles_raw" {
  bucket = aws_s3_bucket.profiles_raw.bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.portal.arn
    }
  }
}

resource "aws_iam_role" "macie_ingest_role" {
  name               = "${var.project_prefix}-macie-ingest-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = var.common_tags
}
resource "aws_iam_role_policy" "macie_ingest_policy" {
  name = "${var.project_prefix}-macie-ingest-ddb"
  role = aws_iam_role.macie_ingest_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # allow writing into the findings table
      {
        Effect   = "Allow",
        Action   = [
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ],
        Resource = aws_dynamodb_table.findings.arn
      },
      # allow DynamoDB to use the KMS key that encrypts that table
      {
        Effect = "Allow",
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ],
        Resource = aws_kms_key.portal.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "macie_ingest_basic" {
  role       = aws_iam_role.macie_ingest_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "macie_ingest_ddb" {
  name = "${var.project_prefix}-macie-ingest-ddb"
  role = aws_iam_role.macie_ingest_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ]
        Resource = aws_dynamodb_table.findings.arn
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.portal.arn  # same key used by ssp-findings SSE
      }
    ]
  })
}

resource "aws_lambda_function" "macie_ingest" {
  function_name    = "${var.project_prefix}-macie-ingest"
  role             = aws_iam_role.macie_ingest_role.arn
  filename         = data.archive_file.macie_ingest_zip.output_path
  source_code_hash = data.archive_file.macie_ingest_zip.output_base64sha256
  handler          = "macie_ingest.handler"
  runtime          = "python3.11"
  timeout          = 15

  environment {
    variables = {
      FINDINGS_TABLE_NAME = aws_dynamodb_table.findings.name
      PROFILE_RAW_BUCKET  = aws_s3_bucket.profiles_raw.bucket
    }
  }

  tags = var.common_tags
}
resource "aws_cloudwatch_event_rule" "macie_findings" {
  name        = "${var.project_prefix}-macie-findings"
  description = "Route Amazon Macie findings to macie_ingest Lambda"

  event_pattern = jsonencode({
    "source"      : ["aws.macie"],
    "detail-type" : ["Macie Finding"]
  })
}

resource "aws_cloudwatch_event_target" "macie_findings_lambda" {
  rule      = aws_cloudwatch_event_rule.macie_findings.name
  target_id = "macie-ingest-lambda"
  arn       = aws_lambda_function.macie_ingest.arn
}
resource "aws_lambda_permission" "allow_events_macie_ingest" {
  statement_id  = "AllowEventsInvokeMacieIngest"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.macie_ingest.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.macie_findings.arn
}

