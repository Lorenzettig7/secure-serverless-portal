# infra/modules/data/main.tf

resource "aws_kms_key" "portal" {
  description         = "CMK for portal DynamoDB table encryption"
  deletion_window_in_days = 10
  enable_key_rotation = true
  tags = {
    Name = "${var.project_prefix}-app-kms"
  }
}

resource "aws_kms_alias" "portal" {
  name          = "alias/${var.project_prefix}-app"
  target_key_id = aws_kms_key.portal.id
}

resource "aws_dynamodb_table" "profiles" {
  name         = "${var.project_prefix}-profiles"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.portal.arn
  }

  tags = {
    Name = "${var.project_prefix}-profiles"
  }
}

resource "aws_ssm_parameter" "api_base_url" {
  name  = "/${var.project_prefix}/api_base_url"
  type  = "String"
  value = var.api_base_url
}

resource "aws_ssm_parameter" "cognito_issuer" {
  name  = "/${var.project_prefix}/cognito_issuer"
  type  = "String"
  value = var.cognito_issuer
}
