data "aws_caller_identity" "current" {}

data "archive_file" "posture_zip" {
  type        = "zip"
  source_file = "${path.root}/../apps/lambda/posture_handler.py"
  output_path = "${path.module}/build/posture_handler.zip"
}

resource "aws_iam_role" "lambda" {
  name               = "${var.project_prefix}-posture-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "lambda.amazonaws.com" },
      Action   = "sts:AssumeRole"
    }]
  })
  tags = var.common_tags
}

resource "aws_iam_role_policy_attachment" "basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
resource "aws_iam_role_policy_attachment" "vpc_access" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy" "inline" {
  name = "${var.project_prefix}-posture-inline"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "CloudTrailDescribe",
        Effect = "Allow",
        Action = ["cloudtrail:DescribeTrails"],
        Resource = "*"
      },
      {
        Sid    = "GuardDutyRead",
        Effect = "Allow",
        Action = ["guardduty:ListDetectors", "guardduty:GetDetector"],
        Resource = "*"
      },
      {
        Sid    = "SecurityHubRead",
        Effect = "Allow",
        Action = ["securityhub:DescribeHub", "securityhub:GetFindings"],
        Resource = "*"
      },
      {
        Sid    = "ConfigSummary",
        Effect = "Allow",
        Action = ["config:GetComplianceSummaryByConfigRule"],
        Resource = "*"
      },
      {
        Sid    = "WAFSample",
        Effect = "Allow",
        Action = ["wafv2:GetSampledRequests"],
        Resource = var.waf_web_acl_arn
      },
      {
       Sid    = "S3Portal",
      Effect = "Allow",
       Action = "s3:*",
       Resource = "arn:aws:s3:::${var.portal_bucket_name}"
      },
      {
        Sid    = "DDBProfiles",
        Effect = "Allow",
        Action = [
    "dynamodb:DescribeTable",
    "dynamodb:GetItem"
  ]
        Resource = "arn:aws:dynamodb:${var.region}:${data.aws_caller_identity.current.account_id}:table/${var.profiles_table_name}"
      }
    ]
  })
}

resource "aws_lambda_function" "posture" {
  function_name = "${var.project_prefix}-posture"
  role          = aws_iam_role.lambda.arn
  handler       = "posture_handler.handler"
  runtime       = "python3.12"
  timeout       = 10

  filename         = data.archive_file.posture_zip.output_path
  source_code_hash = data.archive_file.posture_zip.output_base64sha256

  environment {
    variables = {
      ALLOWED_ORIGIN     = var.allowed_origin
      PORTAL_BUCKET_NAME = var.portal_bucket_name
      PROFILES_TABLE_NAME = var.profiles_table_name
      WAF_WEBACL_ARN     = var.waf_web_acl_arn
      WAF_SAMPLE_RULE    = "Default_Action"
      ADMIN_EMAIL         = "lorenzettigi7@gmail.com"
    }
  }
  tags = var.common_tags
}

resource "aws_apigatewayv2_integration" "posture" {
  api_id                 = var.api_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.posture.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "get_posture" {
  api_id             = var.api_id
  route_key          = "GET /security/posture"
  target             = "integrations/${aws_apigatewayv2_integration.posture.id}"
  authorization_type = "JWT"
  authorizer_id      = var.authorizer_id
}

resource "aws_lambda_permission" "allow_api" {
  function_name = aws_lambda_function.posture.function_name
  action        = "lambda:InvokeFunction"
  principal     = "apigateway.amazonaws.com"
  source_arn    = "arn:aws:execute-api:${var.region}:${data.aws_caller_identity.current.account_id}:${var.api_id}/*/*"
}
