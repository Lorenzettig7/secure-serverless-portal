# app_telemetry/main.tf

data "aws_caller_identity" "current" {}
data "aws_caller_identity" "this" {}
data "aws_cloudwatch_log_group" "profile" {
  name = var.profile_log_group_name
}
data "aws_lambda_function" "telemetry" {
  function_name = var.telemetry_function_name
}
locals {
  telemetry_role_name = basename(data.aws_lambda_function.telemetry.role)
  # e.g., "ssp-telemetry-lambda-role"
}
data "archive_file" "telemetry_zip" {
  type        = "zip"
  source_file = "${path.root}/../apps/lambda/telemetry_handler.py"
  output_path = "${path.module}/build/telemetry_handler.zip"
}
resource "aws_iam_policy" "telemetry_logs" {
  name   = "portal-telemetry-logs"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "LogsStartQueryOnProfileGroup",
        Effect = "Allow",
        Action = ["logs:StartQuery"],
        Resource = data.aws_cloudwatch_log_group.profile.arn
      },
      {
        Sid    = "LogsGetQueryResults",
        Effect = "Allow",
        Action = ["logs:GetQueryResults"],
        Resource = "*"   # <-- required
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "telemetry_logs_attach" {
  role       = local.telemetry_role_name
  policy_arn = aws_iam_policy.telemetry_logs.arn
}

resource "aws_iam_role" "lambda" {
  name = "${var.project_prefix}-telemetry-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "lambda.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.common_tags
}
# Let Lambda create/delete ENIs in your VPC
resource "aws_iam_role_policy_attachment" "lambda_vpc_access" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# (optional but fine to include) basic logs policy
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
resource "aws_iam_role_policy" "lambda_cloudtrail" {
  name = "${var.project_prefix}-telemetry-cloudtrail"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cloudtrail:LookupEvents",
        ]
        # LookupEvents is not resource-scoped; must be "*"
        Resource = "*"
      }
    ]
  })
}


resource "aws_iam_role_policy" "lambda_policy" {
  name = "telemetry-inline"
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "LogsQueryAccess",
        Effect   = "Allow",
        Action   = ["logs:StartQuery", "logs:GetQueryResults"],
        Resource = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:${var.profile_log_group_name}:*"
      },
      {
        Sid      = "CloudTrailAccess",
        Effect   = "Allow",
        Action   = ["cloudtrail:LookupEvents"],
        Resource = "*"
      },
      {
        Sid      = "SelfLogsAccess",
        Effect   = "Allow",
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "telemetry" {
  function_name    = "${var.project_prefix}-telemetry"
  role             = aws_iam_role.lambda.arn
  handler          = "telemetry_handler.handler"
  runtime          = "python3.10"
  timeout          = 15
  memory_size      = 128
  filename         = data.archive_file.telemetry_zip.output_path
  source_code_hash = data.archive_file.telemetry_zip.output_base64sha256
  publish          = true
  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [var.lambda_security_group_id]
  }
  environment {
    variables = {
      LOG_GROUP      = var.profile_log_group_name # or var.telemetry_log_group_name if you have that
      ALLOWED_ORIGIN = "https://portal.secureschoolcloud.org"
      MAX_EVENTS     = "20"
    }
  }

  tags = var.common_tags
}
resource "aws_iam_role_policy" "telemetry_least" {
  name = "${var.project_prefix}-telemetry-least"
  role = aws_iam_role.lambda.name

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "CloudTrailLookup",
        Effect   = "Allow",
        Action   = ["cloudtrail:LookupEvents"],
        Resource = "*"
      },
      {
        Sid      = "Logging",
        Effect   = "Allow",
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"],
        Resource = "arn:aws:logs:${var.region}:${data.aws_caller_identity.this.account_id}:log-group:/aws/lambda/${aws_lambda_function.telemetry.function_name}:*"
      }
    ]
  })
}
resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = var.api_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.telemetry.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_lambda_permission" "allow_api" {
  function_name = aws_lambda_function.telemetry.function_name
  action        = "lambda:InvokeFunction"
  principal     = "apigateway.amazonaws.com"
  source_arn    = "arn:aws:execute-api:${var.region}:${data.aws_caller_identity.current.account_id}:${var.api_id}/*/*"
}
resource "aws_apigatewayv2_integration" "telemetry" {
  api_id                 = var.api_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.telemetry.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "get_activity" {
  api_id             = var.api_id
  route_key          = "GET /activity"
  target             = "integrations/${aws_apigatewayv2_integration.telemetry.id}"
  authorization_type = "JWT"
  authorizer_id      = var.authorizer_id
}

