# app_telemetry/main.tf

data "aws_caller_identity" "current" {}

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
  function_name = "${var.project_prefix}-telemetry"
  role          = aws_iam_role.lambda.arn
  handler       = "telemetry_handler.lambda_handler"
  runtime       = "python3.10"
  filename      = "../../apps/lambda/telemetry_handler.zip"
  timeout       = 15
  memory_size   = 128
  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [var.lambda_security_group_id]
  }
  environment {
    variables = {
      LOG_GROUP = var.profile_log_group_name
    }
  }
  tags = var.common_tags
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = var.api_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.telemetry.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "activity" {
  api_id             = var.api_id
  route_key          = "GET /telemetry/activity"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
  authorization_type = "JWT"
  authorizer_id      = var.authorizer_id
}

resource "aws_lambda_permission" "allow_api" {
  function_name = aws_lambda_function.telemetry.function_name
  action        = "lambda:InvokeFunction"
  principal     = "apigateway.amazonaws.com"
  source_arn    = "arn:aws:execute-api:${var.region}:${data.aws_caller_identity.current.account_id}:${var.api_id}/*/*"
}
