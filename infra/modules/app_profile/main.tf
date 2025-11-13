data "aws_caller_identity" "current" {}

data "archive_file" "auth_exchange" {
  type        = "zip"
  source_file = "${path.module}/../../../apps/lambda/auth_exchange.py"
  output_path = "${path.module}/../../../apps/lambda/auth_exchange.zip"
}

# IAM role for the Profile Lambda
resource "aws_iam_role" "lambda" {
  name = "${var.project_prefix}-profile-lambda-role"
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

# Inline policy (least privilege for DynamoDB + logs)
resource "aws_iam_role_policy" "lambda_policy" {
  name = "profile-inline"
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "DynamoDBAccess",
        Effect   = "Allow",
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem"],
        Resource = "arn:aws:dynamodb:${var.region}:${data.aws_caller_identity.current.account_id}:table/${var.project_prefix}-profiles"
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

# Lambda function
resource "aws_lambda_function" "profile" {
  function_name    = "${var.project_prefix}-profile"
  role             = aws_iam_role.lambda.arn
  handler          = "profile_handler.lambda_handler"
  runtime          = "python3.10"
  filename         = "${path.root}/../apps/lambda/profile_handler.zip"
  source_code_hash = filebase64sha256("${path.root}/../apps/lambda/profile_handler.zip")

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [var.lambda_security_group_id]
  }

  timeout     = 10
  memory_size = 128

  environment {
    variables = {
      TABLE_NAME = "${var.project_prefix}-profiles"
    }
  }

  tags = var.common_tags
}

# API Gateway (HTTP API) shared by app routes
resource "aws_apigatewayv2_api" "api" {
  name          = "${var.project_prefix}-api"
  protocol_type = "HTTP"
  tags          = var.common_tags
}

# JWT authorizer (Cognito)
resource "aws_apigatewayv2_authorizer" "jwt" {
  name             = "${var.project_prefix}-authorizer"
  api_id           = aws_apigatewayv2_api.api.id
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  jwt_configuration {
    issuer   = var.user_pool_issuer_url
    audience = [var.user_pool_client_id]
  }
}

# Lambda proxy integration
resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.profile.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

# Routes
resource "aws_apigatewayv2_route" "get_profile" {
  api_id             = aws_apigatewayv2_api.api.id
  route_key          = "GET /profile"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.jwt.id
}

resource "aws_apigatewayv2_route" "post_profile" {
  api_id             = aws_apigatewayv2_api.api.id
  route_key          = "POST /profile"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.jwt.id
}

# $default stage for instant deploys
resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.api.id
  name        = "$default"
  auto_deploy = true
}

# Allow API Gateway to invoke Lambda
resource "aws_lambda_permission" "allow_api" {
  function_name = aws_lambda_function.profile.function_name
  action        = "lambda:InvokeFunction"
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.api.execution_arn}/*/*"
}
resource "aws_lambda_function" "auth_exchange" {
  function_name    = "${var.project_prefix}-auth-exchange"
  filename         = data.archive_file.auth_exchange.output_path
  source_code_hash = data.archive_file.auth_exchange.output_base64sha256
  handler          = "auth_exchange.lambda_handler"
  runtime          = "python3.10"
  role             = aws_iam_role.lambda.arn

  environment {
    variables = {
      COGNITO_DOMAIN = "${var.project_prefix}-portal.auth.${var.region}.amazoncognito.com"
      CLIENT_ID      = var.user_pool_client_id
      REDIRECT_URI   = "https://${var.domain_name}/auth/callback"
    }
  }
}

resource "aws_apigatewayv2_route" "auth_exchange" {
  api_id    = aws_apigatewayv2_api.api.id
  route_key = "GET /auth/callback"
  target    = "integrations/${aws_apigatewayv2_integration.auth_exchange.id}"
}

resource "aws_apigatewayv2_integration" "auth_exchange" {
  api_id                 = aws_apigatewayv2_api.api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.auth_exchange.invoke_arn
  payload_format_version = "2.0"
}
