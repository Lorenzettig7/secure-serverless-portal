data "aws_caller_identity" "current" {}

data "archive_file" "profile_zip" {
  type        = "zip"
  source_file = "${path.root}/../apps/lambda/profile_handler.py"
  output_path = "${path.module}/build/profile_handler.zip"
}
data "archive_file" "auth_exchange" {
  type        = "zip"
  source_file = "${path.root}/../apps/lambda/auth_exchange.py"
  output_path = "${path.module}/build/auth_exchange.zip"
}
data "archive_file" "findings_zip" {
  type        = "zip"
  source_file = "${path.root}/../apps/lambda/findings_handler.py"
  output_path = "${path.module}/build/findings_handler.zip"
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
resource "aws_iam_role_policy" "lambda_dynamodb" {
  name = "${var.project_prefix}-profile-ddb"
  role = aws_iam_role.lambda.id  # or whatever your profile Lambda role is called

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # 1) Existing DynamoDB access
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
        ]
        Resource = var.profiles_table_arn
      },

      # 2) NEW: allow writing raw profile JSON to S3
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
        ]
        Resource = "arn:aws:s3:::${var.profiles_raw_bucket_name}/profiles/*"
      },

      # 3) NEW: allow encrypting with your CMK
      {
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
        ]
        Resource = var.portal_kms_key_arn
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_kms" {
  name = "${var.project_prefix}-profile-kms"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = var.profiles_kms_key_arn
      }
    ]
  })
}
resource "aws_iam_role_policy" "findings_kms" {
  name = "${var.project_prefix}-findings-kms"
  role = aws_iam_role.findings_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = [
        "kms:Decrypt"
      ],
      Resource = var.profiles_kms_key_arn  # or whatever var you already use for the portal CMK
    }]
  })
}

# Lambda function
# findings_handler Lambda (in app_profile or a new app_findings module)
resource "aws_lambda_function" "findings" {
  function_name    = "${var.project_prefix}-findings"
  role             = aws_iam_role.findings_role.arn
  filename         = data.archive_file.findings_zip.output_path
  source_code_hash = data.archive_file.findings_zip.output_base64sha256
  handler          = "findings_handler.handler"
  runtime          = "python3.11"
  timeout          = 10

  environment {
    variables = {
    ALLOWED_ORIGIN      = var.allowed_origin
    PORTAL_BUCKET_NAME  = var.portal_bucket_name
    PROFILES_TABLE_NAME = var.profiles_table_name
    WAF_WEBACL_ARN      = var.waf_web_acl_arn
    WAF_SAMPLE_RULE     = "Default_Action"
    }
  }

  tags = var.common_tags
}

resource "aws_lambda_function" "profile" {
  function_name    = "${var.project_prefix}-profile"
  role             = aws_iam_role.lambda.arn
  filename         = data.archive_file.profile_zip.output_path
  source_code_hash = data.archive_file.profile_zip.output_base64sha256
  handler          = "profile_handler.handler"
  runtime          = "python3.10"

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [var.lambda_security_group_id]
  }

  timeout     = 10
  memory_size = 128

  environment {
    variables = {
      TABLE_NAME     = var.profiles_table_name
      ISSUER_URL     = var.user_pool_issuer_url
      CLIENT_ID      = var.user_pool_client_id
      ALLOWED_ORIGIN = "https://portal.secureschoolcloud.org"
      PROFILE_RAW_BUCKET = var.profiles_raw_bucket_name
      PK_NAME        = "id"
    }
  }

  tags = var.common_tags
}
resource "aws_iam_role_policy" "profile_least" {
  name = "${var.project_prefix}-profile-least"
  role = aws_iam_role.lambda.name # or aws_iam_role.profile.name if you used a different role resource

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "ProfilesTableRW",
        Effect   = "Allow",
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"],
        Resource = var.profiles_table_arn # see note below
      },
      {
        Sid      = "Logging",
        Effect   = "Allow",
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"],
        Resource = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${aws_lambda_function.profile.function_name}:*"

      }
    ]
  })
}

# API Gateway (HTTP API) shared by app routes
resource "aws_apigatewayv2_api" "api" {
  name          = "ssp-telemetry-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_credentials = true
    allow_headers     = ["authorization", "content-type"]
    allow_methods     = ["GET", "POST", "OPTIONS"]
    allow_origins     = ["https://portal.secureschoolcloud.org"]
    max_age           = 0
  }
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
resource "aws_apigatewayv2_integration" "findings" {
  api_id                 = aws_apigatewayv2_api.api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.findings.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}


resource "aws_apigatewayv2_route" "get_findings" {
  api_id             = aws_apigatewayv2_api.api.id
  route_key          = "GET /findings"
  target             = "integrations/${aws_apigatewayv2_integration.findings.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.jwt.id
}

resource "aws_apigatewayv2_route" "resolve_finding" {
  api_id             = aws_apigatewayv2_api.api.id
  route_key          = "POST /findings/resolve"
  target             = "integrations/${aws_apigatewayv2_integration.findings.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.jwt.id
}


resource "aws_lambda_permission" "allow_api_findings" {
  statement_id  = "AllowAPIGatewayInvokeFindings"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.findings.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.api.execution_arn}/*/*"
}


resource "aws_iam_role" "findings_role" {
  name               = "${var.project_prefix}-findings-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = var.common_tags
}

resource "aws_iam_role_policy_attachment" "findings_basic" {
  role       = aws_iam_role.findings_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "findings_policy" {
  name = "${var.project_prefix}-findings-ddb"
  role = aws_iam_role.findings_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["dynamodb:Query", "dynamodb:Scan", "dynamodb:UpdateItem"],
        Resource = var.findings_table_arn
      },
      {
        Effect   = "Allow",
        Action   = ["dynamodb:Query"],
        Resource = "${var.findings_table_arn}/index/by_user"
      }
    ]
  })
}
