locals {
  role_name   = "${var.project_prefix}-github-deploy-role"
  boundary_nm = "${var.project_prefix}-deploy-boundary"
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# 1) GitHub OIDC provider (create once per account; idempotent)
resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"] # GitHub’s OIDC root CA
  tags = var.common_tags
}

# 2) Permission Boundary for the deploy role (tight but demo-friendly)
data "aws_iam_policy_document" "deploy_boundary" {
  # Allow CRUD for core services in this project
  statement {
    sid     = "AllowCoreServices"
    effect  = "Allow"
    actions = [
      "s3:*",
      "cloudfront:*",
      "wafv2:*",
      "acm:*",
      "route53:*",
      "logs:*",
      "lambda:*",
      "apigateway:*",
      "cognito-idp:*",
      "dynamodb:*",
      "kms:*",
      "events:*",
      "sns:*",
      "ssm:*",
      "iam:PassRole"
    ]
    resources = ["*"]
  }

  # Deny risky account-wide mutations
  statement {
    sid    = "DenyAccountWideDanger"
    effect = "Deny"
    actions = [
      "organizations:*",
      "account:*",
      "iam:CreateUser",
      "iam:CreateAccessKey",
      "iam:DeleteRolePolicy",
      "iam:DeleteUser",
      "iam:PutUserPolicy",
      "iam:AttachUserPolicy",
      "iam:UpdateAssumeRolePolicy"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "deploy_boundary" {
  name        = local.boundary_nm
  policy      = data.aws_iam_policy_document.deploy_boundary.json
  tags        = var.common_tags
}

# 3) Deploy role (assumed by GitHub Actions via OIDC)
data "aws_iam_policy_document" "deploy_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    # Limit to this repo (any branch/ref)
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_owner}/${var.github_repo}:*"]
    }
  }
}

resource "aws_iam_role" "deploy" {
  name                 = local.role_name
  assume_role_policy   = data.aws_iam_policy_document.deploy_trust.json
  permissions_boundary = aws_iam_policy.deploy_boundary.arn
  tags                 = var.common_tags
}

# Inline policy (scoped deploy powers)
data "aws_iam_policy_document" "deploy_inline" {
  statement {
    sid     = "AllowTypicalDeploy"
    effect  = "Allow"
    actions = [
      "s3:*",
      "cloudfront:*",
      "wafv2:*",
      "acm:*",
      "route53:*",
      "logs:*",
      "lambda:*",
      "apigateway:*",
      "cognito-idp:*",
      "dynamodb:*",
      "kms:*",
      "events:*",
      "sns:*",
      "ssm:*"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "deploy_inline" {
  role   = aws_iam_role.deploy.id
  name   = "${var.project_prefix}-deploy-inline"
  policy = data.aws_iam_policy_document.deploy_inline.json
}
