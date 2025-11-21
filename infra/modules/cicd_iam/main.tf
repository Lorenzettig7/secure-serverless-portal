//////////////////////////////
// CICD IAM (GitHub Actions)
//////////////////////////////

terraform {
  required_version = ">= 1.5.0"
}

# Who am I?
data "aws_caller_identity" "current" {}

#############################
# GitHub OIDC provider
#############################
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  # Current recommended thumbprint for token.actions.githubusercontent.com
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

#############################
# Trust policy for GitHub OIDC
#############################
data "aws_iam_policy_document" "deploy_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:Lorenzettig7/secure-serverless-portal:*"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}


#############################
# Deploy role used by GitHub Actions
#############################
resource "aws_iam_role" "deploy" {
  name                 = "ssp-github-deploy-role"
  description          = "Role assumed by GitHub Actions via OIDC to deploy ${var.project_prefix}"
  assume_role_policy   = data.aws_iam_policy_document.deploy_assume.json
  permissions_boundary = aws_iam_policy.deploy_boundary.arn
}

#####################################
# Permissions Boundary (Safety Rails)
#####################################
resource "aws_iam_policy" "deploy_boundary" {
  name        = "ssp-deploy-boundary"
  path        = "/"
  description = "Boundary limiting what the GitHub deploy role can do"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # --- Read-only across services used by plan/apply ---
      {
        Sid    = "ReadOnlyAcrossServices"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",

          "iam:Get*",
          "iam:List*",
          "iam:SimulatePrincipalPolicy",
          "iam:DetachRolePolicy",
          "iam:CreatePolicyVersion ",

          "sts:GetCallerIdentity",

          # CloudTrail
          "cloudtrail:Describe*",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:ListTags",

          # CloudWatch Logs / Config
          "logs:Describe*",
          "logs:Get*",
          "logs:ListTagsForResource*",
          "config:Describe*",
          "config:Get*",
          "config:ListTagsForResource",

          # Security services
          "guardduty:GetDetector",
          "securityhub:DescribeHub",
          "securityhub:GetEnabledStandards",
          "access-analyzer:GetAnalyzer",

          # Route 53 / ACM / API Gateway
          "route53:List*",
          "route53:Get*",
          "acm:ListCertificates",
          "acm:DescribeCertificate",
          "acm:ListTagsForCertificate",
          "apigateway:GET",
          

          # CloudFront (including tag reads)
          "cloudfront:GetDistribution",
          "cloudfront:ListDistributions",
          "cloudfront:GetInvalidation",
          "cloudfront:DescribeFunction",
          "cloudfront:GetFunction",
          "cloudfront:GetCloudFrontOriginAccessIdentity",
          "cloudfront:ListTagsForResource",

          # Lambda (including code signing config)
          "lambda:GetFunction",
          "lambda:GetFunctionConfiguration",
          "lambda:ListVersionsByFunction",
          "lambda:GetFunctionCodeSigningConfig",
          "lambda:GetPolicy",

          # SSM Parameter Store (including tags)
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath",
          "ssm:DescribeParameters",
          "ssm:ListTagsForResource",

          # KMS
          "kms:DescribeKey",
          "kms:ListAliases",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
          "kms:ListResourceTags",

          "dynamodb:DescribeTable",
          "dynamodb:DescribeContinuousBackups",
          "dynamodb:DescribeTimeToLive",
          "dynamodb:ListTagsOfResource",

          # SNS (including subscription attributes + tags)
          "sns:GetTopicAttributes",
          "sns:GetSubscriptionAttributes",
          "sns:ListTagsForResource",

          # EventBridge (including targets + tags)
          "events:DescribeRule",
          "events:ListTagsForResource",
          "events:ListTargetsByRule",

          # Cognito (including MFA + client + domain reads)
          "cognito-idp:DescribeUserPool",
          "cognito-idp:GetUserPoolMfaConfig",
          "cognito-idp:DescribeUserPoolClient",
          "cognito-idp:DescribeUserPoolDomain"
        ]
        Resource = "*"
      },
      # --- Allow creation of project buckets (logs + web) ---
      {
        Sid    = "AllowProjectBucketCreation"
        Effect = "Allow"
        Action = [
          "s3:CreateBucket"
        ]
        Resource = [
          "arn:aws:s3:::ssp-logs-713881788173",
          "arn:aws:s3:::ssp-web-713881788173"
        ]
      },

      # --- Allow Terraform to manage inline policies on the deploy role itself ---
      {
        Sid    = "ManageDeployRoleInlinePolicies"
        Effect = "Allow"
        Action = [
          "iam:DeleteRolePolicy",
          "iam:PutRolePolicy"
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/ssp-github-deploy-role"
      },

      # --- Backend S3 state bucket ---
      {
        Sid    = "TfstateS3"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:PutBucketVersioning",
          "s3:PutBucketPublicAccessBlock",
          "s3:DeleteBucketPolicy",
          "s3:PutEncryptionConfiguration",
          "s3:DeleteBucketPolicy",
        ]
        Resource = "arn:aws:s3:::${var.tfstate_bucket}"
      },
      {
        Sid    = "TfstateS3Objects"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:PutBucketVersioning",
          "s3:PutBucketPublicAccessBlock",
          "s3:DeleteBucketPolicy",
          "s3:PutEncryptionConfiguration",
          "s3:DeleteBucketPolicy",
        ]
        Resource = "arn:aws:s3:::${var.tfstate_bucket}/${var.tfstate_key_prefix}*"
      },

      # --- S3 bucket posture reads ---
      {
        Sid    = "LogsBucketPostureReads"
        Effect = "Allow"
        Action = [
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketVersioning",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketPolicy"
        ]
        Resource = "arn:aws:s3:::ssp-logs-713881788173"
      },

      {
        Sid    = "TfstateS3PostureReads"
        Effect = "Allow"
        Action = [
          "s3:GetBucketPolicy",
          "s3:GetBucketVersioning",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketPublicAccessBlock"
        ]
        Resource = "arn:aws:s3:::${var.tfstate_bucket}"
      },

      # Web bucket posture reads (for ssp-web-<account>)
      {
        Sid    = "WebBucketPostureReads"
        Effect = "Allow"
        Action = [
          "s3:GetBucketPolicy",
          "s3:GetBucketVersioning",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketPublicAccessBlock"
        ]
        Resource = "arn:aws:s3:::ssp-web-713881788173"
      },

      # --- DynamoDB lock table for Terraform ---
      {
        Sid    = "TfLockDDB"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem",
          "dynamodb:DescribeTable"
        ]
        Resource = "arn:aws:dynamodb:${var.region}:${data.aws_caller_identity.current.account_id}:table/${var.tf_lock_table}"
      },

      # --- CloudFront invalidation for web deploy ---
      {
        Sid    = "CloudFrontInvalidate"
        Effect = "Allow"
        Action = [
          "cloudfront:CreateInvalidation"
        ]
        Resource = "*"
      },

      # --- Pass only project-scoped roles (your Lambda exec roles, etc.) ---
      {
        Sid    = "AllowPassProjectRoles"
        Effect = "Allow"
        Action = [
          "iam:PassRole"
        ]
        Resource = "arn:aws:iam::*:role/ssp-*"
      },

      # --- Read OIDC provider so the action can assume the role ---
      {
        Sid    = "OIDCRead"
        Effect = "Allow"
        Action = [
          "iam:GetOpenIDConnectProvider",
          "iam:ListOpenIDConnectProviders"
        ]
        Resource = "*"
      },

            # --- Manage posture on logs and web buckets ---
      {
       Sid    = "AllowAllS3OnProjectBuckets"
       Effect = "Allow"
       Action = "s3:*"
       Resource = [
         "arn:aws:s3:::ssp-logs-713881788173",
         "arn:aws:s3:::ssp-logs-713881788173/*",
         "arn:aws:s3:::ssp-web-713881788173",
         "arn:aws:s3:::ssp-web-713881788173/*",
         "arn:aws:s3:::ssp-tfstate-giovanna-73048814",
         "arn:aws:s3:::ssp-tfstate-giovanna-73048814/*"
  ]
},
      # --- Allow WAFv2 for CloudFront WebACLs ---
      {
        Sid    = "AllowWafv2ForCloudFront"
        Effect = "Allow"
        Action = [
          "wafv2:CreateWebACL",
          "wafv2:UpdateWebACL",
          "wafv2:DeleteWebACL",
          "wafv2:GetWebACL",
          "wafv2:ListWebACLs",
          "wafv2:ListResourcesForWebACL",
          "wafv2:AssociateWebACL",
          "wafv2:DisassociateWebACL",
          "wafv2:TagResource",
          "wafv2:ListTagsForResource",
          "wafv2:UntagResource",
          "wafv2:PutLoggingConfiguration",
          "wafv2:DeleteLoggingConfiguration",
          "wafv2:GetLoggingConfiguration"
        ]
        Resource = "*"
        # "arn:aws:wafv2:us-east-1:${data.aws_caller_identity.current.account_id}:global/webacl/*"
      },

      # --- Allow Terraform to replace its own deploy policies ---
      {
        Sid    = "ManageDeployPolicies"
        Effect = "Allow"
        Action = [
          "iam:CreatePolicy",
          "iam:DeletePolicy",
         "iam:GetPolicy",
         "iam:UpdateAssumeRolePolicy",
         "iam:CreatePolicyVersion",
         "iam:DeletePolicyVersion"
         
        ]
        Resource = [
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/ssp-deploy-boundary",
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/ssp-deploy-policy",
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/ssp-github-deploy-role"
        ]
      },

      # --- Tag the GitHub OIDC provider (for Env/Owner/Project) ---
      {
        Sid    = "TagGithubOIDCProvider"
        Effect = "Allow"
        Action = [
          "iam:TagOpenIDConnectProvider",
          "iam:UntagOpenIDConnectProvider"
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"
      }
    ]
  })
}

##############################################
# Broad deploy policy (boundary keeps it safe)
##############################################
resource "aws_iam_policy" "deploy_policy" {
  name        = "${var.project_prefix}-deploy-policy"
  description = "Effective permissions used by the GitHub deploy role (constrained by boundary)"

  # Boundary above provides the safety guardrails.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowEverythingWithinBoundary"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
resource "aws_iam_role_policy" "deploy_lock_ddb" {
  name = "${var.project_prefix}-deploy-ddb-lock"
  role = aws_iam_role.deploy.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowTerraformStateLockTable"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem",
          "dynamodb:DescribeTable"
        ]
        Resource = "arn:aws:dynamodb:${var.region}:${data.aws_caller_identity.current.account_id}:table/${var.tf_lock_table}"
      }
    ]
  })
}
resource "aws_iam_role_policy" "deploy_inline" {
  name = "${var.project_prefix}-deploy-inline"
  role = aws_iam_role.deploy.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowTypicalDeploy"
        Effect = "Allow"
        Action = [
          # Core services your Terraform touches
          "ec2:*",
          "iam:*",
          "route53:*",
          "acm:*",
          "apigateway:*",
          "apigatewayv2:*",
          "lambda:*",
          "logs:*",
          "s3:*",
          "kms:*",
          "ssm:*",
          "dynamodb:*",
          "events:*",
          "sns:*",
          "cloudfront:*",
          "cognito-idp:*",
          "config:*",
          "guardduty:*",
          "securityhub:*",
          "access-analyzer:*",
          "wafv2:*",
          "cloudtrail:*",
          "config:*"

        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "deploy_attach" {
  role       = aws_iam_role.deploy.name
  policy_arn = aws_iam_policy.deploy_policy.arn
}
