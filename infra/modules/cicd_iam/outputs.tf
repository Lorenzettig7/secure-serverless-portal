 output "deploy_role_arn" {
  value = aws_iam_role.deploy.arn
}

output "deploy_boundary_arn" {
  value = aws_iam_policy.deploy_boundary.arn
}

output "deploy_policy_arn" {
  value = aws_iam_policy.deploy_policy.arn
}
