output "private_subnet_ids" {
  value = [aws_subnet.private_a.id, aws_subnet.private_b.id]
}


output "lambda_security_group_id" {
  value = aws_security_group.lambda_sg.id
}