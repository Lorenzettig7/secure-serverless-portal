resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(var.common_tags, { Name = "${var.project_prefix}-vpc" })
}


resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "${var.region}a"
  tags              = merge(var.common_tags, { Name = "${var.project_prefix}-private-a" })
}


resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "${var.region}b"
  tags              = merge(var.common_tags, { Name = "${var.project_prefix}-private-b" })
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  tags   = merge(var.common_tags, { Name = "${var.project_prefix}-rt-private" })
}

resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private.id
}
resource "aws_security_group" "lambda_sg" {
  name        = "${var.project_prefix}-lambda-sg"
  description = "Minimal egress for Lambda"
  vpc_id      = aws_vpc.main.id


  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }


  tags = merge(var.common_tags, { Name = "${var.project_prefix}-lambda-sg" })
}


resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  tags              = merge(var.common_tags, { Name = "${var.project_prefix}-s3-endpoint" })
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  tags              = merge(var.common_tags, { Name = "${var.project_prefix}-dynamodb-endpoint" })
}
# Security group for interface endpoints (allow HTTPS from Lambda SG)
resource "aws_security_group" "vpce_endpoints_sg" {
  name        = "${var.project_prefix}-vpce-sg"
  description = "SG for Interface VPC Endpoints"
  vpc_id      = aws_vpc.main.id

  # Lambda SG egress is already 443-anywhere; allow inbound from the VPC on 443
  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# CloudTrail interface endpoint
resource "aws_vpc_endpoint" "cloudtrail" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.cloudtrail"
  vpc_endpoint_type   = "Interface"
  security_group_ids  = [aws_security_group.vpce_endpoints_sg.id]
  subnet_ids          = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  private_dns_enabled = true
}

# CloudWatch Logs interface endpoint
resource "aws_vpc_endpoint" "logs" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.logs"
  vpc_endpoint_type   = "Interface"
  security_group_ids  = [aws_security_group.vpce_endpoints_sg.id]
  subnet_ids          = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  private_dns_enabled = true
}
