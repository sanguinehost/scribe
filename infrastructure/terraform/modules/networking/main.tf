# Networking module for Scribe application
# Creates VPC, subnets, NAT gateways, internet gateway, and security groups

# Data source for availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

# VPC
resource "aws_vpc" "scribe_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.environment}-scribe-vpc"
    Environment = var.environment
    Project     = "scribe"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "scribe_igw" {
  vpc_id = aws_vpc.scribe_vpc.id

  tags = {
    Name        = "${var.environment}-scribe-igw"
    Environment = var.environment
    Project     = "scribe"
  }
}

# Public Subnets (for ALB and NAT gateways)
resource "aws_subnet" "public_subnets" {
  count = length(var.public_subnet_cidrs)

  vpc_id                  = aws_vpc.scribe_vpc.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name        = "${var.environment}-scribe-public-subnet-${count.index + 1}"
    Environment = var.environment
    Project     = "scribe"
    Type        = "public"
  }
}

# Private Subnets (for Fargate, RDS)
resource "aws_subnet" "private_subnets" {
  count = length(var.private_subnet_cidrs)

  vpc_id            = aws_vpc.scribe_vpc.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name        = "${var.environment}-scribe-private-subnet-${count.index + 1}"
    Environment = var.environment
    Project     = "scribe"
    Type        = "private"
  }
}

# Elastic IPs for NAT Gateways
resource "aws_eip" "nat_gw_eips" {
  count = length(var.public_subnet_cidrs)

  domain = "vpc"

  tags = {
    Name        = "${var.environment}-scribe-nat-eip-${count.index + 1}"
    Environment = var.environment
    Project     = "scribe"
  }

  depends_on = [aws_internet_gateway.scribe_igw]
}

# NAT Gateways
resource "aws_nat_gateway" "scribe_nat_gws" {
  count = length(var.public_subnet_cidrs)

  allocation_id = aws_eip.nat_gw_eips[count.index].id
  subnet_id     = aws_subnet.public_subnets[count.index].id

  tags = {
    Name        = "${var.environment}-scribe-nat-gw-${count.index + 1}"
    Environment = var.environment
    Project     = "scribe"
  }

  depends_on = [aws_internet_gateway.scribe_igw]
}

# Route table for public subnets
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.scribe_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.scribe_igw.id
  }

  tags = {
    Name        = "${var.environment}-scribe-public-rt"
    Environment = var.environment
    Project     = "scribe"
  }
}

# Route table associations for public subnets
resource "aws_route_table_association" "public_rta" {
  count = length(aws_subnet.public_subnets)

  subnet_id      = aws_subnet.public_subnets[count.index].id
  route_table_id = aws_route_table.public_rt.id
}

# Route tables for private subnets
resource "aws_route_table" "private_rts" {
  count = length(var.private_subnet_cidrs)

  vpc_id = aws_vpc.scribe_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.scribe_nat_gws[count.index].id
  }

  tags = {
    Name        = "${var.environment}-scribe-private-rt-${count.index + 1}"
    Environment = var.environment
    Project     = "scribe"
  }
}

# Route table associations for private subnets
resource "aws_route_table_association" "private_rta" {
  count = length(aws_subnet.private_subnets)

  subnet_id      = aws_subnet.private_subnets[count.index].id
  route_table_id = aws_route_table.private_rts[count.index].id
}

# Security Group for ALB
resource "aws_security_group" "alb_sg" {
  name_prefix = "${var.environment}-scribe-alb-"
  vpc_id      = aws_vpc.scribe_vpc.id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.environment}-scribe-alb-sg"
    Environment = var.environment
    Project     = "scribe"
  }
}

# Security Group for Backend ECS Tasks
resource "aws_security_group" "backend_sg" {
  name_prefix = "${var.environment}-scribe-backend-"
  vpc_id      = aws_vpc.scribe_vpc.id

  ingress {
    description     = "HTTP from ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.environment}-scribe-backend-sg"
    Environment = var.environment
    Project     = "scribe"
  }
}

# Security Group for Qdrant ECS Tasks
resource "aws_security_group" "qdrant_sg" {
  name_prefix = "${var.environment}-scribe-qdrant-"
  vpc_id      = aws_vpc.scribe_vpc.id

  ingress {
    description     = "Qdrant HTTP port from backend"
    from_port       = 6333
    to_port         = 6333
    protocol        = "tcp"
    security_groups = [aws_security_group.backend_sg.id]
  }

  ingress {
    description     = "Qdrant gRPC port from backend"
    from_port       = 6334
    to_port         = 6334
    protocol        = "tcp"
    security_groups = [aws_security_group.backend_sg.id]
  }

  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.environment}-scribe-qdrant-sg"
    Environment = var.environment
    Project     = "scribe"
  }
}

# Security Group for RDS
resource "aws_security_group" "rds_sg" {
  name_prefix = "${var.environment}-scribe-rds-"
  vpc_id      = aws_vpc.scribe_vpc.id

  ingress {
    description     = "PostgreSQL from backend"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.backend_sg.id]
  }

  # Allow access from Tailscale network (100.64.0.0/10 is the default Tailscale CGNAT range)
  ingress {
    description = "PostgreSQL from Tailscale network"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["100.64.0.0/10"]
  }

  # Allow access from Tailscale router EC2 instance
  ingress {
    description = "PostgreSQL from Tailscale router"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]  # Allow from entire VPC for subnet router access
  }

  tags = {
    Name        = "${var.environment}-scribe-rds-sg"
    Environment = var.environment
    Project     = "scribe"
  }
}


# Security Group for EFS
resource "aws_security_group" "efs_sg" {
  name_prefix = "${var.environment}-scribe-efs-"
  vpc_id      = aws_vpc.scribe_vpc.id

  ingress {
    description     = "NFS from Qdrant"
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.qdrant_sg.id]
  }

  tags = {
    Name        = "${var.environment}-scribe-efs-sg"
    Environment = var.environment
    Project     = "scribe"
  }
}