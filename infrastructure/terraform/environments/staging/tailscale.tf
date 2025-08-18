# Simple Tailscale subnet router EC2 instance
# Based on official Tailscale AWS guide: https://tailscale.com/kb/1021/install-aws-ec2

# Variables for dynamic configuration
variable "ssh_public_key_path" {
  description = "Path to SSH public key file for additional access"
  type        = string
  default     = "~/.ssh/id_rsa.pub"
}

variable "tailscale_auth_key" {
  description = "Tailscale auth key for automatic connection"
  type        = string
  sensitive   = true
}

# Data source for latest Amazon Linux 2 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
  
  filter {
    name   = "state"
    values = ["available"]
  }
}

# IAM role for Tailscale EC2 instance to access secrets
resource "aws_iam_role" "tailscale_ec2_role" {
  name = "${var.environment}-tailscale-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "${var.environment}-tailscale-ec2-role"
    Environment = var.environment
    Project     = "scribe"
  }
}

# IAM policy for accessing secrets manager
resource "aws_iam_role_policy" "tailscale_secrets_access" {
  name = "${var.environment}-tailscale-secrets-access"
  role = aws_iam_role.tailscale_ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:staging/scribe/database-*"
        ]
      }
    ]
  })
}

# Instance profile for the EC2 instance
resource "aws_iam_instance_profile" "tailscale_ec2_profile" {
  name = "${var.environment}-tailscale-ec2-profile"
  role = aws_iam_role.tailscale_ec2_role.name

  tags = {
    Name        = "${var.environment}-tailscale-ec2-profile"
    Environment = var.environment
    Project     = "scribe"
  }
}

# Security group for Tailscale subnet router
resource "aws_security_group" "tailscale_sg" {
  name_prefix = "${var.environment}-tailscale-subnet-router"
  description = "Security group for Tailscale subnet router"
  vpc_id      = module.networking.vpc_id

  # SSH access for initial setup (remove after setup)
  ingress {
    description = "SSH for initial setup"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # All outbound traffic
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.environment}-tailscale-subnet-router"
    Environment = var.environment
    Project     = "scribe"
  }
}

# Tailscale subnet router EC2 instance
resource "aws_instance" "tailscale_router" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t3.micro"  # Free tier eligible
  key_name                    = var.ec2_key_pair_name  # You'll need to add this variable
  subnet_id                   = module.networking.public_subnet_ids[0]
  vpc_security_group_ids      = [aws_security_group.tailscale_sg.id]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.tailscale_ec2_profile.name
  
  # User data script using template file with dynamic variables
  user_data = base64encode(templatefile("${path.module}/tailscale-setup.sh.tpl", {
    vpc_cidr           = var.vpc_cidr
    tailscale_auth_key = var.tailscale_auth_key
    ssh_public_key     = file(pathexpand(var.ssh_public_key_path))
    aws_region         = var.aws_region
    aws_account_id     = data.aws_caller_identity.current.account_id
  }))

  tags = {
    Name        = "${var.environment}-tailscale-subnet-router"
    Environment = var.environment
    Project     = "scribe"
    Purpose     = "tailscale-subnet-router"
  }
}

# Output the connection instructions
output "tailscale_setup_instructions" {
  description = "Instructions to complete Tailscale setup"
  value = <<-EOT
Tailscale Subnet Router Setup:

1. SSH into the instance:
   ssh -i ~/.ssh/your-key.pem ec2-user@${aws_instance.tailscale_router.public_ip}

2. Start Tailscale with subnet routing:
   sudo tailscale up --advertise-routes=${var.vpc_cidr}

3. Follow the authentication link in your browser

4. In your Tailscale admin console (https://login.tailscale.com/admin/machines):
   - Find your new subnet router
   - Disable key expiry
   - Authorize subnet routes for ${var.vpc_cidr}

5. Install Tailscale on your local machine and connect

6. Once connected, you can access the database from your local machine using:
   ./connect-db.sh (on the EC2 instance)
   
   Or directly with the database endpoint: ${module.rds.rds_instance_endpoint}

Instance Public IP: ${aws_instance.tailscale_router.public_ip}
Tailscale will assign it an IP in the 100.x.x.x range once configured.
EOT
}