# Tailscale Subnet Router Module

data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023*-x86_64"]
  }
}

resource "aws_security_group" "tailscale" {
  name        = "${var.environment}-scribe-tailscale-sg"
  description = "Security group for Tailscale subnet router"
  vpc_id      = var.vpc_id

  # Tailscale needs outbound access to everything
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow Tailscale communication (UDP 41641) for direct connections
  ingress {
    from_port   = 41641
    to_port     = 41641
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.environment}-scribe-tailscale-sg"
    Environment = var.environment
    Project     = "scribe"
  }
}

resource "aws_iam_role" "tailscale_role" {
  name = "${var.environment}-scribe-tailscale-role"

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
}

# Attach SSM managed instance core for remote access without SSH
resource "aws_iam_role_policy_attachment" "ssm_policy" {
  role       = aws_iam_role.tailscale_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "tailscale_profile" {
  name = "${var.environment}-scribe-tailscale-profile"
  role = aws_iam_role.tailscale_role.name
}

resource "aws_instance" "tailscale_router" {
  ami                         = data.aws_ami.amazon_linux_2023.id
  instance_type               = var.instance_type
  subnet_id                   = var.public_subnet_id
  vpc_security_group_ids      = [aws_security_group.tailscale.id]
  iam_instance_profile        = aws_iam_instance_profile.tailscale_profile.id
  key_name                    = var.key_name
  associate_public_ip_address = true

  # Essential for subnet routing
  source_dest_check = false

  user_data = <<-EOF
    #!/bin/bash
    set -e

    # Install Tailscale
    curl -fsSL https://tailscale.com/install.sh | sh

    # Enable IP forwarding (required for subnet routing)
    echo 'net.ipv4.ip_forward = 1' | tee -a /etc/sysctl.d/99-tailscale.conf
    echo 'net.ipv6.conf.all.forwarding = 1' | tee -a /etc/sysctl.d/99-tailscale.conf
    sysctl -p /etc/sysctl.d/99-tailscale.conf

    # Start Tailscale and authenticate
    # We use --advertise-routes to make the VPC CIDR reachable from the tailnet
    tailscale up --authkey=$${var.tailscale_auth_key} --advertise-routes=$${var.vpc_cidr} --snat-subnet-routes=false --accept-dns=false
  EOF

  tags = {
    Name        = "${var.environment}-scribe-tailscale-router"
    Environment = var.environment
    Project     = "scribe"
  }

  lifecycle {
    ignore_changes = [user_data]
  }
}
