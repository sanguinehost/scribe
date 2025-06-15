# Simple Tailscale subnet router EC2 instance
# Based on official Tailscale AWS guide: https://tailscale.com/kb/1021/install-aws-ec2

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
  
  # User data script for initial setup
  user_data = base64encode(<<-EOF
#!/bin/bash
yum update -y

# Install Tailscale
curl -fsSL https://tailscale.com/install.sh | sh

# Install PostgreSQL client for DB access
amazon-linux-extras enable postgresql14
yum install -y postgresql jq

# Enable IP forwarding
echo 'net.ipv4.ip_forward = 1' | tee -a /etc/sysctl.d/99-tailscale.conf
echo 'net.ipv6.conf.all.forwarding = 1' | tee -a /etc/sysctl.d/99-tailscale.conf
sysctl -p /etc/sysctl.d/99-tailscale.conf

# Enable Tailscale service
systemctl enable tailscaled
systemctl start tailscaled

# Create helper script for database connection
cat > /home/ec2-user/connect-db.sh << 'SCRIPT'
#!/bin/bash
# Get database URL from AWS Secrets Manager
SECRET_ARN="arn:aws:secretsmanager:us-east-1:058264339990:secret:staging/scribe/database-4IK3zB"
DB_URL=$(aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" --query 'SecretString' --output text | jq -r '.url')

if [ -n "$DB_URL" ]; then
    echo "Connecting to database..."
    psql "$DB_URL"
else
    echo "Failed to get database URL from secrets manager"
    exit 1
fi
SCRIPT

chmod +x /home/ec2-user/connect-db.sh
chown ec2-user:ec2-user /home/ec2-user/connect-db.sh

echo "Tailscale subnet router setup complete!"
echo "Next steps:"
echo "1. SSH into this instance: ssh ec2-user@$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)"
echo "2. Run: sudo tailscale up --advertise-routes=${var.vpc_cidr}"
echo "3. Follow the authentication link"
echo "4. In Tailscale admin console, authorize the subnet routes"
echo "5. Use ./connect-db.sh to connect to the database"
EOF
)

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