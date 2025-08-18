#!/bin/bash
set -euo pipefail

# Update system
yum update -y

# Add SSH public key for additional access
echo "${ssh_public_key}" >> /home/ec2-user/.ssh/authorized_keys
chown ec2-user:ec2-user /home/ec2-user/.ssh/authorized_keys
chmod 600 /home/ec2-user/.ssh/authorized_keys

# Install Tailscale
curl -fsSL https://tailscale.com/install.sh | sh

# Install PostgreSQL client and utilities
amazon-linux-extras enable postgresql14
yum install -y postgresql jq

# Enable IP forwarding for subnet routing
echo 'net.ipv4.ip_forward = 1' | tee -a /etc/sysctl.d/99-tailscale.conf
echo 'net.ipv6.conf.all.forwarding = 1' | tee -a /etc/sysctl.d/99-tailscale.conf
sysctl -p /etc/sysctl.d/99-tailscale.conf

# Start Tailscale service
systemctl enable tailscaled
systemctl start tailscaled

# Wait for Tailscale to start
sleep 10

# Connect to Tailscale with auth key and advertise subnet routes
tailscale up --auth-key="${tailscale_auth_key}" --advertise-routes="${vpc_cidr}" --accept-routes --hostname="scribe-staging-db"

# Create database connection helper script
cat > /home/ec2-user/connect-db.sh << 'SCRIPT'
#!/bin/bash
# Get database URL from AWS Secrets Manager
SECRET_ARN="arn:aws:secretsmanager:${aws_region}:${aws_account_id}:secret:staging/scribe/database-4IK3zB"
DB_URL=$(aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" --region "${aws_region}" --query 'SecretString' --output text | jq -r '.url')

if [ -n "$DB_URL" ]; then
    echo "Connecting to staging database..."
    psql "$DB_URL"
else
    echo "Failed to get database URL from secrets manager"
    exit 1
fi
SCRIPT

# Create user clearing script
cat > /home/ec2-user/clear-users.sh << 'SCRIPT'
#!/bin/bash
SECRET_ARN="arn:aws:secretsmanager:${aws_region}:${aws_account_id}:secret:staging/scribe/database-4IK3zB"
DB_URL=$(aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" --region "${aws_region}" --query 'SecretString' --output text | jq -r '.url')

if [ -n "$DB_URL" ]; then
    echo "Clearing users from staging database..."
    psql "$DB_URL" << 'EOF'
DELETE FROM email_verification_tokens;
DELETE FROM users;
SELECT 'Remaining users:' as status, COUNT(*) as count FROM users;
SELECT 'Remaining tokens:' as status, COUNT(*) as count FROM email_verification_tokens;
EOF
    echo "✅ Database cleared successfully!"
else
    echo "❌ Failed to get database URL from secrets manager"
    exit 1
fi
SCRIPT

# Create user count checking script
cat > /home/ec2-user/check-users.sh << 'SCRIPT'
#!/bin/bash
SECRET_ARN="arn:aws:secretsmanager:${aws_region}:${aws_account_id}:secret:staging/scribe/database-4IK3zB"
DB_URL=$(aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" --region "${aws_region}" --query 'SecretString' --output text | jq -r '.url')

if [ -n "$DB_URL" ]; then
    echo "Checking user count in staging database..."
    psql "$DB_URL" << 'EOF'
SELECT 'Total users:' as status, COUNT(*) as count FROM users;
SELECT 'Verification tokens:' as status, COUNT(*) as count FROM email_verification_tokens;
SELECT 'Active users:' as status, COUNT(*) as count FROM users WHERE account_status = 'Active';
SELECT 'Pending users:' as status, COUNT(*) as count FROM users WHERE account_status = 'PendingVerification';
EOF
else
    echo "❌ Failed to get database URL from secrets manager"
    exit 1
fi
SCRIPT

# Set proper permissions and ownership for scripts
chmod +x /home/ec2-user/*.sh
chown ec2-user:ec2-user /home/ec2-user/*.sh

# Create a welcome message
cat > /home/ec2-user/README.txt << 'README'
Tailscale Subnet Router for Sanguine Scribe Staging

Available scripts:
- ./connect-db.sh    - Connect to PostgreSQL database via psql
- ./clear-users.sh   - Clear all users and verification tokens
- ./check-users.sh   - Check user count and status

Tailscale Status:
- Run 'tailscale status' to see connection status
- This machine advertises routes for ${vpc_cidr}
- Hostname: scribe-staging-db

To use these tools:
1. SSH in: ssh ec2-user@<tailscale-ip>
2. Run any script: ./clear-users.sh
3. Connect to DB: ./connect-db.sh

Database access is through the VPC subnet routes.
README

chown ec2-user:ec2-user /home/ec2-user/README.txt

echo "🎉 Tailscale subnet router setup complete!"
echo "📋 Check /home/ec2-user/README.txt for usage instructions"
echo "🔗 Tailscale status: $(tailscale status --json | jq -r '.Self.DNSName')"