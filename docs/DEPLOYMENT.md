# Scribe Cloud Deployment Guide

This document provides step-by-step instructions for deploying the Scribe application to AWS using the Terraform infrastructure-as-code setup.

## 🏗️ Infrastructure Overview

The deployment creates a complete, production-ready AWS infrastructure:

- **VPC & Networking**: Custom VPC with public/private subnets, NAT gateways
- **Application Load Balancer**: With SSL/TLS certificates and WAF protection
- **ECS Fargate**: Containerized backend services (Rust API + Qdrant vector DB)
- **RDS PostgreSQL**: Managed database with automated backups
- **ElastiCache Redis**: In-memory caching layer
- **Secrets Manager**: Secure credential storage
- **CloudWatch**: Monitoring, logging, and alerting
- **ECR Repositories**: Container image storage

## 🚀 Quick Start Deployment

### Step 1: Prerequisites

1. **Install Required Tools**:
   ```bash
   # AWS CLI (macOS)
   brew install awscli
   
   # Terraform
   brew install terraform
   ```

2. **Configure AWS Credentials**:
   ```bash
   ./scripts/terraform/configure-aws.sh
   ```
   This script will help you set up AWS CLI with the necessary permissions.

3. **Verify Prerequisites**:
   ```bash
   ./scripts/terraform/configure-aws.sh check
   ```

### Step 2: Configure Environment

1. **Copy Configuration Template**:
   ```bash
   cd terraform/environments/staging
   cp terraform.tfvars.example terraform.tfvars
   ```

2. **Edit Configuration**:
   ```bash
   vim terraform.tfvars  # or your preferred editor
   ```
   
   **Required Settings**:
   ```hcl
   # Domain configuration
   domain_name = "staging.scribe.sanguinehost.com"
   
   # API Keys (REQUIRED)
   gemini_api_key = "your-gemini-api-key-here"
   ```

   **Optional Settings** (defaults are usually fine):
   ```hcl
   aws_region = "us-east-1"
   environment = "staging"
   
   # Database settings
   db_instance_class = "db.t4g.micro"  # Free tier
   
   # ECS settings
   backend_cpu = 256      # 0.25 vCPU
   backend_memory = 512   # 512 MB
   ```

### Step 3: Deploy Infrastructure

1. **Run Deployment Script**:
   ```bash
   ./scripts/terraform/deploy-staging.sh
   ```
   
   This script will:
   - Initialize Terraform
   - Show deployment plan
   - Ask for confirmation
   - Apply infrastructure changes
   - Display deployment outputs

2. **Alternative Manual Deployment**:
   ```bash
   cd terraform/environments/staging
   terraform init
   terraform plan
   terraform apply
   ```

### Step 4: DNS Configuration (Automated)

DNS configuration is automated if you're using Route 53 for `sanguinehost.com`:

1. **Automatic DNS Updates**:
   - The deployment script automatically updates the CNAME record for `staging.scribe.sanguinehost.com`
   - Points to the new Application Load Balancer DNS name

2. **SSL Certificate Validation**:
   - SSL certificates are automatically validated via DNS
   - The process is handled by Terraform and AWS Certificate Manager

**Manual DNS Setup** (if using external DNS provider):
- Create CNAME record: `staging.scribe.sanguinehost.com` → `[ALB DNS Name from output]`

### Step 5: Deploy Application

1. **Deploy Backend** (Automated):
   ```bash
   ./scripts/deploy-backend.sh
   ```
   
   This script will:
   - Build the Docker image
   - Push to ECR
   - Update ECS service
   - Wait for deployment to complete

2. **Run Database Migrations**:
   ```bash
   ./scripts/run-migrations.sh
   ```

3. **Deploy Frontend**:
   ```bash
   cd frontend
   pnpm build
   pnpm vercel deploy --prebuilt --prod
   ```
   
   **Important**: After deploying to Vercel, you'll need to:
   - Note the new Vercel domain (e.g., `frontend-abc123-projects.vercel.app`)
   - Update the backend CORS configuration in `backend/src/main.rs` to include the new domain
   - Redeploy the backend: `./scripts/deploy-backend.sh backend`

## 📋 Post-Deployment Checklist

- [ ] Infrastructure deployed with Terraform
- [ ] DNS records automatically configured (Route 53)
- [ ] SSL certificate validated and issued
- [ ] Backend deployed and ECS services healthy
- [ ] Database migrations completed
- [ ] Frontend deployed to Vercel with correct API endpoint
- [ ] CORS configured for new Vercel domains
- [ ] SES email sending working (check sandbox limitations)
- [ ] Application accessible and functional via HTTPS

## 🎛️ Management Commands

### View Deployment Status
```bash
# View all outputs
terraform output

# View specific output
terraform output backend_ecr_repository_url

# Check deployment status
./scripts/terraform/deploy-staging.sh output
```

### Update Infrastructure
```bash
# Plan changes
./scripts/terraform/deploy-staging.sh plan

# Apply changes
./scripts/terraform/deploy-staging.sh deploy
```

### Destroy Environment
```bash
# ⚠️ This will permanently delete all resources!
./scripts/terraform/deploy-staging.sh destroy
```

## 🗄️ Database Administration via Tailscale

### Overview
The staging environment includes a Tailscale subnet router for secure database access without exposing the database to the public internet. This allows you to connect directly to the RDS PostgreSQL instance from your local machine.

### Setup Instructions

1. **Initial Tailscale Authentication** (already completed):
   - SSH into the EC2 instance: `ssh -i ~/.ssh/staging-scribe-key.pem ec2-user@44.201.185.0`
   - Run: `sudo tailscale up --advertise-routes=10.0.0.0/16`
   - Follow the authentication link and approve in Tailscale admin console

2. **Local Machine Setup**:
   - Install Tailscale on your local machine
   - Enable route acceptance: `sudo tailscale set --accept-routes`
   - Verify connectivity: `tailscale status`

3. **Database Connection**:
   - **From EC2 instance**: SSH to `ec2-user@10.0.1.79` and use the `./connect-db.sh` helper script
   - **Direct connection**: Use the RDS endpoint from terraform outputs
   - **Connection string**: Get credentials from AWS Secrets Manager or terraform state

### Common Database Tasks

```bash
# Connect to database via Tailscale subnet router
ssh -i ~/.ssh/staging-scribe-key.pem ec2-user@10.0.1.79

# Use the helper script on the EC2 instance
./connect-db.sh

# Or connect directly with psql (replace with actual credentials)
psql "postgresql://scribe_admin:PASSWORD@10.0.11.13:5432/scribe"

# Common database operations
\dt                    # List all tables
\d+ users             # Describe users table
SELECT * FROM users;  # Query users
TRUNCATE TABLE users; # Clear users table (careful!)
```

### Security Notes
- The Tailscale subnet router provides secure, encrypted access to the VPC
- Database is only accessible through Tailscale or from within the VPC
- RDS security group allows connections from:
  - Backend ECS tasks
  - Tailscale CGNAT range (100.64.0.0/10)
  - VPC CIDR range (10.0.0.0/16) for subnet router access

## 🔍 Monitoring & Troubleshooting

### Access Monitoring Dashboard
- CloudWatch Dashboard URL is provided in deployment outputs
- Monitor ALB, ECS, RDS, and Redis metrics

### View Logs
```bash
# ECS service logs
aws logs describe-log-groups --log-group-name-prefix /ecs/staging-scribe

# View specific log stream
aws logs get-log-events --log-group-name /ecs/staging-scribe-backend --log-stream-name [STREAM_NAME]
```

### Common Issues

1. **SSL Certificate Validation Timeout**:
   - Verify DNS validation records are added to Route 53
   - Check domain ownership and DNS propagation

2. **ECS Tasks Failing to Start**:
   - Check CloudWatch logs for container errors
   - Verify ECR image is pushed and accessible
   - Check task definition configuration

3. **Database Connection Issues**:
   - Verify security group configurations
   - Check database credentials in Secrets Manager
   - Ensure VPC networking is configured correctly

4. **Application Not Accessible**:
   - Check ALB health checks
   - Verify DNS configuration
   - Check WAF rules and security groups

## 📧 SES Email Configuration

### Sandbox Mode Limitation

AWS SES starts in sandbox mode, which has the following restrictions:
- Can only send emails to verified email addresses
- Daily sending quota of 200 emails
- Maximum send rate of 1 email per second

### For Development/Testing

If SES is in sandbox mode, you'll see errors like:
```
User is not authorized to perform `ses:SendEmail' on resource `arn:aws:ses:us-east-1:...:identity/user@example.com'
```

**Workaround for testing**:
1. Verify your test email address in SES console
2. Or request production access (see below)

### Request Production Access

For production use, request SES production access:

1. Go to AWS SES console
2. Navigate to "Account dashboard"
3. Click "Request production access"
4. Fill out the form explaining your use case
5. Approval typically takes 24-48 hours

### Current Configuration

The staging environment is configured with:
- Domain identity: `sanguinehost.com` (verified)
- Email identity: `noreply@sanguinehost.com` 
- Sending from: `noreply@sanguinehost.com`
- IAM policy: Allows sending to any recipient (when out of sandbox)

## 💰 Cost Optimization

The staging environment is configured for cost efficiency:

- **Free Tier Usage**: Uses t4g.micro instances where possible
- **Single AZ**: No Multi-AZ deployment for staging
- **Minimal Resources**: Small CPU/memory allocations
- **Reduced Backups**: 7-day retention instead of 30 days

**Estimated Monthly Cost**: $20-50 USD (depending on usage)

## 🔐 Security Features

- **Network Isolation**: All services in private subnets
- **Encryption**: At-rest and in-transit encryption enabled
- **Secrets Management**: AWS Secrets Manager for all credentials
- **WAF Protection**: Web Application Firewall with managed rules
- **Access Control**: Least-privilege IAM roles and security groups

## 📈 Scaling

### Vertical Scaling
Modify variables in `terraform.tfvars`:
```hcl
# Increase instance sizes
db_instance_class = "db.t4g.small"
redis_node_type = "cache.t4g.small"

# Increase ECS resources
backend_cpu = 512      # 0.5 vCPU
backend_memory = 1024  # 1 GB
```

### Horizontal Scaling
```hcl
# Increase number of ECS tasks
backend_desired_count = 2
qdrant_desired_count = 2

# Enable Multi-AZ for database
multi_az_enabled = true
```

## 🌟 Next Steps

1. **Set up CI/CD Pipeline**: Automate Docker builds and deployments
2. **Configure Monitoring Alerts**: Set up SNS notifications
3. **Implement Log Aggregation**: Centralize application logs
4. **Set up Backup Strategy**: Automate data backups
5. **Performance Testing**: Load test the infrastructure
6. **Security Hardening**: Implement additional security controls
7. **Create Production Environment**: Replicate for production with appropriate scaling

## 📞 Support

For issues or questions:
1. Check the troubleshooting section above
2. Review AWS CloudWatch logs and metrics
3. Consult the Terraform documentation in `/terraform/README.md`
4. Check the architecture documentation in `/docs/`

---

**🎉 Congratulations!** Your Scribe application infrastructure is now deployed and ready for development and testing.