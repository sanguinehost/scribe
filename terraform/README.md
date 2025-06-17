# Scribe Infrastructure

This directory contains the Terraform infrastructure-as-code for the Scribe application, implementing the cloud architecture described in `/docs/CLOUD_ARCHITECTURE.md` and `/docs/HOSTING_PLAN.md`.

## Architecture Overview

The infrastructure implements a modern, scalable, and secure cloud architecture:

- **Frontend**: SvelteKit application deployed on Vercel
- **Backend**: Rust application running on AWS Fargate (ECS)
- **Databases**: PostgreSQL (RDS) and Qdrant vector database (Fargate)
- **Caching**: Redis (ElastiCache)
- **Networking**: Custom VPC with public/private subnets, NAT gateways
- **Security**: WAF, Security Groups, Secrets Manager, SSL/TLS
- **Monitoring**: CloudWatch dashboards and alarms

## Directory Structure

```
terraform/
├── environments/
│   └── staging/               # Staging environment configuration
│       ├── main.tf           # Main configuration calling modules
│       ├── variables.tf      # Variable definitions
│       ├── outputs.tf        # Output definitions
│       └── terraform.tfvars.example  # Example configuration
└── modules/                   # Reusable Terraform modules
    ├── networking/           # VPC, subnets, security groups
    ├── ecs/                  # ECS cluster, services, ECR
    ├── rds/                  # PostgreSQL RDS and Redis ElastiCache
    ├── secrets/              # AWS Secrets Manager
    ├── alb/                  # Application Load Balancer and WAF
    └── monitoring/           # CloudWatch dashboards and alarms
```

## Prerequisites

1. **AWS CLI**: Install and configure with appropriate credentials
   ```bash
   aws configure
   ```

2. **Terraform**: Install Terraform >= 1.0
   ```bash
   # macOS
   brew install terraform
   
   # Or download from https://www.terraform.io/downloads.html
   ```

3. **Domain Setup**: Ensure your domain (sanguinehost.com) is configured in Route 53

4. **API Keys**: Obtain necessary API keys (Gemini, etc.)

## Quick Start

### 1. Configure Variables

Copy the example configuration and customize it:

```bash
cd terraform/environments/staging
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your specific values:

```hcl
# Required: Set your domain and API keys
domain_name = "staging.scribe.sanguinehost.com"
gemini_api_key = "your-gemini-api-key-here"

# Optional: Customize other settings as needed
aws_region = "ap-southeast-4"
environment = "staging"
```

### 2. Deploy Infrastructure

Use the provided deployment script:

```bash
# Deploy the staging environment
./scripts/terraform/deploy-staging.sh

# Or just plan to see what will be created
./scripts/terraform/deploy-staging.sh plan
```

Or run Terraform commands directly:

```bash
cd terraform/environments/staging
terraform init
terraform plan
terraform apply
```

### 3. Configure DNS

After deployment, configure DNS records in Route 53:

1. **CNAME Record**: Point your domain to the ALB DNS name
2. **SSL Validation**: Add certificate validation DNS records

The deployment script will show you the exact DNS records needed.

### 4. Deploy Application

1. **Build Docker Images**:
   ```bash
   # Build and push backend image to ECR
   docker build -t backend ./backend
   docker tag backend:latest <ecr-repo-url>:latest
   docker push <ecr-repo-url>:latest
   ```

2. **Update ECS Services**: The services will automatically pull and deploy the new images

3. **Run Migrations**: Connect to the RDS instance and run database migrations

## Environment Configuration

### Staging Environment

The staging environment is optimized for cost savings:

- Single-AZ deployment (no Multi-AZ RDS)
- Smaller instance sizes (t4g.micro for RDS/Redis)
- Reduced backup retention
- Minimal monitoring
- Single ECS task instances

### Production Environment (Future)

To create a production environment:

1. Copy the staging directory structure
2. Adjust variables for production requirements:
   - Multi-AZ RDS deployment
   - Larger instance sizes
   - Enhanced monitoring
   - Multiple ECS task instances
   - Extended backup retention

## Security Features

- **Network Isolation**: Private subnets for all application components
- **Encryption**: At-rest and in-transit encryption for all data stores
- **Secrets Management**: AWS Secrets Manager for all credentials
- **WAF Protection**: Web Application Firewall with managed rule sets
- **Rate Limiting**: Protection against DDoS attacks
- **Security Groups**: Least-privilege network access rules

## Monitoring & Observability

- **CloudWatch Dashboards**: Comprehensive monitoring of all components
- **Alarms**: Automated alerts for critical thresholds
- **Log Aggregation**: Centralized logging via CloudWatch Logs
- **Metrics**: Performance and health metrics for all services

## Cost Optimization

The infrastructure is designed for cost efficiency:

- **Free Tier Usage**: Leverages AWS free tier where possible
- **Minimal Resource Allocation**: Right-sized for staging workloads
- **Auto-scaling**: Configured for future scaling needs
- **Spot Instances**: Can be enabled for non-critical workloads

## Disaster Recovery

- **Automated Backups**: RDS and Redis automated backups
- **Point-in-Time Recovery**: RDS supports PITR
- **Multi-AZ Option**: Can be enabled for high availability
- **Infrastructure as Code**: Complete environment can be recreated

## Maintenance

### Updating Infrastructure

1. Modify Terraform configuration
2. Plan changes: `terraform plan`
3. Apply changes: `terraform apply`

### Scaling

- **Vertical Scaling**: Modify instance sizes in variables
- **Horizontal Scaling**: Adjust desired task counts
- **Auto-scaling**: Configure ECS auto-scaling policies

### Destroying Environment

⚠️ **CAUTION**: This will permanently delete all resources!

```bash
# Using the script
./scripts/terraform/deploy-staging.sh destroy

# Or directly
cd terraform/environments/staging
terraform destroy
```

## Troubleshooting

### Common Issues

1. **DNS Validation Timeout**: Ensure DNS records are properly configured
2. **ECS Task Startup Failures**: Check CloudWatch logs for container errors
3. **Database Connection Issues**: Verify security group configurations
4. **SSL Certificate Issues**: Confirm DNS validation records

### Useful Commands

```bash
# Check deployment status
terraform show

# View specific outputs
terraform output backend_ecr_repository_url

# Refresh state
terraform refresh

# Import existing resources (if needed)
terraform import aws_instance.example i-1234567890abcdef0
```

## Support

For issues or questions:

1. Check the troubleshooting section above
2. Review AWS CloudWatch logs
3. Consult the architecture documentation in `/docs/`
4. Create an issue in the project repository

## Security Notes

- Never commit `terraform.tfvars` files containing secrets
- Use environment variables for sensitive values
- Regularly rotate secrets and API keys
- Monitor AWS CloudTrail for security events
- Keep Terraform and AWS CLI updated