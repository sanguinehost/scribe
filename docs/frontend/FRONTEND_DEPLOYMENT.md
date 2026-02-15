# Frontend Deployment to AWS ECS

This guide walks you through deploying Sanguine Scribe frontend to AWS ECS using Docker containers.

## Why ECS Instead of Vercel?

We migrated from Vercel to AWS ECS for better integration with our infrastructure:
- **Tailscale Integration**: ECS works seamlessly with our Tailscale network setup
- **Unified Domain**: Frontend and backend share the same domain and load balancer
- **Better Control**: Full control over the deployment environment
- **Cost Efficiency**: No third-party platform fees

## Prerequisites

1. **Backend Deployed**: Ensure your AWS backend infrastructure is deployed
2. **Docker Installed**: Docker or Podman for building images
3. **AWS CLI**: Configured with appropriate permissions

## Quick Start

### Deploy to Staging

```bash
./scripts/deploy-frontend.sh
```

This script handles everything:
1. Logs into Amazon ECR
2. Builds the frontend Docker image using `infrastructure/containers/frontend/Containerfile`
3. Pushes the image to ECR
4. Updates the ECS service to deploy the new image

## Manual Deployment Steps

If you need more control or are troubleshooting, here are the manual steps:

### 1. Build Frontend Image

```bash
cd /path/to/scribe

# Build with Podman (or Docker)
podman build -f infrastructure/containers/frontend/Containerfile \
  -t scribe-frontend:latest \
  -t 058264339990.dkr.ecr.ap-southeast-4.amazonaws.com/staging-scribe-frontend:latest \
  .
```

### 2. Push to ECR

```bash
# Login to ECR (handled by script)
aws ecr get-login-password --region ap-southeast-4 | \
  podman login --username AWS --password-stdin \
  058264339990.dkr.ecr.ap-southeast-4.amazonaws.com

# Push image
podman push 058264339990.dkr.ecr.ap-southeast-4.amazonaws.com/staging-scribe-frontend:latest
```

### 3. Update ECS Service

```bash
aws ecs update-service \
  --cluster staging-scribe-cluster \
  --service staging-scribe-frontend \
  --force-new-deployment \
  --region ap-southeast-4
```

## Architecture

### Frontend Containerfile

The frontend is built as a multi-stage Docker image:

**Stage 1: Build**
- Base image: `node:22-alpine`
- Installs pnpm
- Copies `frontend/package.json` and `frontend/pnpm-lock.yaml`
- Runs `pnpm install --frozen-lockfile`
- Copies entire `frontend/` directory
- Runs `pnpm build` to create production bundle

**Stage 2: Runtime**
- Base image: `node:22-alpine`
- Copies built files from stage 1
- Sets environment variables:
  - `NODE_ENV=production`
  - `PORT=3000`
- Exposes port 3000
- Runs with `node build`

### Networking

The frontend service is configured to:
- Run on Fargate (serverless containers)
- Use private subnets for security
- Accessible through the Application Load Balancer
- Share the same domain as the backend (`staging.scribe.sanguinehost.com`)

### Load Balancer Routing

The ALB is configured with path-based routing:
- `/` → Frontend container (port 3000)
- `/api/*` → Backend container (port 8080)

## Environment Configuration

### Build-Time Variables

Set environment variables during the build process:

```bash
# Enable/disable payment features
export PUBLIC_ENABLE_PAYMENTS=true

# Skip type checking for faster builds (CI/CD)
export VITE_BUILD_SKIP_TYPE_CHECK=true
```

These are set in the deployment script automatically.

### Runtime Configuration

The frontend reads configuration from:

1. **`PUBLIC_API_URL`**: Backend API endpoint
   - Set in build environment or runtime
   - Default: Uses same domain as frontend

2. **`PUBLIC_ENABLE_PAYMENTS`**: Show payment features
   - `true`: Enable Stripe integration
   - `false`: Hide payment UI

## Build Configuration

The project uses:
- **Adapter**: `@sveltejs/adapter-node` (not Vercel)
- **Output**: Node.js server build
- **Port**: 3000 (configurable via `PORT` env var)

Configuration in `frontend/svelte.config.js`:
```javascript
import adapter from '@sveltejs/adapter-node';

export default {
  kit: {
    adapter: adapter({
      env: {
        port: process.env.PORT || 3000
      }
    })
  }
};
```

## Deployment Checklist

- [ ] Backend infrastructure deployed via Terraform
- [ ] ECR repository exists for frontend
- [ ] ECS task definition configured for frontend
- [ ] ALB listener rules configured for path routing
- [ ] Target group created for frontend
- [ ] Security group allows port 3000 from ALB
- [ ] Frontend image builds successfully
- [ ] Frontend pushed to ECR
- [ ] ECS service updated with new image
- [ ] Health checks passing for frontend tasks
- [ ] Frontend accessible via domain

## Troubleshooting

### Container Won't Start

1. **Check CloudWatch Logs**:
   ```bash
   aws logs tail /ecs/staging-scribe-frontend --follow
   ```

2. **Common Issues**:
   - Port conflicts: Ensure no other process uses port 3000
   - Memory limits: Check if container has enough memory
   - Build errors: Verify `pnpm build` completed successfully

### Health Check Failures

1. **Verify Health Check Path**:
   - Default: `/` (root path)
   - Must return HTTP 200 status

2. **Check Target Group Health**:
   ```bash
   aws elbv2 describe-target-health \
     --target-group-arn $TARGET_GROUP_ARN
   ```

### Build Issues

1. **Test Build Locally**:
   ```bash
   cd frontend
   pnpm install
   pnpm build
   ```

2. **Check Dependencies**:
   - Ensure `pnpm-lock.yaml` is committed
   - Verify `package.json` is correct

### Routing Issues

If frontend routes don't work:

1. **Check ALB Listener Rules**:
   - Priority order matters
   - Path patterns: `/` for frontend, `/api/*` for backend

2. **Verify Container Port**:
   - Frontend must expose port 3000
   - Target group must forward to port 3000

## Monitoring

### CloudWatch Logs

Frontend logs are sent to CloudWatch:
- Log Group: `/ecs/staging-scribe-frontend`
- Contains server logs and any console output

### Metrics

Monitor in CloudWatch Dashboard:
- CPU utilization
- Memory utilization
- Request count
- Error rate
- Response time

### ECS Events

View ECS service events:
```bash
aws ecs describe-services \
  --cluster staging-scribe-cluster \
  --services staging-scribe-frontend \
  --query 'services[0].events'
```

## Local Testing

### Test Production Build Locally

```bash
# Build production version
cd frontend
pnpm build

# Run production build locally
PORT=3000 node build
```

### Test with Docker

```bash
# Build image
podman build -f infrastructure/containers/frontend/Containerfile -t test-frontend .

# Run container
podman run -p 3000:3000 test-frontend
```

Access at `http://localhost:3000`

## Cost Optimization

Current configuration:
- **Platform**: Fargate Spot (if available) or Fargate
- **vCPU**: 0.25 vCPU (256 units)
- **Memory**: 512 MB
- **Tasks**: 1 desired task

**Estimated Monthly Cost**: $5-15 USD

To reduce costs further:
- Use Fargate Spot instances
- Reduce task count to 0 when not in use
- Use smaller instance sizes

## Next Steps

1. **Set up CI/CD**: Automate builds and deployments
2. **Configure Auto Scaling**: Scale based on traffic
3. **Set up Monitoring**: CloudWatch alarms and SNS notifications
4. **Implement Blue-Green Deployments**: Zero-downtime deployments
5. **Add CDN**: CloudFront integration for static assets

---

**Note**: The frontend deployment uses the same domain, SSL certificate, and load balancer as the backend, providing a unified deployment experience.
