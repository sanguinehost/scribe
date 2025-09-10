# Payment System Deployment Guide

This guide covers deploying the payment system with Paddle integration to staging and production environments.

## Overview

The payment system is implemented with feature flags and can be enabled/disabled per environment:
- **Backend**: Feature-gated with `#[cfg(feature = "payment")]` in Rust code
- **Frontend**: Feature-gated with `PUBLIC_ENABLE_PAYMENTS` environment variable
- **Terraform**: Optional payment variables that can be omitted to disable payments entirely

## Prerequisites

1. **Paddle Account**: Set up a Paddle account and obtain:
   - Paddle API Key (sandbox and production)
   - Paddle Webhook Secret
   - Price IDs for your subscription plans

2. **Domain Setup**: Ensure your domain is properly configured:
   - `staging.scribe.sanguinehost.com` for staging
   - `scribe.sanguinehost.com` for production

## Staging Deployment

### 1. Backend Infrastructure (Terraform)

1. **Copy terraform configuration**:
   ```bash
   cd infrastructure/terraform/environments/staging
   cp terraform.tfvars.example terraform.tfvars
   ```

2. **Enable payment variables** in `terraform.tfvars`:
   ```hcl
   # Payment configuration
   enable_payments = true
   paddle_api_key = "pdl_sdbx_your_sandbox_api_key_here"
   paddle_webhook_secret = "your_webhook_secret_here"
   paddle_sandbox_mode = true
   enforce_payment_limits = false  # Keep disabled for staging testing
   ```

3. **Deploy infrastructure**:
   ```bash
   ./scripts/terraform/deploy-staging.sh
   ```

### 2. Backend Application Deployment

1. **Build with payment features**:
   ```bash
   cd backend
   cargo build --release --features payment
   ```

2. **Deploy to ECS** (assuming ECR is set up):
   ```bash
   # Build and push Docker image
   docker build -t backend --build-arg FEATURES="payment" .
   docker tag backend:latest your-ecr-url:latest
   docker push your-ecr-url:latest
   
   # Update ECS service
   aws ecs update-service --cluster staging-scribe --service backend --force-new-deployment
   ```

### 3. Frontend Deployment (Vercel)

1. **Set Vercel environment variables**:
   ```bash
   # Via Vercel CLI
   vercel env add PUBLIC_ENABLE_PAYMENTS
   # Enter: true
   
   # Or via Vercel Dashboard:
   # Project Settings > Environment Variables
   # PUBLIC_ENABLE_PAYMENTS = true
   ```

2. **Deploy to Vercel**:
   ```bash
   cd frontend
   pnpm build
   vercel deploy --prod
   ```

### 4. Test Payment Flow

1. **Access staging application**: https://staging.scribe.sanguinehost.com
2. **Go to pricing page**: /pricing
3. **Click "Subscribe to Pro"** - should redirect to Paddle checkout
4. **Complete test payment** in Paddle sandbox
5. **Verify redirect** to `/pay` page with transaction ID
6. **Check backend logs** for webhook processing

## Production Deployment

Production deployment follows the same steps but with different configuration:

### Terraform Variables (production)
```hcl
enable_payments = true
paddle_api_key = "pdl_live_your_production_api_key_here"
paddle_webhook_secret = "your_production_webhook_secret_here"
paddle_sandbox_mode = false
enforce_payment_limits = true  # Enable for production
```

### Domain Configuration
- Frontend: `scribe.sanguinehost.com`
- Backend API: `api.scribe.sanguinehost.com`
- Payment completion: `scribe.sanguinehost.com/pay`

## Environment Variables Reference

### Backend (via AWS Secrets Manager)
- `PAYMENT_PADDLE_API_KEY`: Paddle API key
- `PAYMENT_PADDLE_WEBHOOK_SECRET`: Webhook signature verification
- `PAYMENT_PADDLE_SANDBOX_MODE`: "true" for sandbox, "false" for production
- `PAYMENT_PAYMENT_BASE_URL`: Base URL for redirects (computed from domain)
- `PAYMENT_ENFORCE_LIMITS`: "true" to enforce subscription limits
- `PAYMENT_FREE_TIER_TOKEN_LIMIT`: Monthly limit for free users
- `PAYMENT_GRACE_PERIOD_DAYS`: Days after subscription expires

### Frontend (Vercel Environment Variables)
- `PUBLIC_ENABLE_PAYMENTS=true`: Enables payment features in frontend

## Troubleshooting

### Common Issues

1. **"Payments are not enabled"** error:
   - Check `PUBLIC_ENABLE_PAYMENTS` environment variable is set to "true"
   - Verify frontend build includes the environment variable

2. **Paddle.js not loading**:
   - Check browser console for script loading errors
   - Verify PaddleLoader component is included in main layout

3. **Webhook signature verification fails**:
   - Ensure webhook secret matches between Paddle dashboard and backend config
   - Check backend logs for signature computation details

4. **Checkout URL not working**:
   - Verify Paddle API key has correct permissions
   - Check backend logs for transaction creation errors
   - Ensure price IDs in database match Paddle dashboard

5. **Database migration issues**:
   - Run payment table migrations: `diesel migration run`
   - Check backend starts with payment feature enabled

### Logs to Check

- **Backend**: ECS CloudWatch logs for payment route processing
- **Frontend**: Browser console for Paddle.js errors
- **Terraform**: Apply logs for secret creation and ECS deployment
- **Paddle**: Webhook delivery logs in Paddle dashboard

### Feature Flag Testing

To test without payments:
1. Set `enable_payments = false` in terraform.tfvars
2. Set `PUBLIC_ENABLE_PAYMENTS=false` in Vercel
3. Backend will compile without payment routes
4. Frontend will show "Payments Not Available" buttons

## Security Considerations

1. **Secrets Management**:
   - Never commit API keys to git
   - Use AWS Secrets Manager for backend secrets
   - Use Vercel environment variables for frontend configs

2. **Webhook Security**:
   - Always verify webhook signatures using HMAC-SHA256
   - Use different webhook secrets for staging and production

3. **Domain Verification**:
   - Ensure payment completion URLs match your registered domains
   - Validate redirect URLs to prevent open redirect attacks

4. **Testing**:
   - Use Paddle sandbox for all non-production environments
   - Test webhook signature verification regularly
   - Monitor payment processing errors