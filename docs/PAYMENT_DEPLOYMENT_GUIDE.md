# Payment System Deployment Guide

This guide covers deploying the Sanguine Scribe payment system to production.

## Prerequisites

1. **Paddle Account**: Create a production Paddle vendor account at https://vendors.paddle.com
2. **SSL Certificate**: HTTPS is required for payment processing
3. **PostgreSQL Database**: With payment tables migrated
4. **Environment Variables**: Properly configured for production

## Deployment Checklist

### 1. Paddle Configuration

#### Create Products in Paddle Dashboard
1. Log into your Paddle vendor account
2. Navigate to Catalog → Products
3. Create the following products:
   - **Basic Subscription** ($10/month)
   - **Premium Subscription** ($25/month)
   - **Credit Packages** (250, 550, 1500, 3500, 8000 credits)
4. Note the Price IDs for each product

#### Update Configuration File
Edit `backend/config/subscription_tiers.json`:
- Replace `paddle_price_id` values with your actual Paddle Price IDs
- Verify pricing matches Paddle configuration

#### Set Up Webhooks
1. In Paddle Dashboard, go to Developer Tools → Webhooks
2. Add webhook endpoint: `https://your-domain.com/api/payment/webhook/paddle`
3. Subscribe to events:
   - `subscription_created`
   - `subscription_updated`
   - `subscription_cancelled`
   - `transaction_completed`
   - `transaction_failed`
4. Copy the webhook secret

### 2. Environment Configuration

Update your production `.env` file:

```env
# Paddle Production Credentials
PAYMENT_PADDLE_API_KEY=your_production_api_key
PAYMENT_PADDLE_WEBHOOK_SECRET=your_webhook_secret
PAYMENT_PADDLE_SANDBOX_MODE=false  # IMPORTANT: Set to false

# Production URLs
PAYMENT_PAYMENT_BASE_URL=https://your-domain.com
FRONTEND_BASE_URL=https://your-domain.com

# Enable Payment Features
PAYMENT_CREDITS_ENABLED=true
PAYMENT_SOFT_LIMITS_ENABLED=true
PAYMENT_ENFORCE_LIMITS=true  # IMPORTANT: Set to true

# Production Limits
PAYMENT_FREE_TIER_TOKEN_LIMIT=50000
PAYMENT_GRACE_PERIOD_DAYS=7
PAYMENT_MAX_CREDIT_BALANCE=100000
```

### 3. Database Migration

Run migrations to create payment tables:

```bash
cd backend
diesel migration run
```

Verify tables exist:
- `subscriptions`
- `user_credits`
- `credit_transactions`
- `credit_packages`
- `daily_usage_tracking`
- `payment_transactions`
- `payment_audit_logs`

### 4. Frontend Deployment

Ensure frontend environment has payment feature enabled:

```env
PUBLIC_ENABLE_PAYMENTS=true
PUBLIC_PADDLE_VENDOR_ID=your_vendor_id
PUBLIC_PADDLE_SANDBOX=false  # Production mode
```

### 5. Security Verification

#### Pre-deployment Security Checklist
- [ ] All payment endpoints require authentication
- [ ] Webhook signature validation is enabled
- [ ] Rate limiting is configured for payment endpoints
- [ ] Encryption keys are securely stored
- [ ] Database connections use SSL
- [ ] Audit logging is enabled

#### OWASP Compliance Verification
- [ ] A01: Access control - All payment routes protected
- [ ] A02: Cryptographic failures - Sensitive data encrypted
- [ ] A03: Injection - Using parameterized queries
- [ ] A07: Authentication - Session validation on all endpoints
- [ ] A08: Data integrity - Webhook signatures validated
- [ ] A09: Logging - Audit trail for all transactions

### 6. Testing Production Setup

#### Initial Verification
1. Check scheduler is running:
   ```bash
   tail -f logs/app.log | grep scheduler
   ```
   Should see:
   - "Starting payment scheduler for periodic tasks..."
   - "Daily usage reset scheduled for..."
   - "Monthly credit allocation scheduled for..."

2. Test webhook endpoint:
   ```bash
   curl -X POST https://your-domain.com/api/payment/webhook/paddle \
     -H "Content-Type: application/json" \
     -d '{"event_type": "test"}'
   ```
   Should return 401 (invalid signature)

3. Verify API endpoints are accessible:
   ```bash
   # Should return 401 (requires auth)
   curl https://your-domain.com/api/payment/subscription
   curl https://your-domain.com/api/payment/credits/balance
   ```

#### End-to-End Testing
1. Create a test user account
2. Verify free tier limits work
3. Purchase Basic subscription with test card
4. Verify subscription is activated
5. Check monthly credits are allocated
6. Test credit purchase flow
7. Verify daily usage reset at midnight UTC

### 7. Monitoring Setup

#### Key Metrics to Monitor
- Payment success/failure rates
- Credit balance anomalies
- Daily active subscribers by tier
- Soft limit trigger frequency
- Webhook processing errors
- Scheduler task execution

#### Recommended Alerts
- Payment failure rate > 5%
- Webhook endpoint down
- Scheduler tasks not running
- Database connection pool exhausted
- Unusual credit consumption patterns

### 8. Rollback Plan

If issues occur after deployment:

1. **Disable payment enforcement** (immediate):
   ```env
   PAYMENT_ENFORCE_LIMITS=false
   PAYMENT_CREDITS_ENABLED=false
   PAYMENT_SOFT_LIMITS_ENABLED=false
   ```

2. **Grant credits to affected users**:
   ```sql
   UPDATE user_credits
   SET balance = balance + 1000
   WHERE user_id IN (SELECT user_id FROM subscriptions WHERE status = 'active');
   ```

3. **Pause Paddle webhooks** in dashboard

4. **Investigate and fix issues**

5. **Re-enable gradually** with monitoring

## Common Issues & Solutions

### Webhook Signature Validation Failures
- Verify webhook secret matches exactly
- Check for trailing newlines in environment variable
- Ensure webhook URL is exact match (no trailing slash)

### Credits Not Allocating
- Check scheduler logs for errors
- Verify `last_credit_grant` timestamps
- Ensure subscription status is 'active'
- Check timezone configuration (should be UTC)

### Soft Limits Not Working
- Verify `PAYMENT_SOFT_LIMITS_ENABLED=true`
- Check `daily_usage_tracking` table has records
- Ensure usage reset is running at midnight UTC

### Payment Processing Errors
- Verify Paddle API key is valid
- Check API key has correct permissions
- Ensure sandbox mode is disabled
- Verify SSL certificates are valid

## Appendix: SQL Queries for Monitoring

### Check subscription distribution
```sql
SELECT plan_type, status, COUNT(*)
FROM subscriptions
GROUP BY plan_type, status;
```

### Daily revenue tracking
```sql
SELECT DATE(created_at), SUM(total_cents)/100 as revenue
FROM payment_transactions
WHERE status = 'completed'
GROUP BY DATE(created_at)
ORDER BY DATE(created_at) DESC;
```

### Credit usage patterns
```sql
SELECT
    DATE(created_at) as day,
    SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END) as credits_added,
    SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END) as credits_used,
    COUNT(DISTINCT user_id) as unique_users
FROM credit_transactions
WHERE created_at > NOW() - INTERVAL '30 days'
GROUP BY DATE(created_at);
```

### Users hitting soft limits
```sql
SELECT COUNT(DISTINCT user_id) as throttled_users
FROM daily_usage_tracking
WHERE soft_limit_triggered_at IS NOT NULL
  AND date = CURRENT_DATE;
```

---

Last Updated: 2025-09-21
Version: 1.0.0