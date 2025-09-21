#!/bin/bash

# Payment System Health Check Script
# This script verifies that all payment system components are properly configured

echo "======================================"
echo "Payment System Health Check"
echo "======================================"
echo ""

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check functions
check_pass() {
    echo -e "${GREEN}✓${NC} $1"
}

check_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

check_fail() {
    echo -e "${RED}✗${NC} $1"
}

echo "1. Checking Environment Configuration..."
echo "-----------------------------------------"

# Check if .env exists
if [ -f .env ]; then
    check_pass ".env file exists"
else
    check_fail ".env file not found"
    exit 1
fi

# Check Paddle API credentials
if grep -q "PAYMENT_PADDLE_API_KEY=pdl_" .env; then
    check_pass "Paddle API key configured"
else
    check_fail "Paddle API key not configured"
fi

if grep -q "PAYMENT_PADDLE_WEBHOOK_SECRET=" .env && ! grep -q "PAYMENT_PADDLE_WEBHOOK_SECRET=$" .env; then
    check_pass "Paddle webhook secret configured"
else
    check_warn "Paddle webhook secret might not be configured"
fi

# Check sandbox mode
if grep -q "PAYMENT_PADDLE_SANDBOX_MODE=true" .env; then
    check_warn "Running in SANDBOX mode (good for testing)"
else
    check_pass "Running in PRODUCTION mode"
fi

# Check feature flags
if grep -q "CREDITS_ENABLED=true\|PAYMENT_CREDITS_ENABLED=true" .env; then
    check_pass "Credits system enabled"
else
    check_fail "Credits system disabled"
fi

if grep -q "SOFT_LIMITS_ENABLED=true\|PAYMENT_SOFT_LIMITS_ENABLED=true" .env; then
    check_pass "Soft limits enabled"
else
    check_warn "Soft limits disabled"
fi

echo ""
echo "2. Checking Database Tables..."
echo "-----------------------------------------"

# Check if database is accessible and has payment tables
if command -v psql &> /dev/null; then
    # Extract database URL from .env
    DB_URL=$(grep "^DATABASE_URL=" .env | cut -d'=' -f2- | tr -d '"')

    if [ ! -z "$DB_URL" ]; then
        # Check for payment tables
        TABLES=$(psql "$DB_URL" -t -c "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename IN ('subscriptions', 'user_credits', 'credit_transactions', 'credit_packages', 'daily_usage_tracking', 'payment_transactions');" 2>/dev/null | wc -l)

        if [ "$TABLES" -ge 6 ]; then
            check_pass "All payment tables exist ($TABLES/6)"
        else
            check_warn "Some payment tables missing ($TABLES/6)"
        fi
    else
        check_warn "Could not verify database tables (DATABASE_URL not found)"
    fi
else
    check_warn "psql not available, skipping database check"
fi

echo ""
echo "3. Checking Configuration Files..."
echo "-----------------------------------------"

# Check subscription tiers config
if [ -f "backend/config/subscription_tiers.json" ]; then
    check_pass "Subscription tiers configuration exists"

    # Check if it has the required structure
    if grep -q '"free"' backend/config/subscription_tiers.json && \
       grep -q '"basic"' backend/config/subscription_tiers.json && \
       grep -q '"premium"' backend/config/subscription_tiers.json; then
        check_pass "All subscription tiers defined"
    else
        check_warn "Some subscription tiers might be missing"
    fi

    # Check if Paddle price IDs are configured
    if grep -q 'pri_[0-9a-z]\+' backend/config/subscription_tiers.json; then
        check_pass "Paddle price IDs configured"
    else
        check_warn "Paddle price IDs might not be configured"
    fi
else
    check_fail "Subscription tiers configuration not found"
fi

echo ""
echo "4. Checking Backend Compilation..."
echo "-----------------------------------------"

# Check if payment feature compiles
cd backend 2>/dev/null || { check_fail "Backend directory not found"; exit 1; }

if cargo check --features payment --quiet 2>/dev/null; then
    check_pass "Backend compiles with payment feature"
else
    check_fail "Backend compilation failed with payment feature"
fi

cd .. 2>/dev/null

echo ""
echo "5. Checking Frontend Configuration..."
echo "-----------------------------------------"

# Check if frontend has payment components
if [ -d "frontend/src/lib/components/membership" ]; then
    check_pass "Membership components exist"
else
    check_fail "Membership components not found"
fi

if [ -f "frontend/src/lib/stores/subscription.svelte.ts" ]; then
    check_pass "Subscription store exists"
else
    check_fail "Subscription store not found"
fi

if [ -f "frontend/src/lib/stores/credits.ts" ]; then
    check_pass "Credits store exists"
else
    check_fail "Credits store not found"
fi

echo ""
echo "6. System Status Summary..."
echo "-----------------------------------------"

# Check if backend is running
if curl -s http://localhost:8080/health > /dev/null 2>&1; then
    check_pass "Backend server is running"

    # Check if payment endpoints respond
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/payment/subscription/plans)
    if [ "$STATUS" = "200" ]; then
        check_pass "Payment API endpoints accessible"
    else
        check_warn "Payment API returned status $STATUS (might need auth)"
    fi
else
    check_warn "Backend server not running (start with 'cargo run' in backend/)"
fi

# Check if frontend is running
if curl -s http://localhost:5173 > /dev/null 2>&1; then
    check_pass "Frontend server is running"
else
    check_warn "Frontend server not running (start with 'pnpm dev' in frontend/)"
fi

echo ""
echo "======================================"
echo "Health Check Complete"
echo "======================================"
echo ""
echo "Next Steps:"
echo "-----------"
echo "1. If using sandbox, test a purchase at http://localhost:5173"
echo "2. Check logs: tail -f backend/logs/*.log"
echo "3. Monitor scheduler: grep 'scheduler' backend/logs/*.log"
echo "4. View deployment guide: docs/PAYMENT_DEPLOYMENT_GUIDE.md"
echo ""