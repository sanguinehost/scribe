#!/bin/bash
set -e

# Configuration
# Environment configuration
REGION=${AWS_REGION:-"ap-southeast-4"}
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Resource identifiers (adjust if necessary)
SECRET_SUFFIX=${SECRET_SUFFIX:-"database-tXXaO7"}
SECRET_ID="arn:aws:secretsmanager:$REGION:$ACCOUNT_ID:secret:staging/scribe/$SECRET_SUFFIX"
ROUTER_TAG="staging-scribe-tailscale-router"

# RDS Configuration
RDS_IDENTIFIER=${RDS_IDENTIFIER:-"staging-scribe-postgres.c9oy0o248kqw"}
DB_HOST="$RDS_IDENTIFIER.$REGION.rds.amazonaws.com"
DB_PORT="5432"
LOCAL_PORT="54320"
DB_NAME="scribe"
DB_USER="scribe_admin"
TARGET_USER="privacy_test_user"

echo "Fetching Instance ID for SSM Tunnel..."
INSTANCE_ID=$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=$ROUTER_TAG" \
    --query "Reservations[0].Instances[0].InstanceId" --output text --region $REGION)

if [ -z "$INSTANCE_ID" ]; then
    echo "Error: Could not find instance with tag $ROUTER_TAG"
    exit 1
fi
echo "Instance ID: $INSTANCE_ID"

echo "Fetching DB Password..."
DB_PASSWORD=$(aws secretsmanager get-secret-value \
    --secret-id $SECRET_ID \
    --region $REGION \
    --query SecretString --output text | jq -r .password)

if [ -z "$DB_PASSWORD" ]; then
    echo "Error: Could not retrieve password"
    exit 1
fi

echo "Starting SSM Tunnel on port $LOCAL_PORT..."
aws ssm start-session \
    --target $INSTANCE_ID \
    --document-name AWS-StartPortForwardingSessionToRemoteHost \
    --parameters "{\"host\":[\"$DB_HOST\"],\"portNumber\":[\"$DB_PORT\"], \"localPortNumber\":[\"$LOCAL_PORT\"]}" \
    --region $REGION > /dev/null 2>&1 &

TUNNEL_PID=$!
echo "Tunnel started with PID $TUNNEL_PID. Waiting 10s for connection..."
sleep 10

echo "Updating user status in database..."
export PGPASSWORD="$DB_PASSWORD"
psql "postgresql://$DB_USER@localhost:$LOCAL_PORT/$DB_NAME?sslmode=require" -c "UPDATE users SET account_status = 'active' WHERE username = '$TARGET_USER';"

echo "Closing tunnel..."
kill $TUNNEL_PID
echo "Done."
