#!/bin/bash
set -euo pipefail

# Update ECS task definition to add COOKIE_DOMAIN environment variable
# This fixes cross-subdomain cookie sharing for staging environment

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
AWS_REGION="ap-southeast-4"
ECS_CLUSTER="staging-scribe-cluster"
BACKEND_SERVICE="staging-scribe-backend"
TASK_FAMILY="staging-scribe-backend"

echo -e "${BLUE}[INFO]${NC} Updating backend task definition to add COOKIE_DOMAIN..."

# Get the current task definition
echo -e "${BLUE}[INFO]${NC} Fetching current task definition..."
CURRENT_TASK_DEF=$(aws ecs describe-task-definition \
    --task-definition $TASK_FAMILY \
    --region $AWS_REGION \
    --query 'taskDefinition')

# Extract container definitions and add COOKIE_DOMAIN
echo -e "${BLUE}[INFO]${NC} Adding COOKIE_DOMAIN environment variable..."
UPDATED_CONTAINER_DEFS=$(echo "$CURRENT_TASK_DEF" | jq '.containerDefinitions[0].environment += [{"name": "COOKIE_DOMAIN", "value": ".staging.scribe.sanguinehost.com"}]' | jq '.containerDefinitions')

# Create new task definition
echo -e "${BLUE}[INFO]${NC} Creating new task definition..."
NEW_TASK_DEF=$(echo "$CURRENT_TASK_DEF" | jq \
    --argjson containerDefs "$UPDATED_CONTAINER_DEFS" \
    'del(.taskDefinitionArn, .revision, .status, .requiresAttributes, .compatibilities, .registeredAt, .registeredBy) | .containerDefinitions = $containerDefs')

# Register the new task definition
echo -e "${BLUE}[INFO]${NC} Registering new task definition..."
NEW_REVISION=$(aws ecs register-task-definition \
    --cli-input-json "$NEW_TASK_DEF" \
    --region $AWS_REGION \
    --query 'taskDefinition.revision' \
    --output text)

echo -e "${GREEN}[SUCCESS]${NC} New task definition registered: $TASK_FAMILY:$NEW_REVISION"

# Update the service to use the new task definition
echo -e "${BLUE}[INFO]${NC} Updating ECS service with new task definition..."
aws ecs update-service \
    --cluster $ECS_CLUSTER \
    --service $BACKEND_SERVICE \
    --task-definition "$TASK_FAMILY:$NEW_REVISION" \
    --force-new-deployment \
    --region $AWS_REGION \
    --output text > /dev/null

echo -e "${GREEN}[SUCCESS]${NC} ECS service updated successfully!"
echo -e "${BLUE}[INFO]${NC} The service is now deploying with COOKIE_DOMAIN=.staging.scribe.sanguinehost.com"
echo -e "${BLUE}[INFO]${NC} Monitor the deployment with:"
echo "aws ecs describe-services --cluster $ECS_CLUSTER --services $BACKEND_SERVICE --region $AWS_REGION --query 'services[0].deployments'"