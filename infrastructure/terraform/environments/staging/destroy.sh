#!/bin/bash
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ENVIRONMENT="staging"
REGION="ap-southeast-4"

echo "==================================="
echo "Terraform Destroy - Safe Workflow"
echo "Environment: $ENVIRONMENT"
echo "==================================="

# Step 1: Run pre-destroy validation
echo ""
echo "Step 1: Running pre-destroy validation..."
"$SCRIPT_DIR/../../scripts/pre-destroy-check.sh" "$ENVIRONMENT" "$REGION"

if [ $? -ne 0 ]; then
  echo ""
  echo "❌ Pre-destroy validation failed. Please address the issues above before proceeding."
  exit 1
fi

# Step 2: Scale down ECS services (graceful shutdown)
echo ""
echo "Step 2: Scaling down ECS services..."
CLUSTER_NAME="${ENVIRONMENT}-scribe-cluster"

SERVICES=$(aws ecs list-services --cluster "$CLUSTER_NAME" --region "$REGION" --query 'serviceArns[]' --output text 2>/dev/null || echo "")

if [ ! -z "$SERVICES" ]; then
  for SERVICE in $SERVICES; do
    SERVICE_NAME=$(echo "$SERVICE" | awk -F'/' '{print $NF}')
    echo "  Scaling down: $SERVICE_NAME"
    aws ecs update-service --cluster "$CLUSTER_NAME" --service "$SERVICE" --desired-count 0 --region "$REGION" > /dev/null 2>&1 || true
  done

  echo "  Waiting 30 seconds for tasks to drain..."
  sleep 30
else
  echo "  No services found or cluster doesn't exist"
fi

# Step 3: Confirm with user
echo ""
echo "Step 3: Ready to destroy Terraform-managed infrastructure"
echo ""
read -p "Are you sure you want to destroy all resources? (type 'yes' to confirm): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
  echo "Destroy cancelled."
  exit 0
fi

# Step 4: Run Terraform destroy
echo ""
echo "Step 4: Running Terraform destroy..."
cd "$SCRIPT_DIR"

terraform destroy

DESTROY_EXIT_CODE=$?

# Step 5: Clean up any remaining orphaned resources
echo ""
echo "Step 5: Cleaning up orphaned resources..."

# Clean up orphaned ENIs
ORPHANED_ENIS=$(aws ec2 describe-network-interfaces \
  --filters "Name=description,Values=*${CLUSTER_NAME}*" "Name=status,Values=available" \
  --region "$REGION" \
  --query 'NetworkInterfaces[].NetworkInterfaceId' \
  --output text 2>/dev/null || echo "")

if [ ! -z "$ORPHANED_ENIS" ]; then
  echo "  Cleaning up orphaned ENIs..."
  for ENI in $ORPHANED_ENIS; do
    echo "    Deleting ENI: $ENI"
    aws ec2 delete-network-interface --network-interface-id "$ENI" --region "$REGION" 2>/dev/null || true
  done
else
  echo "  No orphaned ENIs found"
fi

# Clean up orphaned EBS volumes
ORPHANED_VOLUMES=$(aws ec2 describe-volumes \
  --filters "Name=tag:Environment,Values=${ENVIRONMENT}" "Name=tag:Project,Values=scribe" "Name=status,Values=available" \
  --region "$REGION" \
  --query 'Volumes[].VolumeId' \
  --output text 2>/dev/null || echo "")

if [ ! -z "$ORPHANED_VOLUMES" ]; then
  echo "  Cleaning up orphaned volumes..."
  for VOL in $ORPHANED_VOLUMES; do
    echo "    Deleting volume: $VOL"
    aws ec2 delete-volume --volume-id "$VOL" --region "$REGION" 2>/dev/null || true
  done
else
  echo "  No orphaned volumes found"
fi

echo ""
echo "==================================="
if [ $DESTROY_EXIT_CODE -eq 0 ]; then
  echo "✅ Destroy Complete!"
else
  echo "⚠️  Destroy completed with errors (exit code: $DESTROY_EXIT_CODE)"
  echo "   Some resources may still exist. Check the output above."
fi
echo "==================================="

exit $DESTROY_EXIT_CODE
