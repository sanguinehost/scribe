#!/bin/bash
set -e

ENVIRONMENT="${1:-staging}"
REGION="${2:-ap-southeast-4}"

echo "==================================="
echo "Pre-Destroy Validation Check"
echo "Environment: $ENVIRONMENT"
echo "Region: $REGION"
echo "==================================="

# Track if any errors were found
ERRORS_FOUND=0

# Check ECS cluster status
CLUSTER_NAME="${ENVIRONMENT}-scribe-cluster"
echo ""
echo "Checking ECS Cluster: $CLUSTER_NAME"

CLUSTER_STATUS=$(aws ecs describe-clusters --clusters "$CLUSTER_NAME" --region "$REGION" --query 'clusters[0].status' --output text 2>/dev/null || echo "NOT_FOUND")

if [ "$CLUSTER_STATUS" == "ACTIVE" ]; then
  echo "⚠️  WARNING: ECS cluster is still ACTIVE"

  # Check for running tasks
  RUNNING_TASKS=$(aws ecs list-tasks --cluster "$CLUSTER_NAME" --region "$REGION" --query 'taskArns' --output text 2>/dev/null || echo "")

  if [ ! -z "$RUNNING_TASKS" ]; then
    echo "❌ ERROR: ECS cluster has running tasks:"
    aws ecs list-tasks --cluster "$CLUSTER_NAME" --region "$REGION" --output table
    echo ""
    echo "Action required: Run the following to stop all tasks:"
    echo "  aws ecs list-tasks --cluster $CLUSTER_NAME --region $REGION --query 'taskArns[]' --output text | xargs -n1 aws ecs stop-task --cluster $CLUSTER_NAME --region $REGION --task"
    ERRORS_FOUND=1
  fi

  # Check for active services
  SERVICES=$(aws ecs list-services --cluster "$CLUSTER_NAME" --region "$REGION" --query 'serviceArns' --output text 2>/dev/null || echo "")

  if [ ! -z "$SERVICES" ]; then
    echo "⚠️  WARNING: ECS cluster has active services. They will be deleted during destroy."
    aws ecs list-services --cluster "$CLUSTER_NAME" --region "$REGION" --output table
  fi

elif [ "$CLUSTER_STATUS" == "INACTIVE" ]; then
  echo "✅ ECS cluster is INACTIVE"

  # Check for tasks in DEPROVISIONING state
  DEPROVISIONING_TASKS=$(aws ecs list-tasks --cluster "$CLUSTER_NAME" --desired-status STOPPED --region "$REGION" --query 'taskArns' --output text 2>/dev/null || echo "")

  if [ ! -z "$DEPROVISIONING_TASKS" ]; then
    echo "⚠️  WARNING: Found tasks in DEPROVISIONING state:"
    for TASK in $DEPROVISIONING_TASKS; do
      TASK_ID=$(echo "$TASK" | awk -F'/' '{print $NF}')
      TASK_STATUS=$(aws ecs describe-tasks --cluster "$CLUSTER_NAME" --tasks "$TASK_ID" --region "$REGION" --query 'tasks[0].{lastStatus:lastStatus,desiredStatus:desiredStatus}' --output table 2>/dev/null || echo "Task not found")
      echo "$TASK_STATUS"
    done
    echo ""
    echo "⏳ Recommendation: Wait for these tasks to fully deprovision before running destroy"
    echo "   Monitor with: watch 'aws ecs list-tasks --cluster $CLUSTER_NAME --region $REGION'"
    ERRORS_FOUND=1
  fi
else
  echo "✅ ECS cluster not found or already deleted"
fi

# Check for orphaned ENIs
echo ""
echo "Checking for orphaned network interfaces..."
ORPHANED_ENIS=$(aws ec2 describe-network-interfaces \
  --filters "Name=description,Values=*${CLUSTER_NAME}*" "Name=status,Values=available" \
  --region "$REGION" \
  --query 'NetworkInterfaces[].NetworkInterfaceId' \
  --output text 2>/dev/null || echo "")

if [ ! -z "$ORPHANED_ENIS" ]; then
  echo "⚠️  WARNING: Found orphaned ENIs that should be deleted:"
  echo "$ORPHANED_ENIS"
  echo ""
  echo "Action recommended: Delete these manually before Terraform destroy:"
  for ENI in $ORPHANED_ENIS; do
    echo "  aws ec2 delete-network-interface --network-interface-id $ENI --region $REGION"
  done
else
  echo "✅ No orphaned ENIs found"
fi

# Check for available (unattached) EBS volumes
echo ""
echo "Checking for unattached EBS volumes..."
AVAILABLE_VOLUMES=$(aws ec2 describe-volumes \
  --filters "Name=tag:Environment,Values=${ENVIRONMENT}" "Name=tag:Project,Values=scribe" "Name=status,Values=available" \
  --region "$REGION" \
  --query 'Volumes[].VolumeId' \
  --output text 2>/dev/null || echo "")

if [ ! -z "$AVAILABLE_VOLUMES" ]; then
  echo "⚠️  WARNING: Found unattached EBS volumes that should be deleted:"
  echo "$AVAILABLE_VOLUMES"
  echo ""
  echo "Action recommended: Delete these manually or they will be destroyed with Terraform:"
  for VOL in $AVAILABLE_VOLUMES; do
    echo "  aws ec2 delete-volume --volume-id $VOL --region $REGION"
  done
else
  echo "✅ No unattached volumes found"
fi

# Check for in-use EBS volumes
echo ""
echo "Checking for in-use EBS volumes..."
IN_USE_VOLUMES=$(aws ec2 describe-volumes \
  --filters "Name=tag:Environment,Values=${ENVIRONMENT}" "Name=tag:Project,Values=scribe" "Name=status,Values=in-use" \
  --region "$REGION" \
  --query 'Volumes[].{VolumeId:VolumeId,State:State,Attachments:Attachments[0].State}' \
  --output table 2>/dev/null || echo "")

if [ ! -z "$IN_USE_VOLUMES" ] && [ "$IN_USE_VOLUMES" != "None" ] && [ "$IN_USE_VOLUMES" != "" ]; then
  # Check if the output actually contains volume data (not just headers)
  if echo "$IN_USE_VOLUMES" | grep -q "vol-"; then
    echo "⚠️  WARNING: Found in-use EBS volumes:"
    echo "$IN_USE_VOLUMES"
    echo ""
    echo "❌ ERROR: EBS volumes are still attached. Cannot safely destroy."
    echo "   These volumes are likely attached to tasks in DEPROVISIONING state."
    echo "   Wait for ECS tasks to fully stop, then retry."
    ERRORS_FOUND=1
  else
    echo "✅ No in-use volumes found"
  fi
else
  echo "✅ No in-use volumes found"
fi

echo ""
echo "==================================="
echo "Pre-Destroy Check Complete"
echo "==================================="

if [ $ERRORS_FOUND -eq 1 ]; then
  echo ""
  echo "❌ ERRORS DETECTED: Cannot proceed with destroy"
  echo "   Please address the issues above before running destroy."
  exit 1
fi

echo ""
echo "✅ All checks passed! Safe to proceed with:"
echo "  cd infrastructure/terraform/environments/$ENVIRONMENT"
echo "  terraform destroy"
echo ""
