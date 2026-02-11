#!/bin/bash
ROLES=("staging-scribe-ecs-infrastructure-role" "staging-scribe-ecs-task-execution-role" "staging-scribe-ecs-task-role")

for ROLE in "${ROLES[@]}"; do
    echo "Processing role: $ROLE"

    # Detach managed policies
    POLICIES=$(aws iam list-attached-role-policies --role-name "$ROLE" --query 'AttachedPolicies[*].PolicyArn' --output text)
    for POLICY in $POLICIES; do
        echo "Detaching policy $POLICY from $ROLE"
        aws iam detach-role-policy --role-name "$ROLE" --policy-arn "$POLICY"
    done

    # Delete inline policies
    INLINE_POLICIES=$(aws iam list-role-policies --role-name "$ROLE" --query 'PolicyNames[*]' --output text)
    for POLICY in $INLINE_POLICIES; do
        echo "Deleting inline policy $POLICY from $ROLE"
        aws iam delete-role-policy --role-name "$ROLE" --policy-name "$POLICY"
    done

    # Check for instance profiles
    PROFILES=$(aws iam list-instance-profiles-for-role --role-name "$ROLE" --query 'InstanceProfiles[*].InstanceProfileName' --output text)
    for PROFILE in $PROFILES; do
        echo "Removing role $ROLE from instance profile $PROFILE"
        aws iam remove-role-from-instance-profile --instance-profile-name "$PROFILE" --role-name "$ROLE"
    done

    # Delete the role
    echo "Deleting role $ROLE"
    aws iam delete-role --role-name "$ROLE"
done
