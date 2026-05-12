# Agentic Reference: Operational Runbook

## Secure Production Access
Direct access to production/staging databases (RDS) is restricted. Access is granted via SSM Port Forwarding through a Bastion host or Tailscale router.

### 1. Database Access (Read/Write)
**Prerequisites**: AWS CLI configured with appropriate permissions.

```bash
# 1. Retrieve Database Password
aws secretsmanager get-secret-value \
    --secret-id arn:aws:secretsmanager:ap-southeast-4:058264339990:secret:staging/scribe/database-tXXaO7 \
    --region ap-southeast-4 \
    --query SecretString --output text | jq -r .password

# 2. Start SSM Tunnel (Port Forwarding)
# Find the Tailscale router or Bastion instance ID
INSTANCE_ID=$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=staging-scribe-tailscale-router" \
    --query "Reservations[0].Instances[0].InstanceId" --output text --region ap-southeast-4)

aws ssm start-session \
    --target $INSTANCE_ID \
    --document-name AWS-StartPortForwardingSessionToRemoteHost \
    --parameters '{"host":["staging-scribe-postgres.c9oy0o248kqw.ap-southeast-4.rds.amazonaws.com"],"portNumber":["5432"], "localPortNumber":["54320"]}' \
    --region ap-southeast-4

# 3. Connect via Localhost
# Note: sslmode=require is mandatory
PGPASSWORD='<RETRIEVED_PASSWORD>' psql "postgresql://scribe_admin@localhost:54320/scribe?sslmode=require"
```

### 2. ECS Exec (Shell Access)
For debugging running containers (e.g., checking env vars, network connectivity).

```bash
# 1. List Tasks
aws ecs list-tasks --cluster staging-scribe-cluster --service-name staging-scribe-backend --region ap-southeast-4

# 2. Start Interactive Shell
aws ecs execute-command \
    --cluster staging-scribe-cluster \
    --task <TASK_ARN> \
    --container backend \
    --command "/bin/sh" \
    --interactive \
    --region ap-southeast-4
```

## OpenObserve (OBS) Operations
Common tasks for monitoring, querying, and managing alerts in OpenObserve.

### 1. Connecting and API Calls
OpenObserve provides a REST API. You need your organization name, stream name, and basic auth credentials token.

```bash
# Set your OpenObserve URL and credentials
export OBS_URL="https://api.openobserve.ai"
export OBS_ORG="default"
export OBS_STREAM="scribe_logs"
export OBS_TOKEN="Basic <base64_encoded_email:password>"

# Test Connection / Get Streams
curl -X GET "${OBS_URL}/api/${OBS_ORG}/streams" \
  -H "Authorization: ${OBS_TOKEN}" \
  -H "Accept: application/json"

# Search Logs using SQL via API
curl -X POST "${OBS_URL}/api/${OBS_ORG}/_search" \
  -H "Authorization: ${OBS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "sql": "SELECT * FROM scribe_logs WHERE level = '\''ERROR'\'' LIMIT 10",
      "start_time": <START_TIMESTAMP_MICROSECONDS>,
      "end_time": <END_TIMESTAMP_MICROSECONDS>
    }
  }'
```

### 2. Configuring Alerts
Alerts in OpenObserve monitor streams using SQL queries and trigger destinations (e.g., webhooks, Slack) when conditions are met. Alert configurations are stored as JSON files in `infrastructure/monitoring/alerts/`.

```bash
# Example: Create or Update an Alert via API
curl -X POST "${OBS_URL}/api/${OBS_ORG}/alerts/scribe_external_dependency" \
  -H "Authorization: ${OBS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d @infrastructure/monitoring/alerts/external_dependency_failure.json
```

**Key Alerting Principles:**
- Store all alert configurations in version control (`infrastructure/monitoring/alerts`).
- Use structured JSON logging to extract the right metrics (e.g., `event_type = 'payment_failed'`).
- Ensure every alert has a clear destination (e.g., Discord webhook) and action plan.

## Manual User Management
Common tasks for support or debugging.

### Reset User for Signup
If a user needs to re-signup (e.g., email verification failed), delete them from the DB.

```sql
-- Connect via SSM Tunnel (see above)
DELETE FROM users WHERE email = 'target@email.com';
```

## Deployment Process

### 1. Backend Deployment
The backend is deployed via the `scripts/deploy/aws.sh` script, which handles building the Docker image, pushing to ECR, and updating the ECS service.

```bash
# Deploy backend to Staging
./scripts/deploy/aws.sh backend
```

**Key Steps Performed:**
1.  Builds `scribe-backend` Docker image.
2.  Pushes image to ECR (`058264339990.dkr.ecr.ap-southeast-4.amazonaws.com/staging-scribe-backend`).
3.  Forces a new deployment in ECS, pulling the latest image.

### 2. Frontend Deployment (ECS)
Frontend is deployed to AWS ECS alongside the backend using the consolidated deployment script.

```bash
# Deploy frontend to Staging
./scripts/deploy/aws.sh frontend
```

This script will:
- Build the Docker image for the frontend
- Push to ECR
- Update the ECS service

See `docs/frontend/FRONTEND_DEPLOYMENT.md` for detailed instructions.

### 3. Infrastructure Updates (Terraform/Terragrunt)
Infrastructure changes (e.g., env vars, IAM roles) are managed via Terragrunt.

```bash
cd infrastructure/terragrunt/aws/staging/<module>
terragrunt apply
```

**Workflow:**
1.  **Plan**: `terragrunt plan` to preview changes.
2.  **Apply**: `terragrunt apply` to execute.
3.  **Verify**: Check AWS console or verification scripts.
