# Incident Response Playbook: Lateral Movement

**Incident Type:** Privilege Escalation / Service-to-Service Attack / Infrastructure Compromise
**Severity:** P0 (Critical)
**MTTD Target:** <5 minutes
**MTTR Target:** <30 minutes
**Owner:** Security Operations Team + Infrastructure Team + CISO

## Overview

This playbook addresses lateral movement attacks where an attacker who has compromised one part of the system attempts to expand their access to other services, resources, or privilege levels:

- **Privilege Escalation:** Normal user → Admin, Database read-only → Full access
- **Service-to-Service:** Compromised backend → Database, Compromised frontend → Backend API
- **Infrastructure:** Application server → AWS infrastructure (S3, RDS, Secrets Manager)
- **DEK Cache Access:** Compromised session → All user DEKs in memory
- **Database Credential Theft:** Application credentials → Direct database access

**Kill Chain Context:** Lateral movement is typically Phase 3 of an attack:
1. Initial Access (credential stuffing, webhook exploit)
2. Privilege Escalation (exploit vulnerability, steal credentials)
3. **Lateral Movement** ← This playbook
4. Data Exfiltration / Impact

## Detection Criteria

### Primary Indicators

**CloudWatch Metric Filter:**
```json
{ $.event = "lateral_movement_detected" }
```

**Alert Thresholds:**
- **P0 Alert:** IAM role assumption from unauthorized source
- **P0 Alert:** Database connection from non-application IP
- **P0 Alert:** AWS Secrets Manager access from unauthorized service
- **P0 Alert:** Unusual service-to-service API calls (frontend → database direct)
- **P1 Alert:** Privilege escalation attempt detected (user → admin)
- **P1 Alert:** DEK cache mass access (>100 users in 5 minutes)

**Prometheus Metrics:**
- `iam_role_assumption_failures` > 0 (failed privilege escalation)
- `database_connection_from_unknown_source` > 0
- `secrets_manager_access_unauthorized` > 0
- `dek_cache_bulk_access` > 100 users per 5-minute window

**AWS GuardDuty Findings:**
- `PrivilegeEscalation:IAMUser/AdministrativePermissions`
- `Persistence:IAMUser/UserPermissions`
- `CredentialAccess:IAMUser/AnomalousBehavior`
- `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`

### Secondary Indicators (Correlation)

- Successful attack on one service (e.g., credential stuffing) followed by unusual behavior in another service
- Geographic anomaly (attack from US, then AWS API calls from China)
- Time-of-day anomaly (3am AWS console login after user authentication)
- Unusual port scanning (internal network reconnaissance)
- Service discovery attempts (AWS metadata API queries, port 169.254.169.254)

### Composite Alarm

```hcl
aws_cloudwatch_composite_alarm "lateral_movement_attack" {
  alarm_rule = "ALARM(iam_privilege_escalation) OR
                ALARM(database_unauthorized_access) OR
                (ALARM(guardduty_high_severity) AND ALARM(unusual_service_calls))"
  alarm_actions = [
    aws_sns_topic.security_alerts_p0.arn,
    aws_sns_topic.ciso_alerts.arn
  ]
}
```

## Investigation Steps

### Phase 1: Initial Triage (0-5 minutes)

1. **Check Alert Context**
   ```bash
   # CloudWatch Logs Insights query
   fields @timestamp, event, source_service, target_service, action, result
   | filter event = "lateral_movement_detected"
   | sort @timestamp desc
   | limit 50
   ```

2. **Identify Movement Pattern**
   - **User → Admin:** Privilege escalation attempt
   - **User → DEK Cache:** Attempt to decrypt other users' data
   - **App → Database Direct:** Bypassing application layer (SQL injection follow-up)
   - **App → AWS Services:** Credential theft, metadata API abuse
   - **External → Internal Services:** Network perimeter breach

3. **Check Initial Compromise Source**
   ```bash
   # Trace back to initial attack vector
   fields @timestamp, event, hashed_user_id, source_ip_anonymized
   | filter hashed_user_id = "<suspected_attacker_hash>"
   | sort @timestamp
   | limit 100
   # Look for: auth failures → success → unusual API calls → lateral movement
   ```

4. **Assess Blast Radius**
   ```bash
   # What services/resources were accessed?
   fields target_service, target_resource, action
   | filter event = "lateral_movement_detected"
   | stats count() by target_service, target_resource
   | sort count desc
   ```

### Phase 2: Deep Investigation (5-15 minutes)

1. **Analyze IAM Activity** (if AWS infrastructure involved)
   ```bash
   # CloudTrail logs analysis
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=Username,AttributeValue=<suspected_user> \
     --start-time <incident_start> \
     --max-results 100

   # Key events to look for:
   # - AssumeRole (privilege escalation)
   # - GetSecretValue (credential theft)
   # - DescribeInstances (reconnaissance)
   # - PutObject/GetObject (data exfiltration)
   ```

2. **Check Database Access Logs**
   ```sql
   -- PostgreSQL: Review connections from unexpected sources
   SELECT
     datname,
     usename,
     application_name,
     client_addr,
     backend_start,
     state,
     query
   FROM pg_stat_activity
   WHERE client_addr NOT IN (
     '<known_app_server_ips>'  -- Your ECS/EC2 IPs
   )
   ORDER BY backend_start DESC;

   -- Check for administrative queries from application user
   SELECT
     userid::regrole,
     query,
     calls,
     rows
   FROM pg_stat_statements
   WHERE userid::regrole = 'scribe_app_user'
   AND (query ILIKE '%DROP%'
        OR query ILIKE '%GRANT%'
        OR query ILIKE '%ALTER%'
        OR query ILIKE '%CREATE USER%')
   ORDER BY calls DESC;
   ```

3. **Review Service-to-Service Authentication**
   ```bash
   # Check for unauthorized service tokens
   fields @timestamp, source_service, target_service, auth_method, auth_result
   | filter event = "service_auth_attempt"
   | filter auth_result = "unauthorized"
   | stats count() by source_service, target_service
   ```

4. **Check DEK Cache Access Patterns**
   ```bash
   # Detect bulk DEK cache access (attempt to decrypt all users' data)
   fields @timestamp, hashed_user_id, dek_cache_hit_count
   | filter event = "dek_cache_access"
   | stats sum(dek_cache_hit_count) as total_hits by hashed_user_id, bin(5m)
   | filter total_hits > 100
   # If >100 DEK hits in 5 minutes → bulk decryption attempt
   ```

5. **Review AWS Security Hub Findings**
   ```bash
   # Check for privilege escalation findings
   aws securityhub get-findings \
     --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}],
                 "RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' \
     --max-results 50

   # Look for:
   # - PCI.IAM.1 (root account usage)
   # - PCI.IAM.3 (access keys not rotated)
   # - PrivilegeEscalation findings
   ```

### Phase 3: Threat Validation (15-30 minutes)

1. **Verify Privilege Escalation Success**
   ```bash
   # Check if attacker successfully escalated privileges
   aws iam get-user --user-name <suspected_user>
   aws iam list-attached-user-policies --user-name <suspected_user>
   aws iam list-user-policies --user-name <suspected_user>

   # Check for newly granted admin permissions
   aws iam simulate-principal-policy \
     --policy-source-arn arn:aws:iam::123456789012:user/<suspected_user> \
     --action-names iam:* s3:* rds:* \
     --max-items 100
   ```

2. **Check for Stolen Credentials**
   ```bash
   # Review Secrets Manager access logs
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
     --start-time <incident_start> \
     --max-results 100 \
     | jq '.Events[] | {time: .EventTime, user: .Username, secret: .Resources[0].ResourceName}'

   # Check for database credential access
   aws secretsmanager list-secret-version-ids \
     --secret-id staging-scribe-postgres \
     --include-deprecated
   ```

3. **Analyze Network Traffic** (if VPC Flow Logs enabled)
   ```bash
   # Check for unusual internal network traffic
   fields srcAddr, dstAddr, dstPort, protocol, bytes
   | filter srcAddr like /^10\./  # Internal IP
   | filter dstPort in [5432, 6379, 3306]  # Database ports
   | stats sum(bytes) as total_bytes by srcAddr, dstAddr, dstPort
   | sort total_bytes desc
   # Look for unexpected source IPs connecting to databases
   ```

4. **Check for Persistence Mechanisms**
   ```sql
   -- PostgreSQL: Check for backdoor database users
   SELECT
     usename,
     usesuper,
     usecreatedb,
     valuntil,
     useconfig
   FROM pg_user
   WHERE usename NOT IN ('postgres', 'scribe_admin', 'scribe_app_user', 'rds_superuser')
   ORDER BY usecreatedb DESC;

   -- Check for malicious functions/triggers
   SELECT
     proname,
     prosrc,
     proowner::regrole
   FROM pg_proc
   WHERE prosrc ILIKE '%exec%'
   OR prosrc ILIKE '%system%'
   OR prosrc ILIKE '%shell%';
   ```

## Containment Actions

### Immediate (0-5 minutes)

1. **Isolate Compromised Service**
   ```bash
   # If ECS task compromised, drain and stop task
   aws ecs update-service \
     --cluster scribe-staging \
     --service scribe-backend \
     --desired-count 0

   # If EC2 instance compromised, modify security group
   aws ec2 modify-instance-attribute \
     --instance-id <compromised-instance> \
     --groups <isolated-security-group-id>  # No outbound internet
   ```

2. **Revoke Compromised IAM Credentials**
   ```bash
   # Disable IAM user access keys
   aws iam update-access-key \
     --user-name <compromised-user> \
     --access-key-id <access-key-id> \
     --status Inactive

   # Attach deny-all policy (immediate lockout)
   aws iam attach-user-policy \
     --user-name <compromised-user> \
     --policy-arn arn:aws:iam::aws:policy/AWSDenyAll
   ```

3. **Rotate Database Credentials**
   ```bash
   # Generate new password
   NEW_DB_PASSWORD=$(openssl rand -base64 32)

   # Update in AWS Secrets Manager
   aws secretsmanager update-secret \
     --secret-id staging-scribe-postgres \
     --secret-string "{\"username\":\"scribe_app_user\",\"password\":\"$NEW_DB_PASSWORD\"}"

   # Update PostgreSQL password
   ssh ec2-user@<db-jump-host> "PGPASSWORD='$OLD_PASSWORD' psql \
     -h staging-scribe-postgres.c9oy0o248kqw.ap-southeast-4.rds.amazonaws.com \
     -U scribe_admin \
     -d scribe \
     -c \"ALTER USER scribe_app_user PASSWORD '$NEW_DB_PASSWORD';\""
   ```

4. **Clear DEK Cache** (if compromised)
   ```rust
   // Emergency DEK cache clear
   // backend/src/auth/mod.rs

   pub async fn emergency_full_dek_cache_clear() -> Result<(), AppError> {
       let mut cache = AUTH_BACKEND.dek_cache.write().await;
       cache.clear();
       tracing::critical!("EMERGENCY: Full DEK cache cleared due to lateral movement attack");
       Ok(())
   }
   ```

### Short-Term (5-30 minutes)

1. **Enable AWS Security Services** (if not already enabled)
   ```bash
   # Enable GuardDuty (threat detection)
   aws guardduty create-detector --enable

   # Enable Security Hub (compliance monitoring)
   aws securityhub enable-security-hub \
     --enable-default-standards

   # Enable CloudTrail (audit logging)
   aws cloudtrail create-trail \
     --name scribe-security-trail \
     --s3-bucket-name scribe-cloudtrail-logs \
     --is-multi-region-trail
   ```

2. **Implement Network Segmentation**
   ```hcl
   # Terraform: Restrict security groups to least privilege

   resource "aws_security_group_rule" "backend_to_rds" {
     type              = "egress"
     from_port         = 5432
     to_port           = 5432
     protocol          = "tcp"
     security_group_id = aws_security_group.backend.id

     # ONLY allow backend to access database
     source_security_group_id = aws_security_group.rds.id
   }

   resource "aws_security_group_rule" "rds_ingress_restrictive" {
     type              = "ingress"
     from_port         = 5432
     to_port           = 5432
     protocol          = "tcp"
     security_group_id = aws_security_group.rds.id

     # ONLY allow connections from backend security group
     source_security_group_id = aws_security_group.backend.id
   }

   # Remove public access entirely
   resource "aws_db_instance" "postgres" {
     publicly_accessible = false  # CRITICAL: No public internet access
   }
   ```

3. **Implement Service-to-Service Authentication**
   ```rust
   // backend/src/middleware/service_auth.rs

   pub struct ServiceAuthToken {
       pub service_name: String,
       pub issued_at: DateTime<Utc>,
       pub expires_at: DateTime<Utc>,
   }

   pub async fn verify_service_auth(
       req: Request<Body>,
       next: Next,
   ) -> Result<Response, AppError> {
       // Extract service auth token from header
       let token = req.headers()
           .get("X-Service-Auth-Token")
           .and_then(|h| h.to_str().ok())
           .ok_or_else(|| AppError::Unauthorized("Missing service auth token".into()))?;

       // Verify HMAC signature
       let service_token = verify_hmac_token(token, &SERVICE_AUTH_SECRET)?;

       // Check service is authorized for this endpoint
       let endpoint = req.uri().path();
       if !is_service_authorized(&service_token.service_name, endpoint) {
           return Err(AppError::Forbidden(format!(
               "Service {} not authorized for {}",
               service_token.service_name, endpoint
           )));
       }

       Ok(next.run(req).await)
   }
   ```

4. **Enable Database Row-Level Security** (if not already enabled)
   ```sql
   -- PostgreSQL: Enforce strict user isolation
   ALTER TABLE chat_messages ENABLE ROW LEVEL SECURITY;
   ALTER TABLE characters ENABLE ROW LEVEL SECURITY;
   ALTER TABLE user_personas ENABLE ROW LEVEL SECURITY;

   -- Policy: Users can only access their own data
   CREATE POLICY user_isolation ON chat_messages
   FOR ALL
   USING (user_id = current_setting('app.current_user_id')::uuid);

   -- Application MUST set current_user_id on every connection
   -- Prevents lateral movement even with database credentials
   ```

### Long-Term (30min - 7 days)

1. **Implement Zero Trust Architecture**
   ```hcl
   # Terraform: VPC with private subnets only

   resource "aws_vpc" "main" {
     cidr_block           = "10.0.0.0/16"
     enable_dns_hostnames = true
     enable_dns_support   = true
   }

   resource "aws_subnet" "private" {
     count             = 3
     vpc_id            = aws_vpc.main.id
     cidr_block        = "10.0.${count.index + 1}.0/24"
     availability_zone = data.aws_availability_zones.available.names[count.index]

     # NO internet gateway access
     map_public_ip_on_launch = false
   }

   # All outbound traffic through NAT gateway (controlled egress)
   resource "aws_nat_gateway" "main" {
     allocation_id = aws_eip.nat.id
     subnet_id     = aws_subnet.public[0].id
   }
   ```

2. **Implement IAM Least Privilege**
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "secretsmanager:GetSecretValue"
         ],
         "Resource": [
           "arn:aws:secretsmanager:ap-southeast-4:*:secret:staging-scribe-postgres-*"
         ],
         "Condition": {
           "StringEquals": {
             "aws:SourceVpc": "vpc-12345678"
           }
         }
       }
     ]
   }
   ```

3. **Enable AWS Systems Manager Session Manager** (no SSH keys)
   ```bash
   # Use Session Manager instead of SSH (no open ports)
   aws ssm start-session --target <instance-id>

   # Disable SSH entirely
   aws ec2 revoke-security-group-ingress \
     --group-id <security-group-id> \
     --protocol tcp \
     --port 22 \
     --cidr 0.0.0.0/0
   ```

4. **Implement Privilege Access Management (PAM)**
   ```rust
   // backend/src/services/pam.rs

   pub struct TemporaryElevatedAccess {
       pub user_id: Uuid,
       pub elevated_to: Role,
       pub granted_at: DateTime<Utc>,
       pub expires_at: DateTime<Utc>,
       pub reason: String,
       pub approved_by: Uuid,
   }

   pub async fn request_temporary_admin_access(
       requester_id: Uuid,
       reason: String,
       duration_minutes: i32,
   ) -> Result<PendingRequest, AppError> {
       // Create approval request
       let request = sqlx::query_as!(
           PendingRequest,
           "INSERT INTO privilege_escalation_requests
            (user_id, requested_role, reason, duration_minutes, status)
            VALUES ($1, 'admin', $2, $3, 'pending')
            RETURNING *",
           requester_id, reason, duration_minutes
       ).fetch_one(&pool).await?;

       // Notify approvers
       notify_approvers(&request).await?;

       Ok(request)
   }

   // Auto-revoke after expiry
   pub async fn auto_revoke_expired_privileges() -> Result<(), AppError> {
       sqlx::query!(
           "UPDATE privilege_escalation_requests
            SET status = 'expired', expired_at = NOW()
            WHERE status = 'approved'
            AND expires_at < NOW()"
       ).execute(&pool).await?;

       Ok(())
   }
   ```

## Recovery Procedures

### Infrastructure Recovery

1. **Assess Infrastructure Compromise**
   ```bash
   # Check for backdoor IAM users/roles
   aws iam list-users | jq '.Users[] | select(.CreateDate > "<incident_start>")'
   aws iam list-roles | jq '.Roles[] | select(.CreateDate > "<incident_start>")'

   # Check for malicious Lambda functions
   aws lambda list-functions | jq '.Functions[] | select(.LastModified > "<incident_start>")'

   # Check for unauthorized S3 bucket policies
   for bucket in $(aws s3 ls | awk '{print $3}'); do
     echo "Bucket: $bucket"
     aws s3api get-bucket-policy --bucket $bucket 2>/dev/null || echo "No policy"
   done
   ```

2. **Remove Persistence Mechanisms**
   ```bash
   # Delete backdoor IAM users
   aws iam delete-user --user-name <backdoor-user>

   # Remove malicious Lambda functions
   aws lambda delete-function --function-name <malicious-function>

   # Restore S3 bucket policies from backup
   aws s3api put-bucket-policy \
     --bucket scribe-data \
     --policy file://s3-policy-backup.json
   ```

3. **Rebuild Compromised Infrastructure**
   ```bash
   # Use Infrastructure-as-Code (Terraform) to rebuild from known-good state
   cd infrastructure
   git checkout <last-known-good-commit>
   terraform plan  # Review changes
   terraform apply # Rebuild infrastructure

   # Redeploy application from clean images
   ./scripts/deploy/deploy-backend-podman.sh --force-rebuild
   ```

### Service Restoration

1. **Verify All Credentials Rotated**
   ```bash
   # Checklist of credentials to rotate:
   # ✓ Database passwords (PostgreSQL, Redis)
   # ✓ AWS IAM access keys
   # ✓ Service API tokens
   # ✓ Webhook secrets (Paddle)
   # ✓ Cookie signing keys
   # ✓ Encryption keys (if compromised)
   ```

2. **Restore Normal Operations**
   - Re-enable services (ECS tasks, EC2 instances)
   - Remove temporary deny-all IAM policies
   - Restore normal security group rules
   - Clear DEK cache, force users to re-authenticate

3. **Validate Security Posture**
   ```bash
   # Run AWS Security Hub compliance checks
   aws securityhub get-compliance-summary

   # Run automated penetration test
   # (use approved vendor, schedule for off-peak hours)
   ```

## Post-Incident Review

### Evidence Collection

1. **Archive All Logs**
   ```bash
   # CloudTrail (AWS API calls)
   aws cloudtrail create-export-task \
     --log-group-name aws-cloudtrail-logs \
     --from <incident_start_epoch> \
     --to <incident_end_epoch> \
     --destination scribe-security-incident-logs \
     --destination-prefix lateral-movement-$(date +%Y%m%d)

   # Application logs
   aws logs create-export-task \
     --log-group-name /aws/scribe/application \
     --from <incident_start_epoch> \
     --to <incident_end_epoch> \
     --destination scribe-security-incident-logs \
     --destination-prefix lateral-movement-app-$(date +%Y%m%d)

   # Database logs
   aws rds download-db-log-file-portion \
     --db-instance-identifier scribe-postgres \
     --log-file-name postgresql/postgresql.log.<date> \
     --output text > postgres-incident.log
   ```

2. **Document Attack Path**
   ```markdown
   ## Lateral Movement Attack Path

   1. **Initial Compromise:** [How attacker first gained access]
      - Method: [Credential stuffing, webhook exploit, etc.]
      - Timestamp: [HH:MM UTC]
      - Compromised Account: [hashed_user_id]

   2. **Privilege Escalation:** [How attacker escalated privileges]
      - Method: [IAM role assumption, database credential theft]
      - Timestamp: [HH:MM UTC]
      - Elevated To: [Role/permission level]

   3. **Lateral Movement:** [What services/resources attacker accessed]
      - Target Services: [Database, S3, Secrets Manager]
      - Timestamp: [HH:MM UTC]
      - Actions Performed: [Data exfiltration, persistence, etc.]

   4. **Detection:** [How attack was discovered]
      - Alert: [CloudWatch alarm, GuardDuty finding]
      - Timestamp: [HH:MM UTC]
      - MTTD: [minutes from initial compromise]

   5. **Containment:** [Actions taken to stop attack]
      - Timestamp: [HH:MM UTC]
      - MTTR: [minutes from detection]
   ```

### Root Cause Analysis

**Questions to Answer:**
1. How did attacker move from initial compromise to privileged access?
2. What security controls failed? (IAM policies, network segmentation, authentication)
3. Could zero trust architecture have prevented lateral movement?
4. Why didn't detection systems alert earlier?
5. What persistence mechanisms did attacker establish?

### Preventive Measures

1. **Code-Level Improvements**
   - Implement service-to-service authentication (mutual TLS)
   - Add privilege escalation detection middleware
   - Implement just-in-time (JIT) privilege access
   - Add DEK cache access rate limiting

2. **Infrastructure Hardening**
   - Enable AWS GuardDuty, Security Hub (if not already)
   - Implement VPC private subnets (no public IPs)
   - Enable CloudTrail for all regions
   - Implement AWS Config for drift detection

3. **Monitoring Enhancements**
   - Add lateral movement correlation rules
   - Implement behavioral baselines for service-to-service calls
   - Enable real-time IAM activity monitoring
   - Add database connection source monitoring

4. **Process Improvements**
   - Quarterly privilege access reviews
   - Regular IAM permission audits
   - Automated credential rotation (30-day max)
   - Red team exercises (simulate lateral movement)

### Compliance Reporting

**Incident Report Template:**
```markdown
## Lateral Movement Incident Report

**Incident ID:** INC-LATERAL-<YYYYMMDD>-<seq>
**Date/Time:** <UTC timestamp>
**Severity:** P0
**MTTD:** <actual minutes>
**MTTR:** <actual minutes>
**Infrastructure Compromised:** YES/NO

### Summary
[Brief description of lateral movement attack path]

### Timeline
- [HH:MM] Initial compromise detected
- [HH:MM] Privilege escalation identified
- [HH:MM] Lateral movement to [services] detected
- [HH:MM] Compromised services isolated
- [HH:MM] Credentials rotated
- [HH:MM] Infrastructure rebuilt
- [HH:MM] Service restored

### Impact
- Initial compromise: [Service/account]
- Lateral movement targets: [Services accessed]
- Data exfiltrated: [YES/NO, how much]
- Persistence established: [YES/NO, type]
- Infrastructure compromised: [YES/NO, extent]

### Root Cause
[Analysis from RCA section]

### Preventive Actions
[List of zero trust and least privilege improvements]
```

## Escalation Matrix

| Condition | Escalate To | Timeline |
|-----------|-------------|----------|
| Lateral movement detected | CISO, Security Ops, Infrastructure | Immediate |
| IAM privilege escalation | CTO, AWS Support | Within 5min |
| Database credentials compromised | DBA team, CISO, CFO | Within 5min |
| Infrastructure compromise | Incident Commander, CEO, Board | Within 15min |
| Data exfiltration confirmed | Legal, PR, Regulators | Within 30min |

## Checklist

- [ ] Alert acknowledged
- [ ] Lateral movement pattern identified
- [ ] Initial compromise source traced
- [ ] Blast radius assessed
- [ ] Compromised services isolated
- [ ] IAM credentials revoked
- [ ] Database credentials rotated
- [ ] DEK cache cleared
- [ ] Persistence mechanisms removed
- [ ] Infrastructure rebuilt from IaC
- [ ] All credentials rotated
- [ ] Security posture validated
- [ ] Evidence archived
- [ ] Attack path documented
- [ ] Post-incident review completed
- [ ] Zero trust improvements deployed

## References

- [SECURITY_MONITORING.md](../SECURITY_MONITORING.md) - Full monitoring architecture
- [AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/)
- [MITRE ATT&CK - Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
- [Zero Trust Architecture (NIST SP 800-207)](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
