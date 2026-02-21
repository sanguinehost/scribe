# Composable Infrastructure Architecture

Scribe's infrastructure is designed to be **Platform-Agnostic**, **Modular**, and **Service-First**. By decoupling the application logic from the underlying cloud provider, we ensure that Scribe can be deployed globally with minimal vendor lock-in. We utilize **OpenTofu** for its modular flexibility and advanced security features, specifically native state encryption.

## 1. Abstracting the "Platform" vs. "Application"

We separate infrastructure into two distinct layers:

### 1.1 Platform Modules
Provider-specific resources managed by OpenTofu/Terragrunt that satisfy a generic interface.
- **Networking**: VPCs, Subnets, Peering (AWS VPC vs. GCP VPC).
- **Compute**: Managed container platforms (AWS ECS vs. GCP Cloud Run).
- **Persistence**: Managed databases (AWS RDS vs. GCP Cloud SQL).
- **Security**: State encryption keys (AWS KMS) and vault configurations.

### 1.2 Application Modules
Generic configurations that define how the Scribe service interacts with the platform.
- **Service Mesh (Traefik)**: Ingress routes, middleware, and entrypoints.
- **Observability (OpenObserve)**: OTLP sinks and storage buckets.
- **W3C Context**: Trace propagation standards across distributed nodes.

## 2. Orchestration with Terragrunt & OpenTofu

Terragrunt acts as the "glue" that binds Platform and Application layers together across multiple environments and regions, orchestrating the OpenTofu engine.

### 2.1 State Encryption (OpenTofu Native)
To ensure the highest security posture, we utilize OpenTofu's native state encryption. This encrypts the *contents* of the state file using a managed key (AWS KMS), preventing exposure of even transient secrets.

### 2.1 The "DRY" Principle
Global configurations for providers and remote state are defined in a single root `terragrunt.hcl`:
```hcl
remote_state {
  backend = "s3"
  config = {
    bucket = "scribe-terraform-state"
    region = "us-east-1"
  }
}

generate "provider" {
  path      = "provider.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<EOF
provider "aws" {
  region = "us-east-1"
}
EOF
}
```

## 3. Ingress: Traefik for Distributed Scribe

We utilize **Traefik** as the primary ingress controller due to its superior support for containerized environments and dynamic configuration.

### 3.1 ECS/Docker Service Discovery
Traefik automatically detects Scribe containers and OpenObserve nodes, eliminating the need for manual ALB target group management.

### 3.2 Security & SSL
- **Platform-Managed TLS (AWS)**: We utilize AWS ACM on the Network Load Balancer (NLB) for robust, manageable SSL termination at the edge.
- **Application-Managed TLS (Generic)**: For non-cloud deployments, Traefik's native Let's Encrypt support is used.
- **Middlewares**: Standardized security headers and rate-limiting applied globally at the ingress boundary.

## 4. Management: Tailscale Secure Overlay

Direct management access to Scribe internal services (RDS, OpenObserve UI, SSM) is restricted through a **Tailscale** overlay network.
- **No Management Public IPs**: Internal services are only accessible via the Tailscale subnet router.
- **ACL Enforcement**: Identity-based access control for administrative tasks.
