---
date: 2025-11-25
authors:
  - been
categories:
  - Cloud Security
  - AWS
  - Threat Modeling
tags:
  - aws
  - iam
  - policies
  - threat-modeling
  - defense
description: Policy-to-threat-model mapping showing exactly which IAM policy types mitigate which attack classes - the reference table for analyzing IAM blast radius and privilege escalation paths
---

# AWS IAM Policy Types → Threat Models Mapping

A policy-to-threat-model mapping table showing exactly which IAM policy types mitigate which attack classes, why they matter, and what they do not protect against.

This is the reference table cloud security engineers, auditors, and pentesters use when analyzing IAM blast radius and privilege escalation paths.

<!-- more -->

## Policy Type → Threat Mitigation Table

| Policy Type | Primary Threats Mitigated | How it Mitigates | Threats NOT Mitigated |
|-------------|---------------------------|------------------|----------------------|
| **Identity-Based Policies** (managed/inline) | Excess privilege, unwanted API access, accidental misuse | Grant least privilege, deny unused APIs, enforce conditions (MFA, source IP, service restrictions) | Role assumption abuse, resource exposure, account-wide misconfigurations, cross-account access leaks |
| **Customer-Managed Policies** | Over-permissioning, privilege escalation via AWS-managed policies | Custom least-privilege definitions, tight scoping | Insecure trust policies, cross-account access, SCP bypasses |
| **AWS-Managed Policies** | None (they're broad) | Convenience only; no meaningful direct threat reduction | Over-permissioning, identity privilege escalation, lateral movement, exfiltration |
| **Inline Policies** | None (not a control), but binds policy lifecycle to identity | Used for break-glass or special cases | Over-permissioning, resource exposure, privilege escalation, cross-account abuse |
| **Resource-Based Policies** (S3, SQS, KMS, Lambda, API Gateway, ECR) | Cross-account data exfil, unintended public access, unauthorized invocation, lateral movement across accounts | Restrict principals directly; enforce who can access the resource even if identity policy allows more | Identity escalation, internal privilege escalation inside account, insider threat with valid credentials |
| **KMS Key Policies** (special resource policy) | Data exfiltration, ransomware via unauthorized encryption, privilege escalation via decrypt/grant | Explicitly controls who can encrypt/decrypt, rotate, or change the key policy | IAM-based privilege escalation outside KMS, trust policy abuse |
| **Trust Policies** (IAM Role trust relationships) | Privilege escalation via AssumeRole, cross-account takeover, lateral movement | Restricts who can assume roles; limits external principals; enforces STS external ID patterns | Over-permissive identity policies, KMS/S3 exposure, missing SCP guardrails |
| **Service Control Policies (SCPs)** | Account takeover impact, privilege escalation, disabling security tooling, creating new IAM users, bypassing region restrictions | Deny dangerous API calls globally; prevent creation of overpowered roles; block IAM modifications | Internal resource exposure, misconfigured trust/resource policies, insider threats with valid paths |
| **Permission Boundaries** | Developers creating over-privileged roles or policies, IAM privilege escalation in delegated admin environments | Enforces a maximum permission ceiling; prevents granting new permissions beyond boundary | Misconfigured resource policies, trust policy abuse, public S3 buckets, SCP gaps |
| **Session Policies** | Excess permission during federated or temporary access sessions | Restricts STS-issued credentials, applies ephemeral least-privilege | Long-lived IAM credentials, overly broad identity or resource policies |
| **ABAC** (Attribute-Based Access Control via Conditions + Tags) | Horizontal privilege escalation, multi-tenant data access, cross-environment bleed (dev → prod) | Restricts access dynamically via tags (e.g., project=alpha); isolates tenants | Trust policy escalation, broad identity permissions, untagged or incorrectly tagged resources |
| **Access Control Lists (ACLs)** | S3 object-level unwanted access (legacy), network-level allow/deny | Fine-grained object access; coarse-grained subnet rules | Modern IAM controls, role assumption, identity escalation, SCP bypasses |

---

## Threat Model → Policy Mapping (Inverse View)

**If the threat is… → Use these policies as primary controls**

| Threat | Primary Policy Controls | Why |
|--------|------------------------|-----|
| **Privilege escalation via AssumeRole** | Trust policies, SCPs | Trust policies restrict who can assume; SCPs globally deny role-creation/modification abuse |
| **Cross-account access / unauthorized external access** | Resource policies, trust policies, SCPs | Resource policies define allowed principals; trust policies restrict assumption; SCPs block accidental creation of cross-account roles |
| **Unintended public access** (S3, API, Lambda, ECR) | Resource policies, SCPs | Resource policies prevent public principals; SCPs deny `s3:PutBucketPolicy` mistakes |
| **Over-permissioned identities** (developers, users, CI/CD) | Permission boundaries, customer-managed policies | Boundaries set ceilings; custom L-P policies enforce least-privilege |
| **Data exfiltration** (S3, KMS, Secrets Manager) | Resource policies, KMS policies, SCPs | Resource & key policies enforce principal-level controls; SCP denies unapproved regions/paths |
| **Lateral movement inside AWS account** | Identity-based policies, trust policies, ABAC | Least privilege blocks pivot APIs; ABAC prevents tenant-to-tenant cross-contamination |
| **Accidental IAM misconfiguration** | SCPs, permission boundaries | SCP provides global guardrails; boundaries limit delegated IAM administrators |
| **Federated identity overreach** | Session policies | Restricts temporary credentials to a safe subset |
| **Insider threat with high privilege** | SCP deny rules, permission boundaries, KMS key separation | Hard deny prevents catastrophic damage; key policies define blast radius |
| **Service compromise** (EC2, Lambda, EKS) | Identity-based policies + resource policies + trust boundaries | Prevent compromised workloads from accessing privileged resources |

---

## Policy Misconfiguration → Compromise Paths

| Misconfiguration | Attack Path | Exploited By | Mitigation |
|------------------|-------------|--------------|------------|
| Overly broad trust policy (`"Principal": "*"`) | Cross-account role takeover | External attacker assumes role from their account | Explicit principal ARNs, ExternalId requirement, `aws:SourceAccount` condition |
| Missing `iam:PassedToService` condition | PassRole privilege escalation | Attacker passes admin role to Lambda/EC2 they control | Restrict PassRole with `iam:PassedToService` condition |
| `AdministratorAccess` on EC2 instance role | Service compromise → full account takeover | Compromised instance SSRF or RCE gains admin | Least privilege per workload, deny IAM from instance roles |
| Public S3 bucket with PII | Data breach, compliance violation | Direct download via HTTP | S3 Block Public Access (org-wide), resource policies |
| No MFA on root/admin users | Credential stuffing → full compromise | Phished or leaked credentials | Enforce MFA via SCP deny without MFA |
| `s3:*` on `Resource: "*"` | Unrestricted data exfiltration | Insider or compromised account syncs all buckets | Scope to specific buckets, deny cross-account copy |
| Cross-account KMS key policy allowing external decrypt | Data exfiltration via decryption | External account decrypts sensitive data | Explicit principal allow-list, `kms:ViaService` restriction |
| SCPs not applied to management account | Management account bypass | Attacker targets root account or org master | Apply controls at account boundary (trust policies, CloudTrail) |
| Inline policy granting `iam:*` to non-admin | Privilege escalation to admin | User/role creates new admin policy and attaches it | Permission boundary, SCP deny on IAM modification |
| No session policy on federated users | Over-privileged SSO sessions | Federated user gains excessive temp permissions | Apply restrictive session policies at STS assume time |

---

## IAM Privilege Escalation Paths Reference

| Method | IAM Actions Required | Threat | Mitigation |
|--------|---------------------|--------|------------|
| **AttachUserPolicy / AttachRolePolicy** | `iam:AttachUserPolicy`, `iam:AttachRolePolicy` | Attach `AdministratorAccess` to self or controlled identity | SCP deny, require MFA, explicit principal conditions |
| **CreateAccessKey** | `iam:CreateAccessKey` | Create keys for privileged users | SCP deny for non-admins, CloudTrail alert |
| **CreatePolicyVersion** | `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion` | Overwrite existing managed policy with admin permissions | SCP deny, version control + approval workflow |
| **PassRole + CreateFunction/RunInstances** | `iam:PassRole`, `lambda:CreateFunction` or `ec2:RunInstances` | Pass admin role to service attacker controls | `iam:PassedToService` condition, deny passing privileged roles |
| **UpdateAssumeRolePolicy** | `iam:UpdateAssumeRolePolicy` | Modify trust policy to allow attacker principal | SCP deny except for specific admin role |
| **CreateUser + AddUserToGroup** | `iam:CreateUser`, `iam:AddUserToGroup` | Create user and add to admin group | SCP deny user creation, enforce roles-only |
| **SetDefaultPolicyVersion** | `iam:SetDefaultPolicyVersion` | Rollback to previous over-permissive policy version | SCP deny, audit policy version history |
| **PutUserPolicy / PutRolePolicy** | `iam:PutUserPolicy`, `iam:PutRolePolicy` | Attach inline admin policy | SCP deny inline policies on production roles |
| **AssumeRole chaining** | `sts:AssumeRole` across multiple roles | Chain through roles to escalate to higher privilege | Trust policies with specific source conditions, break chains |
| **Lambda + Environment Variable Injection** | `lambda:UpdateFunctionConfiguration`, `lambda:InvokeFunction` | Inject credentials via env vars in privileged Lambda | Deny config updates, use Secrets Manager instead |

---

## Critical Policy Patterns

### 1. SCP: Global IAM Protection

**Apply to:** All accounts in AWS Organization (except management if needed)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyIAMPrivilegeEscalation",
      "Effect": "Deny",
      "Action": [
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:PutUserPolicy",
        "iam:PutRolePolicy",
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:UpdateAssumeRolePolicy"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/SecurityAdmin"
        }
      }
    },
    {
      "Sid": "DenyCloudTrailDisable",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyRegionBypass",
      "Effect": "Deny",
      "NotAction": [
        "iam:*",
        "sts:*",
        "cloudfront:*",
        "route53:*",
        "support:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": ["us-east-1", "us-west-2"]
        }
      }
    }
  ]
}
```

### 2. Trust Policy: Restrict AssumeRole with Conditions

**Apply to:** All IAM roles

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/TrustedAppRole"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "unique-external-id-12345",
          "aws:SourceAccount": "123456789012"
        },
        "IpAddress": {
          "aws:SourceIp": ["10.0.0.0/8", "172.16.0.0/12"]
        }
      }
    }
  ]
}
```

### 3. Resource Policy: S3 Bucket Defense-in-Depth

**Apply to:** S3 buckets with sensitive data

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnencryptedUploads",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::sensitive-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "aws:kms"
        }
      }
    },
    {
      "Sid": "DenyExternalAccess",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::sensitive-bucket",
        "arn:aws:s3:::sensitive-bucket/*"
      ],
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalAccount": "123456789012"
        }
      }
    },
    {
      "Sid": "RequireVPCEndpoint",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::sensitive-bucket",
        "arn:aws:s3:::sensitive-bucket/*"
      ],
      "Condition": {
        "StringNotEquals": {
          "aws:SourceVpce": "vpce-1234567"
        }
      }
    }
  ]
}
```

### 4. Permission Boundary: Developer Self-Service

**Apply to:** Roles created by developers

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowDeveloperServices",
      "Effect": "Allow",
      "Action": [
        "lambda:*",
        "dynamodb:*",
        "s3:*",
        "logs:*",
        "xray:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:RequestedRegion": "us-east-1"
        }
      }
    },
    {
      "Sid": "DenyIAMChanges",
      "Effect": "Deny",
      "Action": [
        "iam:*",
        "organizations:*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyLeavingBoundary",
      "Effect": "Deny",
      "Action": [
        "iam:DeleteRolePermissionsBoundary",
        "iam:PutRolePermissionsBoundary"
      ],
      "Resource": "*"
    }
  ]
}
```

### 5. KMS Key Policy: Encryption Key Isolation

**Apply to:** KMS keys encrypting sensitive data

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Enable IAM policies",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:root"
      },
      "Action": "kms:*",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "kms:CallerAccount": "123456789012"
        }
      }
    },
    {
      "Sid": "AllowServiceUsage",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/ProductionAppRole"
      },
      "Action": [
        "kms:Decrypt",
        "kms:DescribeKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "kms:ViaService": [
            "s3.us-east-1.amazonaws.com",
            "secretsmanager.us-east-1.amazonaws.com"
          ]
        }
      }
    },
    {
      "Sid": "DenyKeyPolicyChanges",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "kms:PutKeyPolicy",
        "kms:ScheduleKeyDeletion"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::123456789012:role/KeyAdmin"
        }
      }
    }
  ]
}
```

### 6. Identity Policy with ABAC: Multi-Tenant Isolation

**Apply to:** Users/roles in multi-tenant environments

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowResourceAccessByTag",
      "Effect": "Allow",
      "Action": [
        "ec2:*",
        "s3:*",
        "lambda:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/Project": "${aws:PrincipalTag/Project}",
          "aws:ResourceTag/Environment": "${aws:PrincipalTag/Environment}"
        }
      }
    },
    {
      "Sid": "DenyUntaggedResourceCreation",
      "Effect": "Deny",
      "Action": [
        "ec2:RunInstances",
        "s3:CreateBucket",
        "lambda:CreateFunction"
      ],
      "Resource": "*",
      "Condition": {
        "Null": {
          "aws:RequestTag/Project": "true"
        }
      }
    }
  ]
}
```

---

## Auditing Checklist: Evidence → Policy Review

Use this when auditing AWS environments:

| Audit Question | Evidence to Collect | Policy Type to Review | Red Flag |
|----------------|---------------------|----------------------|----------|
| Can any identity modify IAM policies? | CloudTrail: `AttachUserPolicy`, `PutRolePolicy` | Identity policies, SCPs | Actions allowed without MFA or from unexpected principals |
| Can roles be assumed from external accounts? | IAM role trust policies | Trust policies | `"Principal": "*"` or broad external account IDs |
| Are S3 buckets publicly accessible? | S3 bucket policies, ACLs | Resource policies | `"Principal": "*"` with Allow effect |
| Can KMS keys be used cross-account? | KMS key policies | KMS key policies | External account in principal without ExternalId |
| Can developers create admin roles? | Permission boundaries on dev roles | Permission boundaries | No boundary or boundary allows IAM actions |
| Are CloudTrail logs protected? | S3 bucket policy on CloudTrail bucket | Resource policies, SCPs | Principals can delete objects or disable logging |
| Can instance roles access IAM? | EC2 instance role policies | Identity policies | IAM actions allowed on compute roles |
| Are there privilege escalation paths? | IAM policies with PassRole + CreateFunction | Identity policies, trust policies | PassRole without `iam:PassedToService` condition |
| Is MFA enforced for sensitive actions? | IAM policies, SCP conditions | SCPs, identity policies | No `aws:MultiFactorAuthPresent` condition on critical APIs |
| Can secrets be accessed from outside VPC? | Secrets Manager/SSM access patterns | Resource policies, VPC endpoints | No `aws:SourceVpce` restriction |

---

## Quick Reference: Policy Evaluation Logic

**Order of evaluation** (first explicit deny wins):

1. **Deny evaluation**: Any explicit Deny → access denied
2. **Organization SCPs**: Allow in all SCPs? → continue, else deny
3. **Resource-based policies**: Explicit Allow? → access allowed (skip identity checks for cross-account)
4. **Permission boundaries**: Allow in boundary? → continue, else deny
5. **Session policies**: Allow in session? → continue, else deny
6. **Identity-based policies**: Explicit Allow? → access allowed, else deny by default

**Key takeaways:**
- Explicit Deny always wins (use for security guardrails)
- Default is Deny (must have explicit Allow somewhere)
- Resource policies can allow cross-account without identity policy
- Use SCPs for global account-level controls
- Use permission boundaries to limit delegation

---

This reference is a living document. Bookmark it, share it with your security team, and use it during AWS assessments, audits, and red team engagements.
