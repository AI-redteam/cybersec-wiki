---
date: 2025-12-08
authors:
  - been
categories:
  - Cloud Security
  - AWS
tags:
  - aws
  - sagemaker
  - token-vending-machine
  - iam
  - lambda
  - lateral-movement
  - zero-trust
description: Building a Token Vending Machine pattern to eliminate lateral movement risks in SageMaker by removing direct IAM permissions from users and centralizing presigned URL generation through a Lambda-based broker with strict validation and external logging.
---

# **Kill the Keys: Building a SageMaker Vending Machine to Stop Lateral Movement**

In my last post, we talked about how SageMaker Presigned URLs are effectively "Golden Tickets" to your ML environment. We established that giving users direct IAM permission to generate these tickets (sagemaker:CreatePresigned\*) is a recipe for disaster—specifically, lateral movement disaster.

<!-- more -->

If Alice has the permission to generate a URL, and your IAM policy isn't perfectly scoped to her specific UserProfile ARN, Alice can generate a URL for **Bob**, **Admin**, or **Root-God-Mode**.

The "VPC Only" fix I mentioned last time is great, but it’s heavy infrastructure. Today, we’re going to talk about the **Application Layer fix**: The Token Vending Machine.

## **The Strategy: "Take Away the Keys"**

The most secure IAM policy for a Data Scientist is **no permissions at all.**

In this architecture, we strip the sagemaker:CreatePresignedDomainUrl permission from every human user. Instead, we give that permission to exactly one entity: **A Lambda Function.**

We call this the **Vending Machine Pattern** (or Broker Pattern).

### **The User Flow**

Instead of a user running an AWS CLI command or clicking a button in the AWS Console, the flow looks like this:

1. **The User** logs into your internal Corporate Portal (e.g., https://datascience.corp).  
2. **The Portal** authenticates them via your IdP (Okta, AD, etc.).  
3. **The Portal** calls an internal API (Amazon API Gateway).  
4. **The API** triggers a Lambda function (The Clerk).  
5. **The Lambda** validates the request logic (e.g., "Is Alice allowed to access the 'Finance' profile?").  
6. **The Lambda** calls SageMaker to generate the URL.  
7. **The URL** is returned to the user, and their browser auto-redirects.

## **The Blueprint: Architecting the Vending Machine**

To build this, you need four core components. Think of this as the "Starter Kit" for your platform engineering team.

### **1\. The Front Door (Amazon API Gateway)**

* **Role:** Traffic management and initial authorization.  
* **Why:** Never expose your Lambda directly. API Gateway handles throttling (so Alice doesn't spam create requests), WAF integration, and standardizes your API surface.

### **2\. The Brain (AWS Lambda)**

* **Role:** The logic engine.  
* **Why:** This is the *only* entity in your entire account that holds the sagemaker:CreatePresignedDomainUrl permission. It runs your Python/Boto3 logic to validate *who* is asking for *what*.

### **3\. The Ledger (Amazon DynamoDB or SSM Parameter Store)**

* **Role:** The "Truth Source" for permissions.  
* **Why:** You need a map that says alice@corp.com is allowed to access UserProfile: Finance-Alice. **Do not** hardcode this in your Lambda. Use a fast, external look-up table so you can revoke access without redeploying code.

### **4\. The Watchtower (External Logging)**

* **Role:** The immutable audit trail.  
* **Why:** As mentioned later, you need logs that exist *outside* of AWS CloudTrail to prove intent during an incident.

### **Securing the Clerk (Who Watches the Watchmen?)**

If you build a Vending Machine, it becomes a high-value target (a "Tier 0" asset). You must secure it with the same paranoia you treat your Root User.

* **Strict IAM Scope:** The Lambda's Execution Role should have sagemaker:CreatePresignedDomainUrl scoped strictly to Resource: arn:aws:sagemaker:\*:\*:user-profile/\*. It should **never** have Resource: \*.  
* **Private APIs Only:** Your API Gateway should be a **Private API** accessible only from within your VPC (connected via Interface Endpoint). Do not put this on the public internet.  
* **Strong Authentication:** Use a Custom Authorizer (Lambda Authorizer) or Cognito to validate the JWT from your IdP. The Vending Machine should never accept unauthenticated requests.  
* **Input Sanitization:** Validate the UserProfileName against a strict allow-list from your Ledger. Never blindly pass user input to the boto3 client.

## **Why This Wins (The Security ROI)**

Building a small web app might seem like overkill compared to just writing an IAM policy, but here is why the Enterprise security teams do it this way:

### **1\. It Solves the "Zscaler Problem"**

As we discussed, aws:sourceIp is useless if your users are behind a dynamic corporate proxy like Zscaler.  
In this model, the Lambda Function is the one calling the SageMaker API.

* You put the Lambda inside your VPC.  
* You attach a Security Group to the Lambda.  
* You lock down the SageMaker API to **only accept requests from that Lambda's Private IP** (or better yet, its specific IAM Role).  
* **Result:** The user's IP doesn't matter. The request is always internal.

### **2\. Context-Aware Auditing**

CloudTrail logs for direct IAM calls are dry: User:Alice called CreatePresignedUrl.  
But your Vending Machine logs can be rich with business context:

* *"Alice requested access to Project-X-Notebook."*  
* *"Request Denied: Alice is not in the 'Project-X' AD Group."*  
* *"Request Approved: Ticket \#JIRA-1234 linked to session."*

### **3\. Zero-Trust Logic**

You can write Python logic that IAM simply cannot handle.

* *Time-based Access:* "No notebooks allowed on weekends."  
* *Budget-based Access:* "Team Finance has exceeded their compute budget; deny login."  
* *Four-Eyes Principle:* "Alice cannot login to Production unless Bob approves it via Slack."

## **The "Black Box" Flight Recorder: Logging Outside the Blast Radius**

There is a nightmare scenario in Cloud Security: An attacker gains Admin access and nukes your CloudTrail logs and S3 buckets before doing their dirty work. In a pure AWS environment, you are now flying blind.

This is where the Vending Machine shines as a **survivable log plane**.

Because your Vending Machine is a standalone application, it should be configured to ship logs to an external SIEM (like Splunk, Datadog, or Sumo Logic) **before** it ever calls the AWS API.

* **The Detective Control:** If your AWS logs go dark, your Vending Machine logs remain untouchable. You can see exactly who requested the last session before the breach occurred. This "Black Box" exists outside the AWS control plane, giving you forensic depth that AWS CloudTrail alone cannot provide.  
* **The Corrective Control:** You can set up alerts on the Vending Machine itself. If User:Alice requests 50 URLs in 1 minute, you can block her at the application layer *before* she ever touches the SageMaker API limits.

By decoupling the "Request" log from the "AWS Execution" log, you create depth. You have a record of intent that exists outside the blast radius of a compromised AWS account.

## **The Compliance Hammer (HIPAA & Friends)**

If you are working in Healthcare (HIPAA) or Finance (PCI/SOC2), the Vending Machine isn't just a "nice to have"—it's often the only way to sanely pass an audit.

### **1\. Enforcing the "Minimum Necessary" Rule**

HIPAA mandates that access to PHI (Protected Health Information) is limited to the "minimum necessary" to perform a job.

* **Direct IAM:** Often relies on wildcard resources (Resource: \*) because managing 1,000 individual user policies is impossible. This technically allows lateral movement, violating the rule.  
* **Vending Machine:** The code strictly enforces one-to-one mapping. User:Alice can *only* generate a URL for Profile:Alice. You can prove this to an auditor by showing them 10 lines of Python code rather than 10,000 lines of JSON policy.

### **2\. The Attribution Problem**

In a direct access model, if a "Shared Role" generates a URL, CloudTrail might just show AssumedRole:DataScienceTeam. Who was that? Was it Alice? Was it Bob?  
With a Vending Machine, your application logs capture the Federated Identity (alice@hospital.org) before the AWS call is ever made. You have a definitive, unbreakable link between a human ID and a Notebook Session.

### **3\. Session Termination**

HIPAA requires strict controls on session timeouts.

* **Direct IAM:** Users can use the CLI to set \--session-expiration-duration-in-seconds to the max (12 hours) effectively creating a persistent backdoor.  
* **Vending Machine:** You hardcode the limit in the Lambda. "Oh, you want a 12-hour session? Too bad. The Vending Machine only mints 1-hour tickets." This enforces security hygiene programmatically.

## **Build vs. Buy (AWS Identity Center)**

You might be asking: *"Doesn't AWS Identity Center (SSO) do this automatically?"*

**Yes, it does.** If you use AWS Identity Center integration for SageMaker, AWS runs a managed version of this Vending Machine for you. It handles the federation and the URL generation.

**So why build your own?**

1. **Custom Portals:** You want SageMaker embedded in your own internal developer portal (Backstage, etc.), not the AWS Console.  
2. **Strict Governance:** You want to enforce logic that AWS SSO doesn't support (e.g., "You must have a valid PagerDuty shift to log in").  
3. **Complex Networking:** You need the URL generation to happen from a specific VPC IP to satisfy a paranoid Service Control Policy (SCP).

## **Conclusion**

If you are a small shop, direct IAM permissions might be fine. But if you are scaling up, relying on developers to *not* click the "Generate URL" button for their neighbor is a losing strategy.

The Vending Machine pattern moves security from **Policy Configuration** (which is brittle) to **Application Logic** (which is testable).

Kill the keys. Hire a clerk. Secure the model.

Amazon SageMaker for Healthcare and Life Sciences Use Cases  
This video provides further context on how healthcare organizations utilize SageMaker, which aligns directly with the compliance section of this post.