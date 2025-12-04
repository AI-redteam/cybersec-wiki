# **The Golden Ticket: Why SageMaker Presigned URLs are Your New Favorite Pivot Point**

Let’s be real: usually, when we talk about cloud security, we’re talking about S3 buckets left open to the world or over-permissive IAM roles attached to EC2 instances. But while everyone is watching the front door, the Data Science team is building a massive side entrance with Amazon SageMaker.

I’ve been deep-diving into SageMaker security assessments lately, specifically looking at how we access these environments. The verdict? **SageMaker Presigned URLs are the "Golden Tickets" of the AWS ecosystem.**

If you are a pentester or a Cloud Sec engineer, you need to understand how these URLs work because they are effectively bearer tokens that bypass your IDP, your MFA, and potentially your sanity.

## **The Two Flavors of Danger**

SageMaker has two main ways to run Jupyter, and both have their own unique flavor of risk:

1. **SageMaker Studio** (The new, integrated IDE)  
2. **SageMaker Notebook Instances** (The classic, EC2-based Jupyter servers)

Both rely on "Magic Links" to get users in. Let's break them down.

### **1\. SageMaker Studio: The "God Proxy" Risk**

At its core, Studio is a managed environment. To get a user in, AWS uses the API action sagemaker:CreatePresignedDomainUrl.

When this API is called, AWS spits out a URL that looks like this:

\[https://d-xxxxxxxx.studio.us-east-1.sagemaker.aws/auth?token=\](https://d-xxxxxxxx.studio.us-east-1.sagemaker.aws/auth?token=)...

The Threat:  
This isn't just a login link. It is a capability URL. Possession of this link is 10/10ths of the law. If I have this URL (and it hasn’t expired), I am that user. I don’t need their Okta password. I don’t need their YubiKey. I just paste the link, and boom—I have a shell in their container.  
The Real Pivot:  
In many environments, the IAM permission sagemaker:CreatePresignedDomainUrl is treated like a low-risk "read" permission. You’ll see it bundled into generic "DataScienceTeam" roles, often with a wildcard Resource scope (Resource: \*).  
If I compromise a low-level developer credential, I can run:

aws sagemaker create-presigned-domain-url \\  
    \--domain-id d-xxxxxxxx \\  
    \--user-profile-name Lead-Architect

AWS will happily hand me a URL for the *Admin’s* profile. I click it, I become the Admin, and I inherit their **SageMaker Execution Role** (which likely has full S3 access).

### **2\. Notebook Instances: The 12-Hour Party**

This is the "Old School" method, but it's still running in almost every AWS environment I see. It uses the API sagemaker:CreatePresignedNotebookInstanceUrl.

The Danger Multiplier:  
While Studio URLs are generally short-lived entry points, the sessions created by Notebook Instances are aggressive. The CLI has a flag called \--session-expiration-duration-in-seconds. The default? 12 Hours.  
aws sagemaker create-presigned-notebook-instance-url \\  
    \--notebook-instance-name My-Sensitive-Financial-Model \\  
    \--session-expiration-duration-in-seconds 43200

That means if I exfiltrate this URL from a log file, a browser history, or a proxy server, I have a valid shell for **half a day**.

## **The "VPC Only" Dilemma**

AWS provides a mechanism to lock this down called **"VPC Only" mode**.

In this configuration, the presigned URL creates a connection that *must* traverse a specific VPC Endpoint (vpce-interface). If you try to hit that URL from the public internet, it fails.

**The Reality:** I’ve tested this extensively. If a client is running strict "VPC Only" mode with proper network controls, the attack surface is tiny. It effectively neutralizes the threat of URL theft because the URL is useless outside the corporate network.

The Catch: "VPC Only" mode is a massive pain to implement.  
It requires setting up Route 53 inbound resolvers, managing DNS forwarding from corporate networks, and dealing with split-horizon DNS headaches just to get a data scientist’s laptop to talk to the Studio interface. Because of this friction, most organizations default to "Public Internet Only" mode.  
And that is where the fun begins.

## **How to Fix It: The Network Layer Lock**

Since identity-based restrictions can be tricky (and prone to misconfiguration), your best bet is to enforce **where** the request comes from. If you can't rely on the "Who," you must rely on the "Where."

For SageMaker Studio Domain URLs, you have three primary IAM condition keys that can stop an attacker in their tracks. You should be applying these to any IAM role that has permission to generate presigned URLs.

### **1\. The Classic: aws:sourceIp**

This is your first line of defense. It restricts the API call to a specific CIDR block.

* **Use Case:** Your data scientists connect via a corporate VPN with a static exit IP.  
* **The Policy:**  
  "Condition": {  
      "IpAddress": {  
          "aws:sourceIp": "203.0.113.0/24"  
      }  
  }

* **The Gotcha:** If your company uses a cloud proxy like Zscaler, your "Source IP" is dynamic and shared with other Zscaler customers. This condition becomes useless there.

### **2\. The Internal: aws:sourceVpc**

This condition ensures the request to generate the URL originates from *within* a specific VPC.

* **Use Case:** You require developers to log into a secure "Jump Box" or "Bastion Host" inside AWS to generate their notebook URLs.  
* **The Policy:**  
  "Condition": {  
      "StringEquals": {  
          "aws:sourceVpc": "vpc-12345678"  
      }  
  }

* **The Win:** Even if an attacker steals the AWS credentials, they can't generate a URL from their own laptop. They would need to compromise the Bastion host first.

### **3\. The Gold Standard: aws:sourceVpce**

This is the strongest control available. It enforces that the API request must traverse a specific **VPC Endpoint**.

* **Use Case:** You have a dedicated Interface Endpoint for SageMaker API calls, and you want to ensure no traffic creates URLs via the public internet API endpoints.  
* **The Policy:**  
  "Condition": {  
      "StringEquals": {  
          "aws:sourceVpce": "vpce-0xx11xx22xx33"  
      }  
  }

* **Why it rocks:** This binds the capability to your network infrastructure. Even if I have Admin credentials, if I'm not sitting on the network segment that routes through vpce-0xx..., I can't generate the URL.

## **Conclusion**

SageMaker presigned URLs are a feature, not a bug—but in the wrong hands, they are a bypass for your entire authentication stack.

While the documentation praises the security of VPC Endpoints (and they are right), the operational complexity often pushes teams toward the public internet configuration. If you find yourself in that bucket, implementing these three network-based IAM conditions is mandatory.

Treat sagemaker:CreatePresigned\* with the same respect you treat iam:PassRole. Because in the world of MLOps, they effectively grant the same power.