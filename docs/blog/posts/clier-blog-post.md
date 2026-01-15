---
date: 2026-01-14
authors:
  - been
categories:
  - Security Research
  - Cloud Security
tags:
  - aws
  - cloud-security
  - tools
  - iam
  - red-teaming
description: Why browser-based AWS Console access controls are fundamentally flawed and how clier demonstrates that console access effectively equals CLI access.
---

# Clier: Why Your "Secure" AWS Console Access Might Not Be

When security teams design controlled access to AWS, they often rely on a simple assumption: if users can only access the AWS Console through a locked-down browser in a VDI environment, credentials can't leave that environment.

**That assumption is wrong.**

<!-- more -->

## Introducing clier

[clier](https://github.com/AI-redteam/clier) is a browser extension that extracts AWS STS credentials directly from the AWS Console session. It's the reverse of [consoler](https://github.com/NetSPI/aws_consoler)—while consoler takes CLI credentials and provides console access, clier takes console access and provides CLI credentials.

The tool works by intercepting the `/console/tb/creds` API endpoint that AWS Console uses internally to fetch temporary credentials for making API calls. These credentials exist only in browser memory (not localStorage or cookies), but they're trivially accessible to any code running in the page context.

Once extracted, users can copy credentials in multiple formats:
- Bash environment variables
- PowerShell environment variables  
- AWS credentials file format
- JSON

## The Security Model That Doesn't Work

Many organizations implement AWS access controls like this:

1. Users connect to a VDI or virtual browser
2. The VDI has a pre-authenticated session to AWS Console
3. Users can click around the console but "can't" get raw credentials
4. Therefore, all AWS access is logged and controlled through the console

This model assumes the browser is a black box that hides the underlying API credentials. It isn't.

### What's Actually Happening

When you use the AWS Console, your browser isn't making magic UI calls—it's making the same STS-signed API calls that the CLI makes. The console needs credentials to sign these requests, and those credentials have to exist somewhere the JavaScript can access them.

AWS fetches these credentials from an internal endpoint and stores them in the JavaScript heap. Any browser extension, DevTools console, or injected script can:

1. Intercept the fetch response
2. Read the credentials from memory
3. Exfiltrate them via copy/paste, screenshots, or network requests

## Real Attack Scenarios

### Scenario 1: The Frustrated Developer

A developer has console-only access through a corporate VDI. They need to run a quick AWS CLI command but don't have CLI credentials. They install clier (or write the 50 lines of JavaScript themselves), extract the credentials, and paste them into their local terminal.

Now they're operating outside all the VDI logging and controls.

### Scenario 2: The Compromised Browser

An attacker gets code execution in the VDI browser—maybe through a malicious extension, XSS in an internal tool, or a supply chain attack. They inject the credential extraction code, exfiltrate the temporary STS credentials, and now have API access from outside the controlled environment.

### Scenario 3: The Insider Threat

An employee with console access wants to maintain access after leaving the company. They extract and store credentials. While STS credentials expire, they can automate extraction while they still have access, maintaining a rolling set of valid credentials.

## What Security Teams Should Do

### 1. Don't Rely on Browser-Based Access Control

If your security model depends on users not having raw credentials, browser-based console access doesn't achieve that. The credentials exist and are extractable.

### 2. Implement Proper IAM Controls

Instead of trying to hide credentials, assume users have them and implement controls accordingly:

- **Short session durations**: Reduce the window of exposure
- **IP-based restrictions**: STS credentials can be scoped to source IPs via IAM policies
- **Service Control Policies**: Limit what credentials can do regardless of who has them
- **VPC endpoints with policies**: Require API calls to come through specific network paths

### 3. Monitor for Credential Exfiltration Patterns

Look for signs that console credentials are being used outside expected patterns:

- API calls from IPs outside your VDI range
- CLI-style API patterns (vs console's specific call patterns)
- User agents that don't match expected browsers
- Credential usage after VDI session ends

### 4. Use AWS IAM Identity Center Properly

If you need controlled access, use IAM Identity Center with:

- Session policies that restrict credential scope
- Conditions that limit where credentials work
- Permission sets designed for console-only access patterns

### 5. Consider Client Certificate Authentication

For high-security environments, require mutual TLS that ties sessions to specific VDI instances. Extracted credentials become useless without the client certificate.

## The Uncomfortable Truth

clier isn't novel or sophisticated. Anyone with basic JavaScript knowledge can write equivalent code in minutes. The AWS Console's credential endpoint has been known for years.

The tool's value is in making the risk concrete. If your security architecture assumes console-only users can't get CLI access, test that assumption. Install clier in your VDI and see what happens.

**You can't secure what you don't understand.**

## Conclusion

Browser-based access control is a speed bump, not a barrier. Any security model that relies on users not having credentials—when those credentials must exist for the application to function—is fundamentally flawed.

Design your AWS access controls assuming that anyone with console access effectively has CLI access. Implement defense in depth: network controls, IAM policies, monitoring, and short credential lifetimes.

And maybe give clier a try on your own systems. Better you find out than someone else.

---

*clier is available at [github.com/your-repo/clier](https://github.com/your-repo/clier). Use responsibly and only on systems you're authorized to test.*
