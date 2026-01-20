---
date: 2025-01-15
authors:
  - been
categories:
  - Security Research
  - Cloud Security
tags:
  - aws
  - red-teaming
  - cloud-security
  - credential-extraction
  - browser-extension
description: How I automated AWS Console credential extraction into a Chrome extension, turning a manual red team TTP into a point-and-click tool that bypasses VDI and DLP controls.
---

# Cloud Red Team TTPs: Operationalizing AWS Console Credential Extraction

For years, one of my go-to TTPs during red team engagements has been bridging the gap between AWS Console access and the CLI. We've all been there: you land on a compromised workstation, or you're stuck in a restrictive VDI environment. You have access to the AWS Console via the browser, but you're handcuffed. You can't run scripts, you can't use tools like Pacu, and you can't mass-enumerate resources efficiently.

I knew the credentials had to be *somewhere*. AWS doesn't use magic; the browser has to authenticate API calls somehow.

<!-- more -->

## **The Origin Story: Spite-Driven Development**

The spark for this tool actually came from a specific engagement a few years ago. I was hired to perform a threat model and configuration review, but the client's IT department was absolutely immovable. They refused to provision access keys or IAM users for me. Their demand was simple and frustrating: "You do everything in the Console."

I ended up spending most of that engagement not reviewing configs, but digging into the browser's network tab out of necessity (and a bit of spite). I realized that if I couldn't get them to give me keys, I would just take the ones they were sending to my browser. I developed a manual strategy of scraping these requests to get my CLI access anyway. 

This sounds silly… but in 20 minutes after securing CLI creds I was able to run scripts that found dozens of findings compared to the few I had found manually. 

For the longest time, that workflow was a manual nightmare. I’d open Chrome DevTools or proxy traffic through Burp Suite, filter for specific keywords, and manually copy-paste JSON tokens into my terminal. It was tedious, prone to copy-paste errors, and worst of all, stressful. These temporary tokens often have a 15-minute expiration window. By the time I had formatted the credentials for \~/.aws/credentials, half my access window was gone.

I finally got tired of the manual grind and decided to automate it. Here is the research process behind **clier**, and how I used AI to turn a complex manual TTP into a point-and-click exploit.

## **Bypassing the Unbypassable**

What makes clier unique is that it bypasses the controls that organizations rely on to "sandbox" users.

Companies spend millions on Virtual Desktop Infrastructures (VDIs), Data Loss Prevention (DLP) agents, and restrictive IAM policies to ensure that credentials never leave the secure environment. They assume that by forcing a user into the GUI, they are preventing mass data exfiltration or automated attacks.

clier breaks that assumption. It proves that **if the browser can see it, you can take it.**

By hooking into the browser's legitimate fetch process, clier renders those VDI restrictions moot. It doesn't matter if you block the clipboard or disable file downloads; if the Console works, clier works. This tool essentially turns a "read-only" GUI session into fully scriptable CLI access, completely sidestepping the intended security boundary.

## **The Research: Chasing Undocumented Endpoints**

The core challenge wasn't just finding *a* credential; it was finding the *right* credential. AWS API endpoints for the console are completely undocumented, and reverse-engineering them was a lesson in frustration.

### **The browsercreds Trap**

Initially, I spent a lot of time looking at calls to /tb/browsercreds. It seemed obvious—it literally says "browser creds." But the tokens returned here were often inconsistent, formatted strangely, or didn't provide the access I expected when plugged into the CLI. It was a rabbit hole that ate up hours of research time.

### **The Breakthrough: Service Scoping**

The "lightbulb moment" came when I realized that the AWS Console doesn't just use one master session token for everything. It requests *scoped* credentials.

I started noticing a pattern in the network traffic. When I navigated to S3, the browser made a call to /s3/tb/creds. When I went to EC2, it hit /ec2/tb/creds.

I realized that https://{region}.console.aws.amazon.com/{service}/tb/creds was the golden goose.

However, there was a catch: Scoping.  
The credentials returned by the S3 endpoint are often scoped only for S3. If you grab those keys and try to run aws ec2 describe-instances, you get an Access Denied error. This explained why my manual extraction had been so hit-or-miss in the past. I wasn't just grabbing "AWS keys"; I was grabbing service-specific STS tokens.

## **From Research to Tooling with Claude**

Once I understood the logic—intercept requests to \*/tb/creds, parse the JSON, and map them to the service name—I needed to build the tool.

I’m a security researcher, not a frontend developer. I know how to break things, but writing a Manifest V3 Chrome Extension with its complex service workers, isolated worlds, and message passing is a headache I didn't want to deal with.

This is where I brought in Claude.

Instead of writing the boilerplate myself, I provided Claude with my research findings:

1. **The Goal:** Intercept fetch/XHR requests.  
2. **The Pattern:** /\\/(\[^\\/\]+)\\/tb\\/creds/i  
3. **The Logic:** Clone the response stream (so we don't crash the actual AWS console), extract the JSON, and bubble it up to the UI.

Claude helped generate the "monkey-patching" logic in injected.js that sits in the browser's Main World. It hooks window.fetch, checks if the URL matches my regex, and if it does, it silently emits the credentials to the extension before the AWS Console even finishes rendering the page.

## **The Result: clier**

The result is **clier** (Console \-\> CLI). It automates years of my manual suffering into a background process.

It handles the complexity I discovered during research:

* **Service Separation:** It creates a tab for each service (S3, EC2, Lambda) so you know exactly what access you have.  
* **Time Management:** It parses the expiration timestamp and gives you a countdown, so you know exactly how much time you have left on that 15-minute token.  
* **VDI Escape:** I added a QR code generator. If you are in a VDI that blocks clipboard sharing to your host, you can scan the screen with your phone to extract the keys.

## **The Fix: An Architectural Dead End?**

This technique highlights a significant architectural challenge for AWS. Currently, there isn't a clean way for them to "patch" this without breaking the fundamental way the Console works.

The Console is a Single Page Application (SPA). To function, it *must* have temporary credentials in the browser's memory to authenticate API calls to backend services (like listing S3 buckets or describing EC2 instances).

Currently, there are no granular controls to stop this specific extraction vector. The only effective mitigation is applying strict **Source IP restrictions** (e.g., aws:SourceIp) to the IAM roles users assume when logging into the Console. However, this is a nuclear option. Enforcing Source IP restrictions breaks the access model for:

* Users with dynamic IPs.  
* Distributed teams.  
* Users accessing the console via corporate VPNs or proxies that rotate IPs.

Until a fundamental change occurs in how the Console authenticates its own API calls, tools like clier will continue to bridge the gap between "secure" console access and full CLI control.

You can check out the code and grab the extension here: [Click ME Quick](https://github.com/AI-redteam/clier)