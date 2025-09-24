# Defensive Detection Tools

Comprehensive guide to security monitoring, threat detection, and incident response tools for blue team operations.

## SIEM and Log Analysis

### Splunk - Security Information and Event Management

#### Basic Search and Investigation
```bash
# Search for failed login attempts
index=security sourcetype=linux_secure "Failed password"

# Time range searches
index=security earliest=-24h latest=now

# Statistical analysis
index=security source="/var/log/auth.log" | stats count by user

# Field extraction and filtering
index=security | search src_ip="192.168.1.100" | table _time, src_ip, dest_port, action

# Correlation searches
index=security | transaction src_ip startswith="login attempt" endswith="login success"
```

#### Advanced Splunk SPL
```bash
# Detect brute force attacks
index=security source="/var/log/auth.log" "Failed password"
| stats count by src_ip
| where count > 10
| sort -count

# Network anomaly detection
index=network
| eval mb_transferred=bytes/1024/1024
| stats avg(mb_transferred) as avg_mb, stdev(mb_transferred) as stdev_mb by src_ip
| where mb_transferred > avg_mb + (3 * stdev_mb)

# Threat hunting with subsearches
index=security
[ search index=threat_intel indicator_type="ip"
| return indicator ]

# Custom alerting
index=security error
| eval severity=case(
    like(_raw, "%CRITICAL%"), 5,
    like(_raw, "%ERROR%"), 4,
    like(_raw, "%WARNING%"), 3,
    1=1, 2
)
| where severity >= 4
```

### ELK Stack (Elasticsearch, Logstash, Kibana)

#### Elasticsearch Queries
```bash
# Basic search for authentication events
curl -X GET "localhost:9200/logstash-*/_search" -H 'Content-Type: application/json' -d'
{
  "query": {
    "match": {
      "message": "authentication failure"
    }
  }
}'

# Time-based queries
curl -X GET "localhost:9200/security-*/_search" -H 'Content-Type: application/json' -d'
{
  "query": {
    "bool": {
      "must": {
        "match": { "event_type": "login" }
      },
      "filter": {
        "range": {
          "@timestamp": {
            "gte": "now-1h"
          }
        }
      }
    }
  }
}'

# Aggregation queries for analysis
curl -X GET "localhost:9200/network-*/_search" -H 'Content-Type: application/json' -d'
{
  "size": 0,
  "aggs": {
    "top_source_ips": {
      "terms": {
        "field": "source_ip.keyword",
        "size": 10
      }
    }
  }
}'
```

#### Logstash Configuration Examples
```bash
# Logstash config for parsing Apache logs
input {
  file {
    path => "/var/log/apache2/access.log"
    start_position => "beginning"
  }
}

filter {
  grok {
    match => {
      "message" => "%{COMBINEDAPACHELOG}"
    }
  }

  mutate {
    convert => { "response" => "integer" }
    convert => { "bytes" => "integer" }
  }

  if [response] >= 400 {
    mutate {
      add_tag => ["error"]
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "apache-logs-%{+YYYY.MM.dd}"
  }
}
```

### Graylog - Centralized Log Management

```bash
# API queries for log analysis
curl -u username:password -X GET "http://graylog-server:9000/api/search/universal/relative?query=source:firewall&range=3600"

# Stream configuration via API
curl -u username:password -X POST "http://graylog-server:9000/api/streams" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Security Events",
    "description": "High priority security events",
    "rules": [{
      "field": "level",
      "type": 1,
      "value": "ERROR",
      "inverted": false
    }]
  }'

# Alert configuration
curl -u username:password -X POST "http://graylog-server:9000/api/alerts/conditions" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "message_count",
    "title": "High Error Rate",
    "parameters": {
      "threshold": 100,
      "threshold_type": "more",
      "time": 5
    }
  }'
```

## Network Security Monitoring

### Zeek (formerly Bro) - Network Security Monitor

#### Basic Zeek Operation
```bash
# Install and configure Zeek
sudo zeek -i eth0 local

# Analyze pcap files
zeek -r suspicious_traffic.pcap

# Custom script execution
zeek -i eth0 /opt/zeek/share/zeek/policy/protocols/http/detect-sqli.zeek

# Log analysis
tail -f /opt/zeek/logs/current/http.log | grep -E "(union|select|insert|drop)"
```

#### Zeek Scripting for Detection
```bash
# Custom Zeek script for detecting lateral movement
cat > lateral_movement.zeek << 'EOF'
@load base/protocols/conn
@load base/utils/site

event connection_established(c: connection) {
    if (c$id$orig_h in Site::local_nets && c$id$resp_h in Site::local_nets) {
        if (c$id$resp_p == 445/tcp || c$id$resp_p == 3389/tcp) {
            print fmt("Potential lateral movement: %s -> %s:%s",
                c$id$orig_h, c$id$resp_h, c$id$resp_p);
        }
    }
}
EOF

zeek -i eth0 lateral_movement.zeek
```

### Suricata - Network IDS/IPS

#### Suricata Configuration and Rules
```bash
# Update rule sets
suricata-update

# Test configuration
suricata -T -c /etc/suricata/suricata.yaml

# Run in IDS mode
suricata -c /etc/suricata/suricata.yaml -i eth0

# Analyze pcap files
suricata -c /etc/suricata/suricata.yaml -r suspicious.pcap

# Custom rule creation
cat >> /etc/suricata/rules/custom.rules << 'EOF'
alert tcp any any -> any 80 (msg:"Potential SQL Injection"; content:"union"; content:"select"; sid:1000001; rev:1;)
alert tcp any any -> any any (msg:"Suspicious PowerShell Activity"; content:"powershell"; content:"-encodedcommand"; sid:1000002; rev:1;)
EOF

# Real-time log monitoring
tail -f /var/log/suricata/fast.log
tail -f /var/log/suricata/eve.json | jq '.'
```

### Security Onion - Network Security Monitoring Platform

```bash
# Setup and deployment
sudo so-setup

# ElastAlert rule creation
cat > /etc/elastalert/rules/brute_force.yaml << 'EOF'
name: SSH Brute Force Detection
type: frequency
index: logstash-*
num_events: 10
timeframe:
  minutes: 5
filter:
- term:
    program: "sshd"
- match:
    message: "Failed password"
alert:
- "email"
email:
- "admin@company.com"
EOF

# Kibana dashboard queries
# Failed authentication events
event_type:auth AND outcome:failure

# Network connections to external IPs
event_type:connection AND NOT destination.ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16)

# DNS queries to suspicious domains
event_type:dns AND query:(*.tk OR *.ml OR *.ga)
```

## Endpoint Detection and Response (EDR)

### Osquery - Operating System Instrumentation Framework

#### Basic Osquery Operations
```bash
# Interactive shell
osqueryi

# One-off queries
osqueryi "SELECT * FROM processes WHERE name LIKE '%powershell%';"

# Configuration-driven monitoring
osqueryd --config_path=/etc/osquery/osquery.conf --logger_path=/var/log/osquery/

# Remote querying via API
curl -X POST http://osquery-server:8080/query \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT * FROM logged_in_users;"}'
```

#### Threat Hunting with Osquery
```bash
# Detect persistence mechanisms
osqueryi "SELECT * FROM startup_items;"
osqueryi "SELECT * FROM scheduled_tasks WHERE enabled=1;"
osqueryi "SELECT * FROM registry WHERE key LIKE 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%';"

# Network connections analysis
osqueryi "SELECT DISTINCT process.name, listening_ports.port, listening_ports.address FROM processes JOIN listening_ports USING (pid);"

# File integrity monitoring
osqueryi "SELECT * FROM file_events WHERE action='CREATED' AND path LIKE '%/tmp/%';"

# Process monitoring
osqueryi "SELECT pid, name, path, cmdline, parent FROM processes WHERE cmdline LIKE '%powershell%' AND cmdline LIKE '%base64%';"

# User activity monitoring
osqueryi "SELECT * FROM logged_in_users WHERE type='user';"
osqueryi "SELECT * FROM shell_history WHERE command LIKE 'sudo%' OR command LIKE 'su %';"
```

### YARA - Malware Identification and Classification

#### Basic YARA Usage
```bash
# Scan files with existing rules
yara /path/to/rules.yar /path/to/scan/

# Scan recursively
yara -r /path/to/rules.yar /path/to/directory/

# Output matches only
yara -q /path/to/rules.yar /path/to/scan/

# Scan running processes
yara /path/to/rules.yar $(pgrep -f suspicious_process)
```

#### Custom YARA Rules
```bash
# Malware detection rules
cat > malware_detection.yar << 'EOF'
rule Suspicious_PowerShell
{
    meta:
        description = "Detects suspicious PowerShell commands"
        author = "Security Team"
        date = "2024-01-15"

    strings:
        $cmd1 = "IEX" nocase
        $cmd2 = "Invoke-Expression" nocase
        $cmd3 = "DownloadString" nocase
        $cmd4 = "encodedcommand" nocase
        $cmd5 = "bypass" nocase

    condition:
        2 of ($cmd*)
}

rule Lateral_Movement_Tools
{
    strings:
        $tool1 = "psexec" nocase
        $tool2 = "wmiexec" nocase
        $tool3 = "smbexec" nocase
        $tool4 = "mimikatz" nocase

    condition:
        any of them
}
EOF

# Advanced behavioral detection
cat > behavioral_detection.yar << 'EOF'
rule Credential_Dumping
{
    strings:
        $lsass1 = "lsass.exe" nocase
        $lsass2 = "lsass.dmp" nocase
        $sam1 = "SAM" nocase
        $sam2 = "SYSTEM" nocase
        $cred1 = "sekurlsa" nocase
        $cred2 = "logonpasswords" nocase

    condition:
        ($lsass1 or $lsass2) and ($sam1 or $sam2) and ($cred1 or $cred2)
}
EOF
```

### Sysmon - Windows System Activity Monitor

#### Sysmon Configuration and Monitoring
```bash
# Install with comprehensive config
sysmon -accepteula -i sysmonconfig.xml

# View events in PowerShell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-Table -Wrap

# Filter for specific event types
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=1} | Select-Object TimeCreated, Message | Format-List

# Export events for analysis
wevtutil epl Microsoft-Windows-Sysmon/Operational C:\sysmon-export.evtx
```

#### Sysmon Configuration for Advanced Detection
```xml
<!-- Enhanced Sysmon config -->
<Sysmon schemaversion="4.40">
  <EventFiltering>
    <!-- Process creation -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <CommandLine condition="contains">windows\system32</CommandLine>
      </ProcessCreate>
    </RuleGroup>

    <!-- Network connections -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <DestinationPort condition="is">443</DestinationPort>
        <DestinationPort condition="is">80</DestinationPort>
      </NetworkConnect>
    </RuleGroup>

    <!-- File creation -->
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">temp</TargetFilename>
        <TargetFilename condition="contains">startup</TargetFilename>
      </FileCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

## Threat Intelligence Integration

### MISP - Malware Information Sharing Platform

#### MISP API Operations
```bash
# API key authentication
export MISP_URL="https://misp.example.com"
export MISP_KEY="your-api-key"

# Search for indicators
curl -H "Authorization: $MISP_KEY" \
     -H "Accept: application/json" \
     "$MISP_URL/attributes/restSearch" \
     -d '{"value": "malicious-domain.com"}'

# Add new indicators
curl -X POST \
     -H "Authorization: $MISP_KEY" \
     -H "Content-Type: application/json" \
     "$MISP_URL/attributes/add/123" \
     -d '{
       "type": "ip-dst",
       "category": "Network activity",
       "value": "1.2.3.4",
       "comment": "Malicious C2 server"
     }'

# Export IoCs in various formats
curl -H "Authorization: $MISP_KEY" \
     "$MISP_URL/events/restSearch/download/1234.json" \
     -o event_1234.json

# STIX export
curl -H "Authorization: $MISP_KEY" \
     "$MISP_URL/events/restSearch/returnFormat:stix/eventid:1234"
```

### OpenCTI - Cyber Threat Intelligence Platform

```bash
# GraphQL API queries
curl -X POST \
  -H "Authorization: Bearer $OPENCTI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { indicators(first: 10) { edges { node { id pattern indicator_types } } } }"
  }' \
  https://opencti.example.com/graphql

# Search for specific indicators
curl -X POST \
  -H "Authorization: Bearer $OPENCTI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query($search: String) { indicators(search: $search) { edges { node { pattern created confidence } } } }",
    "variables": { "search": "malicious-ip.com" }
  }' \
  https://opencti.example.com/graphql
```

### ThreatConnect API Integration

```bash
# Retrieve indicators
curl -H "Authorization: TC $API_ID:$API_SECRET" \
     "https://api.threatconnect.com/api/v2/indicators/addresses"

# Submit new indicators
curl -X POST \
     -H "Authorization: TC $API_ID:$API_SECRET" \
     -H "Content-Type: application/json" \
     "https://api.threatconnect.com/api/v2/indicators/addresses" \
     -d '{
       "ip": "192.168.1.100",
       "rating": 5,
       "confidence": 85
     }'

# Search for related threats
curl -H "Authorization: TC $API_ID:$API_SECRET" \
     "https://api.threatconnect.com/api/v2/indicators/addresses/192.168.1.100/groups"
```

## Automated Response and Orchestration

### TheHive - Security Incident Response Platform

#### Case Management via API
```bash
# Create new case
curl -X POST \
  -H "Authorization: Bearer $THEHIVE_API_KEY" \
  -H "Content-Type: application/json" \
  "http://thehive.example.com:9000/api/case" \
  -d '{
    "title": "Suspicious Network Activity",
    "description": "Potential data exfiltration detected",
    "severity": 3,
    "startDate": 1640995200000,
    "owner": "analyst@company.com",
    "flag": false,
    "tlp": 2,
    "tags": ["network", "exfiltration", "urgent"]
  }'

# Add observables to case
curl -X POST \
  -H "Authorization: Bearer $THEHIVE_API_KEY" \
  -H "Content-Type: application/json" \
  "http://thehive.example.com:9000/api/case/$CASE_ID/artifact" \
  -d '{
    "dataType": "ip",
    "data": "192.168.1.100",
    "message": "Suspicious source IP",
    "tlp": 2,
    "tags": ["c2", "malicious"]
  }'

# Search cases
curl -X POST \
  -H "Authorization: Bearer $THEHIVE_API_KEY" \
  -H "Content-Type: application/json" \
  "http://thehive.example.com:9000/api/case/_search" \
  -d '{
    "query": {
      "_and": [
        {"status": "Open"},
        {"severity": {"_gte": 2}}
      ]
    }
  }'
```

### Cortex - Observable Analysis Engine

```bash
# Analyze observables
curl -X POST \
  -H "Authorization: Bearer $CORTEX_API_KEY" \
  -H "Content-Type: application/json" \
  "http://cortex.example.com:9001/api/analyzer/VirusTotal_GetReport_3_0/run" \
  -d '{
    "data": "malicious-hash-here",
    "dataType": "hash",
    "tlp": 2
  }'

# Get analysis results
curl -H "Authorization: Bearer $CORTEX_API_KEY" \
     "http://cortex.example.com:9001/api/job/$JOB_ID"

# List available analyzers
curl -H "Authorization: Bearer $CORTEX_API_KEY" \
     "http://cortex.example.com:9001/api/analyzer"
```

### Phantom/SOAR Automation

```bash
# REST API playbook execution
curl -X POST \
  -H "Authorization: ph-auth-token $PHANTOM_TOKEN" \
  -H "Content-Type: application/json" \
  "https://phantom.example.com/rest/playbook_run" \
  -d '{
    "playbook_id": 123,
    "container_id": 456,
    "scope": "all"
  }'

# Custom action execution
curl -X POST \
  -H "Authorization: ph-auth-token $PHANTOM_TOKEN" \
  -H "Content-Type: application/json" \
  "https://phantom.example.com/rest/action_run" \
  -d '{
    "action": "block ip",
    "parameters": {
      "ip": "192.168.1.100",
      "comment": "Automated block from detection system"
    },
    "assets": ["firewall_asset_id"]
  }'
```

## Custom Detection Scripts

### Network Anomaly Detection
```bash
#!/bin/bash
# Network traffic baseline comparison
INTERFACE="eth0"
BASELINE="/tmp/network_baseline.txt"
CURRENT="/tmp/network_current.txt"

# Capture current network statistics
ss -tuln > $CURRENT
netstat -i >> $CURRENT

# Compare with baseline
if [ -f "$BASELINE" ]; then
    diff $BASELINE $CURRENT > /tmp/network_diff.txt
    if [ -s "/tmp/network_diff.txt" ]; then
        echo "Network anomaly detected at $(date)"
        cat /tmp/network_diff.txt
        # Send alert
        mail -s "Network Anomaly Alert" admin@company.com < /tmp/network_diff.txt
    fi
fi

# Update baseline
cp $CURRENT $BASELINE
```

### Process Monitoring Script
```bash
#!/bin/bash
# Detect suspicious process activities
SUSPICIOUS_PROCESSES=("nc" "netcat" "nmap" "masscan" "john" "hashcat" "hydra")
ALERT_LOG="/var/log/security/process_alerts.log"

for process in "${SUSPICIOUS_PROCESSES[@]}"; do
    if pgrep -f "$process" > /dev/null; then
        echo "$(date): Suspicious process detected: $process" | tee -a $ALERT_LOG
        ps aux | grep "$process" | grep -v grep >> $ALERT_LOG

        # Get network connections for the process
        netstat -tuln | grep $(pgrep -f "$process") >> $ALERT_LOG

        # Optional: Kill the process
        # pkill -f "$process"
    fi
done
```

### Log Analysis Automation
```bash
#!/bin/bash
# Automated log analysis for common attack patterns
LOG_FILE="/var/log/apache2/access.log"
ALERT_THRESHOLD=10
TEMP_DIR="/tmp/security_analysis"

mkdir -p $TEMP_DIR

# Detect SQL injection attempts
grep -i "union\|select\|insert\|drop\|exec" $LOG_FILE > $TEMP_DIR/sqli_attempts.txt
if [ $(wc -l < $TEMP_DIR/sqli_attempts.txt) -gt 0 ]; then
    echo "SQL injection attempts detected:"
    cat $TEMP_DIR/sqli_attempts.txt
fi

# Detect brute force attacks
awk '($9 == 401 || $9 == 403) {print $1}' $LOG_FILE | sort | uniq -c | sort -nr > $TEMP_DIR/failed_logins.txt
while read count ip; do
    if [ $count -gt $ALERT_THRESHOLD ]; then
        echo "Brute force detected from IP: $ip ($count attempts)"
        # Optional: Block IP
        # iptables -A INPUT -s $ip -j DROP
    fi
done < $TEMP_DIR/failed_logins.txt

# Detect directory traversal
grep -E "\.\./|\.\.\\|%2e%2e" $LOG_FILE > $TEMP_DIR/directory_traversal.txt
if [ $(wc -l < $TEMP_DIR/directory_traversal.txt) -gt 0 ]; then
    echo "Directory traversal attempts detected:"
    cat $TEMP_DIR/directory_traversal.txt
fi
```

## Integration and Automation

### ELK Stack Integration Script
```bash
#!/bin/bash
# Send custom security events to Elasticsearch
ES_HOST="localhost:9200"
INDEX_NAME="security-events-$(date +%Y.%m.%d)"

send_security_event() {
    local event_type=$1
    local severity=$2
    local description=$3
    local source_ip=$4

    curl -X POST "$ES_HOST/$INDEX_NAME/_doc" \
        -H "Content-Type: application/json" \
        -d "{
            \"@timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)\",
            \"event_type\": \"$event_type\",
            \"severity\": \"$severity\",
            \"description\": \"$description\",
            \"source_ip\": \"$source_ip\",
            \"hostname\": \"$(hostname)\"
        }"
}

# Example usage
send_security_event "suspicious_process" "high" "Netcat executed on system" "192.168.1.100"
```

### SIEM Alert Correlation
```bash
#!/bin/bash
# Multi-source alert correlation
CORRELATION_WINDOW=300  # 5 minutes
TEMP_DIR="/tmp/correlation"

mkdir -p $TEMP_DIR

# Collect alerts from various sources
tail -n 1000 /var/log/suricata/fast.log | grep "$(date +%Y-%m-%d)" > $TEMP_DIR/ids_alerts.txt
journalctl --since "5 minutes ago" | grep -i "failed\|error\|denied" > $TEMP_DIR/system_alerts.txt
grep "$(date +%b\ %d\ %H:%M)" /var/log/auth.log > $TEMP_DIR/auth_alerts.txt

# Correlate events by IP address
cat $TEMP_DIR/*.txt | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -nr | while read count ip; do
    if [ $count -gt 3 ]; then
        echo "Correlated security events for IP $ip: $count incidents"
        echo "Details:"
        grep "$ip" $TEMP_DIR/*.txt | head -10
        echo "---"
    fi
done
```

This comprehensive defensive detection toolkit provides security teams with the tools and techniques necessary for effective threat monitoring, incident response, and security operations management.