# Offensive Reconnaissance Tools

Comprehensive guide to reconnaissance tools and techniques for security assessments and red team operations.

## Network Discovery

### Nmap - Network Mapper

The essential network discovery and security auditing tool.

#### Basic Host Discovery
```bash
# Ping sweep for live hosts
nmap -sn 192.168.1.0/24

# TCP SYN ping (bypasses ICMP blocks)
nmap -PS 192.168.1.0/24

# UDP ping for hosts behind firewalls
nmap -PU 192.168.1.0/24

# ARP ping for local network
nmap -PR 192.168.1.0/24
```

#### Port Scanning Techniques
```bash
# TCP SYN scan (stealthy, default)
nmap -sS target.com

# TCP connect scan (noisier but reliable)
nmap -sT target.com

# UDP scan (slow but thorough)
nmap -sU target.com

# Comprehensive scan with service detection
nmap -sS -sV -O -A target.com

# Fast scan of common ports
nmap -F target.com

# Scan specific ports
nmap -p 80,443,8080,8443 target.com
```

#### Service Enumeration
```bash
# Version detection
nmap -sV target.com

# OS fingerprinting
nmap -O target.com

# Script scanning for vulnerabilities
nmap --script vuln target.com

# HTTP enumeration scripts
nmap --script http-enum,http-headers,http-methods target.com

# SMB enumeration
nmap --script smb-enum-shares,smb-enum-users target.com
```

#### Advanced Nmap Techniques
```bash
# Timing templates (0=paranoid, 5=insane)
nmap -T4 target.com

# Decoy scanning to hide source
nmap -D RND:10 target.com

# Source port spoofing
nmap --source-port 53 target.com

# Fragment packets to evade firewalls
nmap -f target.com

# Custom NSE script execution
nmap --script /path/to/custom-script.nse target.com
```

### Masscan - High-Speed Port Scanner

Ultra-fast port scanner for large-scale reconnaissance.

```bash
# Scan entire internet for port 80 (be careful!)
masscan 0.0.0.0/0 -p 80 --rate=1000

# Scan specific subnet with high rate
masscan 10.0.0.0/8 -p 80,443,8080,8443 --rate=10000

# Output to XML for parsing
masscan 192.168.1.0/24 -p 1-65535 --rate=1000 -oX results.xml

# Exclude certain hosts
masscan 10.0.0.0/8 -p 80 --excludefile exclude.txt --rate=5000
```

### Zmap - Internet-Scale Network Scanner

```bash
# Scan for port 443 across IPv4 space
zmap -p 443 -o results.txt

# Scan with specific source port
zmap -p 80 -s 53 -o web-servers.txt

# Rate limiting
zmap -p 22 -r 10000 -o ssh-servers.txt

# Target specific networks
echo "192.168.1.0/24" | zmap -p 80
```

## Web Application Reconnaissance

### Gobuster - Directory and File Brute-Forcing

```bash
# Directory brute-forcing
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt

# Include file extensions
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -x php,html,txt

# DNS subdomain enumeration
gobuster dns -d target.com -w /usr/share/wordlists/dnsrecon/subdomains-top1mil-5000.txt

# VHOST enumeration
gobuster vhost -u http://target.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Custom headers and cookies
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -H "Authorization: Bearer token"
```

### Feroxbuster - Fast Content Discovery

```bash
# Recursive directory scanning
feroxbuster -u http://target.com -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Limit recursion depth
feroxbuster -u http://target.com -w wordlist.txt -d 3

# Filter by response size
feroxbuster -u http://target.com -w wordlist.txt -S 1000,2000

# Multiple extensions
feroxbuster -u http://target.com -w wordlist.txt -x php,html,txt,bak
```

### Ffuf - Fast Web Fuzzer

```bash
# Directory fuzzing
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://target.com/FUZZ

# Parameter fuzzing
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://target.com/page?FUZZ=value

# POST data fuzzing
ffuf -w wordlist.txt -X POST -d "username=admin&password=FUZZ" -u http://target.com/login

# Header fuzzing
ffuf -w wordlist.txt -H "X-Forwarded-For: FUZZ" -u http://target.com/admin

# Filter by response size/words/lines
ffuf -w wordlist.txt -u http://target.com/FUZZ -fs 1234 -fw 100 -fl 50
```

## DNS Reconnaissance

### DNSRecon - DNS Enumeration

```bash
# Standard DNS enumeration
dnsrecon -d target.com

# Brute force subdomains
dnsrecon -d target.com -D /usr/share/wordlists/dnsrecon/subdomains-top1mil-5000.txt -t brt

# Zone transfer attempt
dnsrecon -d target.com -t axfr

# Reverse DNS lookup
dnsrecon -r 192.168.1.0/24

# Google dorking for subdomains
dnsrecon -d target.com -t goo
```

### Subfinder - Subdomain Discovery

```bash
# Basic subdomain enumeration
subfinder -d target.com

# Use all sources
subfinder -d target.com -all

# Output to file
subfinder -d target.com -o subdomains.txt

# Silent mode (only show results)
subfinder -d target.com -silent

# Recursive subdomain discovery
subfinder -d target.com -recursive
```

### Assetfinder - Domain Asset Discovery

```bash
# Find subdomains
assetfinder target.com

# Find subdomains and related domains
assetfinder --subs-only target.com

# Output unique results
assetfinder target.com | sort -u
```

## OSINT (Open Source Intelligence)

### TheHarvester - Email and Domain Information Gathering

```bash
# Search multiple sources
theHarvester -d target.com -b google,bing,yahoo

# Limit results
theHarvester -d target.com -b google -l 100

# DNS brute forcing
theHarvester -d target.com -b dns

# Search specific source
theHarvester -d target.com -b shodan

# Save results to file
theHarvester -d target.com -b all -f results.html
```

### Sherlock - Social Media Username Investigation

```bash
# Search for username across platforms
python3 sherlock.py username

# Search specific sites
python3 sherlock.py username --site Instagram --site Twitter

# Output to file
python3 sherlock.py username --output /path/to/results

# Verbose output
python3 sherlock.py username --verbose
```

### Shodan CLI - Internet-Connected Device Search

```bash
# Initialize with API key
shodan init YOUR_API_KEY

# Search for specific service
shodan search apache

# Search by IP range
shodan search net:192.168.1.0/24

# Search for specific product and version
shodan search "Apache/2.4.41"

# Country-specific search
shodan search apache country:US

# Download search results
shodan download --limit 1000 apache_servers apache

# Parse downloaded data
shodan parse --fields ip_str,port,org --separator , apache_servers.json.gz
```

## Vulnerability Scanning

### Nuclei - Vulnerability Scanner with Templates

```bash
# Run with default templates
nuclei -u http://target.com

# Run specific template category
nuclei -u http://target.com -t cves/

# Run against multiple targets
nuclei -l targets.txt

# Update templates
nuclei -update-templates

# Custom template execution
nuclei -u http://target.com -t /path/to/custom-template.yaml

# Rate limiting
nuclei -u http://target.com -rl 150

# Output formatting
nuclei -u http://target.com -json -o results.json
```

### Nikto - Web Server Scanner

```bash
# Basic web server scan
nikto -h http://target.com

# Scan with specific port
nikto -h http://target.com -p 8080

# Use proxy
nikto -h http://target.com -useproxy http://proxy:8080

# Custom user agent
nikto -h http://target.com -useragent "Custom User Agent"

# Save results
nikto -h http://target.com -output results.xml -Format xml
```

## Advanced Reconnaissance Automation

### Reconnaissance Pipelines

```bash
# Subdomain enumeration pipeline
echo "target.com" | subfinder -silent | httprobe -silent | nuclei -t cves/ -silent

# Port scan to service enumeration
nmap -sS -T4 -p- target.com | grep open | awk '{print $1}' FS='/' | while read port; do nmap -sV -p $port target.com; done

# Web application discovery chain
gobuster dns -d target.com -w subdomains.txt -q | httprobe | gobuster dir -u - -w directories.txt

# OSINT to attack surface mapping
theHarvester -d target.com -b all | grep '@' | cut -d'@' -f2 | sort -u | while read domain; do subfinder -d $domain; done
```

### Custom Recon Scripts

```bash
# Mass subdomain takeover check
#!/bin/bash
for subdomain in $(cat subdomains.txt); do
  response=$(curl -s -I -L "$subdomain" | grep -i "Location\|CNAME")
  if [[ $response =~ (github|heroku|amazonaws) ]]; then
    echo "Potential takeover: $subdomain - $response"
  fi
done

# Technology stack fingerprinting
#!/bin/bash
curl -s -I "$1" | grep -E "(Server|X-Powered-By|X-Framework)" | while read line; do
  echo "$1: $line"
done
```

## Anti-Detection Techniques

### Traffic Manipulation

```bash
# Random user agents with curl
USER_AGENTS=("Mozilla/5.0..." "Chrome/..." "Safari/...")
curl -H "User-Agent: ${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}" http://target.com

# Proxy rotation
proxychains nmap -sS target.com

# Timing delays in scanning
nmap --scan-delay 1s target.com

# Source IP spoofing (requires raw socket privileges)
hping3 -S -p 80 -s 53 target.com
```

### Session Management

```bash
# Cookie-based reconnaissance
curl -c cookies.txt -b cookies.txt http://target.com/login
curl -b cookies.txt http://target.com/admin

# JWT token extraction and usage
token=$(curl -s -X POST -d "user=admin&pass=password" http://target.com/login | jq -r '.token')
curl -H "Authorization: Bearer $token" http://target.com/api/users
```

## Best Practices

### Reconnaissance Methodology

1. **Passive Information Gathering**
   - OSINT collection
   - DNS enumeration
   - Social media investigation

2. **Active Scanning**
   - Network discovery
   - Port scanning
   - Service enumeration

3. **Web Application Testing**
   - Directory brute-forcing
   - Parameter fuzzing
   - Technology fingerprinting

4. **Vulnerability Assessment**
   - Template-based scanning
   - Custom exploit verification
   - Attack surface analysis

### Operational Security

```bash
# Log management
export HISTFILE=/dev/null
export HISTSIZE=0

# Proxy all traffic
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080

# VPN verification
curl ipinfo.io/ip

# Clean artifacts
history -c
rm -rf ~/.local/share/recently-used.xbel
```

### Legal and Ethical Guidelines

- Always obtain proper authorization before testing
- Respect rate limits and server resources
- Document all activities for reporting
- Follow responsible disclosure practices
- Comply with local laws and regulations

This reconnaissance toolkit provides the foundation for effective security assessments while maintaining operational security and ethical standards.