# Security Lab Setup

Comprehensive guide for building cybersecurity testing and research environments using various virtualization and containerization platforms.

## Virtual Machine Environments

### VMware vSphere/ESXi Setup

#### ESXi Installation and Configuration
```bash
# Download ESXi ISO and create bootable USB
dd if=VMware-VMvisor-Installer-8.0.iso of=/dev/sdX bs=4M status=progress

# Post-installation ESXi CLI configuration
esxcli system hostname set --host=lab-esxi-01
esxcli system hostname set --domain=homelab.local

# Network configuration
esxcli network vswitch standard add -v vSwitch1
esxcli network vswitch standard portgroup add -p "Lab Network" -v vSwitch1
esxcli network vswitch standard portgroup set -p "Lab Network" --vlan-id 100

# Enable SSH for management
esxcli system ssh start
esxcli system ssh set --enabled true

# Storage configuration
esxcli storage filesystem list
esxcli storage nfs add -H 192.168.1.10 -s /mnt/nfs-share -v nfs-datastore
```

#### vCenter Server Deployment
```bash
# Deploy vCenter Server Appliance via CLI
./vcsa-deploy install --accept-eula --acknowledge-ceip \
  --deployment-option small \
  --appliance-name vcenter-lab \
  --network "Lab Network" \
  --ip 192.168.100.10 \
  --prefix 24 \
  --gateway 192.168.100.1 \
  --dns 192.168.1.1 \
  /path/to/vcsa-config.json

# PowerCLI automation
Connect-VIServer -Server vcenter-lab.homelab.local
New-Datacenter -Name "Security Lab"
New-Cluster -Name "Test Cluster" -Location "Security Lab"
Add-VMHost -Name 192.168.100.11 -Location "Test Cluster" -User root -Password password123
```

### VirtualBox Automation

#### VirtualBox VM Management
```bash
# Create new VM
VBoxManage createvm --name "Kali-Lab" --ostype "Debian_64" --register

# Configure VM resources
VBoxManage modifyvm "Kali-Lab" --memory 4096 --cpus 2
VBoxManage modifyvm "Kali-Lab" --vram 128
VBoxManage modifyvm "Kali-Lab" --nic1 nat --nic2 intnet --intnet2 "LabNetwork"

# Create and attach storage
VBoxManage createhd --filename "/VirtualBox VMs/Kali-Lab/Kali-Lab.vdi" --size 50000
VBoxManage storagectl "Kali-Lab" --name "SATA Controller" --add sata
VBoxManage storageattach "Kali-Lab" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "/VirtualBox VMs/Kali-Lab/Kali-Lab.vdi"

# Attach ISO and start VM
VBoxManage storageattach "Kali-Lab" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium kali-linux-2024.1-installer-amd64.iso
VBoxManage startvm "Kali-Lab"

# Snapshot management
VBoxManage snapshot "Kali-Lab" take "Clean Install" --description "Fresh Kali installation"
VBoxManage snapshot "Kali-Lab" restore "Clean Install"
```

#### Vagrant Environment Setup
```bash
# Initialize Vagrant environment
mkdir security-lab && cd security-lab
vagrant init

# Vagrantfile configuration
cat > Vagrantfile << 'EOF'
Vagrant.configure("2") do |config|
  # Kali Linux VM
  config.vm.define "kali" do |kali|
    kali.vm.box = "kalilinux/rolling"
    kali.vm.network "private_network", ip: "192.168.50.10"
    kali.vm.provider "virtualbox" do |vb|
      vb.memory = "4096"
      vb.cpus = 2
    end
  end

  # Ubuntu vulnerable VM
  config.vm.define "target" do |target|
    target.vm.box = "ubuntu/focal64"
    target.vm.network "private_network", ip: "192.168.50.20"
    target.vm.provision "shell", inline: <<-SHELL
      apt-get update
      apt-get install -y apache2 mysql-server php
      # Intentionally vulnerable configurations
      echo "<?php system(\$_GET['cmd']); ?>" > /var/www/html/shell.php
    SHELL
  end

  # Windows 10 VM
  config.vm.define "windows" do |win|
    win.vm.box = "gusztavvargadr/windows-10"
    win.vm.network "private_network", ip: "192.168.50.30"
    win.vm.provider "virtualbox" do |vb|
      vb.memory = "8192"
      vb.cpus = 4
    end
  end
end
EOF

# Deploy environment
vagrant up
vagrant ssh kali
```

### KVM/QEMU Setup

#### KVM Installation and Configuration
```bash
# Install KVM and management tools
sudo apt update
sudo apt install -y qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virt-manager

# Verify KVM installation
sudo kvm-ok
sudo virsh list --all

# Create bridge network for lab
sudo cat > /etc/netplan/01-bridge.yaml << 'EOF'
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: no
  bridges:
    br0:
      interfaces: [enp0s3]
      dhcp4: yes
      parameters:
        stp: false
EOF

sudo netplan apply
```

#### QEMU VM Management
```bash
# Create VM with qemu-img
qemu-img create -f qcow2 kali-lab.qcow2 50G

# Start VM with custom configuration
qemu-system-x86_64 \
  -enable-kvm \
  -m 4096 \
  -cpu host \
  -smp cores=2 \
  -drive file=kali-lab.qcow2,format=qcow2 \
  -cdrom kali-linux.iso \
  -netdev bridge,id=net0,br=br0 \
  -device virtio-net-pci,netdev=net0 \
  -vnc :1

# Virsh domain management
sudo virsh define vm-config.xml
sudo virsh start kali-lab
sudo virsh snapshot-create-as kali-lab "clean-install" "Fresh installation"
sudo virsh snapshot-revert kali-lab "clean-install"
```

## Container Environments

### Docker Security Lab

#### Docker Installation and Setup
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Docker Compose installation
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Enable Docker service
sudo systemctl enable docker
sudo systemctl start docker
```

#### Vulnerable Application Containers
```bash
# DVWA (Damn Vulnerable Web Application)
docker run -d -p 8080:80 vulnerables/web-dvwa

# WebGoat (OWASP Learning Platform)
docker run -d -p 8081:8080 webgoat/goatandwolf

# Metasploitable
docker run -d -p 8022:22 -p 8023:23 -p 8080:80 tleemcjr/metasploitable2

# VulnHub-style containers
docker run -d --name vulnhub-basic -p 8888:80 citizenstig/vulnhub-basic

# Custom vulnerable stack with Docker Compose
cat > docker-compose.yml << 'EOF'
version: '3.8'
services:
  dvwa:
    image: vulnerables/web-dvwa
    ports:
      - "8080:80"
    networks:
      - lab-network

  webgoat:
    image: webgoat/goatandwolf
    ports:
      - "8081:8080"
    networks:
      - lab-network

  mysql:
    image: mysql:5.7
    environment:
      MYSQL_ROOT_PASSWORD: vulnerable
      MYSQL_DATABASE: dvwa
    networks:
      - lab-network

  kali:
    image: kalilinux/kali-rolling
    stdin_open: true
    tty: true
    networks:
      - lab-network
    volumes:
      - ./tools:/opt/tools

networks:
  lab-network:
    driver: bridge
EOF

docker-compose up -d
```

#### Kubernetes Security Lab
```bash
# Install minikube
curl -Lo minikube https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube /usr/local/bin/

# Start minikube cluster
minikube start --driver=docker --memory=8192 --cpus=4

# Deploy vulnerable applications
kubectl apply -f - << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vulnerable-app
  template:
    metadata:
      labels:
        app: vulnerable-app
    spec:
      containers:
      - name: app
        image: vulnerables/web-dvwa
        ports:
        - containerPort: 80
        securityContext:
          runAsUser: 0
          privileged: true
---
apiVersion: v1
kind: Service
metadata:
  name: vulnerable-service
spec:
  selector:
    app: vulnerable-app
  ports:
  - port: 80
    targetPort: 80
  type: NodePort
EOF

# Expose service
minikube service vulnerable-service
```

### Podman Rootless Containers

```bash
# Install Podman
sudo apt install -y podman

# Rootless configuration
echo "user.max_user_namespaces=28633" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Run security tools in containers
podman run -it --rm kalilinux/kali-rolling /bin/bash

# Persistent tool container
podman run -d --name security-tools \
  -v /home/user/tools:/opt/tools:Z \
  -p 8080:80 \
  kalilinux/kali-rolling tail -f /dev/null

podman exec -it security-tools /bin/bash
```

## Cloud-Based Labs

### AWS Security Lab Setup

#### Infrastructure as Code with Terraform
```bash
# Install Terraform
wget https://releases.hashicorp.com/terraform/1.5.0/terraform_1.5.0_linux_amd64.zip
unzip terraform_1.5.0_linux_amd64.zip
sudo mv terraform /usr/local/bin/

# AWS CLI configuration
aws configure set region us-west-2
aws configure set output json

# Terraform configuration
cat > main.tf << 'EOF'
provider "aws" {
  region = "us-west-2"
}

# VPC for security lab
resource "aws_vpc" "security_lab" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "SecurityLab-VPC"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "lab_igw" {
  vpc_id = aws_vpc.security_lab.id

  tags = {
    Name = "SecurityLab-IGW"
  }
}

# Public subnet
resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.security_lab.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-west-2a"
  map_public_ip_on_launch = true

  tags = {
    Name = "SecurityLab-PublicSubnet"
  }
}

# Kali Linux instance
resource "aws_instance" "kali" {
  ami           = "ami-0c94f3e6b6d1a5c33"  # Kali Linux AMI
  instance_type = "t3.medium"
  subnet_id     = aws_subnet.public_subnet.id
  key_name      = aws_key_pair.lab_keypair.key_name

  vpc_security_group_ids = [aws_security_group.kali_sg.id]

  user_data = <<-EOF
    #!/bin/bash
    apt-get update
    apt-get install -y nmap metasploit-framework
  EOF

  tags = {
    Name = "SecurityLab-Kali"
  }
}

# Vulnerable target instance
resource "aws_instance" "target" {
  ami           = "ami-0c2b8ca1dad447f8a"  # Ubuntu 20.04 LTS
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.public_subnet.id
  key_name      = aws_key_pair.lab_keypair.key_name

  vpc_security_group_ids = [aws_security_group.target_sg.id]

  user_data = <<-EOF
    #!/bin/bash
    apt-get update
    apt-get install -y apache2 mysql-server
    echo "<?php system(\$_GET['cmd']); ?>" > /var/www/html/shell.php
  EOF

  tags = {
    Name = "SecurityLab-Target"
  }
}

# Security groups
resource "aws_security_group" "kali_sg" {
  name_prefix = "kali-sg"
  vpc_id      = aws_vpc.security_lab.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
EOF

# Deploy infrastructure
terraform init
terraform plan
terraform apply -auto-approve

# Connect to instances
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,PublicIpAddress,Tags[?Key==`Name`].Value|[0]]'
ssh -i lab-key.pem kali@$(terraform output kali_public_ip)
```

#### AWS CloudFormation Alternative
```yaml
# cloudformation-security-lab.yml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Security Lab Environment'

Parameters:
  KeyPairName:
    Type: AWS::EC2::KeyPair::KeyName
    Description: EC2 Key Pair for SSH access

Resources:
  SecurityLabVPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
      EnableDnsHostnames: true
      EnableDnsSupport: true

  KaliInstance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-0c94f3e6b6d1a5c33
      InstanceType: t3.medium
      KeyName: !Ref KeyPairName
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          apt-get update
          apt-get install -y nmap metasploit-framework
```

```bash
# Deploy with CloudFormation
aws cloudformation create-stack \
  --stack-name security-lab \
  --template-body file://cloudformation-security-lab.yml \
  --parameters ParameterKey=KeyPairName,ParameterValue=my-key-pair
```

### Azure Security Lab

#### Azure CLI Setup
```bash
# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Login and set subscription
az login
az account set --subscription "Your-Subscription-ID"

# Create resource group
az group create --name SecurityLab-RG --location eastus

# Create virtual network
az network vnet create \
  --resource-group SecurityLab-RG \
  --name SecurityLab-VNet \
  --address-prefix 10.0.0.0/16 \
  --subnet-name default \
  --subnet-prefix 10.0.1.0/24

# Create Kali Linux VM
az vm create \
  --resource-group SecurityLab-RG \
  --name KaliVM \
  --image kali-linux \
  --admin-username kali \
  --generate-ssh-keys \
  --size Standard_B2s \
  --public-ip-sku Standard

# Create vulnerable Windows VM
az vm create \
  --resource-group SecurityLab-RG \
  --name WindowsTarget \
  --image Win2019Datacenter \
  --admin-username labuser \
  --admin-password ComplexPassword123! \
  --size Standard_B2s

# Open necessary ports
az vm open-port --port 22 --resource-group SecurityLab-RG --name KaliVM
az vm open-port --port 3389 --resource-group SecurityLab-RG --name WindowsTarget

# List VMs and get IP addresses
az vm list-ip-addresses --resource-group SecurityLab-RG --output table
```

#### Azure Resource Manager Template
```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "adminUsername": {
      "type": "string",
      "defaultValue": "labuser"
    },
    "adminPassword": {
      "type": "securestring"
    }
  },
  "resources": [
    {
      "type": "Microsoft.Network/virtualNetworks",
      "apiVersion": "2020-06-01",
      "name": "SecurityLabVNet",
      "location": "[resourceGroup().location]",
      "properties": {
        "addressSpace": {
          "addressPrefixes": ["10.0.0.0/16"]
        },
        "subnets": [
          {
            "name": "default",
            "properties": {
              "addressPrefix": "10.0.1.0/24"
            }
          }
        ]
      }
    }
  ]
}
```

### GCP Security Lab

#### Google Cloud SDK Setup
```bash
# Install Google Cloud SDK
curl https://sdk.cloud.google.com | bash
exec -l $SHELL
gcloud init

# Set project and region
gcloud config set project your-project-id
gcloud config set compute/region us-central1
gcloud config set compute/zone us-central1-a

# Create VPC network
gcloud compute networks create security-lab-network --subnet-mode regional

# Create subnet
gcloud compute networks subnets create security-lab-subnet \
  --network security-lab-network \
  --range 10.0.1.0/24 \
  --region us-central1

# Create firewall rules
gcloud compute firewall-rules create allow-ssh \
  --network security-lab-network \
  --allow tcp:22 \
  --source-ranges 0.0.0.0/0

gcloud compute firewall-rules create allow-internal \
  --network security-lab-network \
  --allow tcp,udp,icmp \
  --source-ranges 10.0.0.0/16

# Create Kali Linux VM
gcloud compute instances create kali-vm \
  --machine-type e2-medium \
  --network-interface subnet=security-lab-subnet \
  --image-family debian-11 \
  --image-project debian-cloud \
  --metadata-from-file startup-script=kali-setup.sh

# Kali setup script
cat > kali-setup.sh << 'EOF'
#!/bin/bash
echo "deb http://http.kali.org/kali kali-rolling main non-free contrib" > /etc/apt/sources.list
wget -q -O - https://archive.kali.org/archive-key.asc | apt-key add
apt-get update
apt-get install -y kali-linux-core
EOF

# Create Windows target VM
gcloud compute instances create windows-target \
  --machine-type e2-medium \
  --network-interface subnet=security-lab-subnet \
  --image-family windows-2019 \
  --image-project windows-cloud \
  --metadata windows-startup-script-ps1='Install-WindowsFeature -name Web-Server -IncludeManagementTools'
```

## Specialized Security Platforms

### Security Onion All-in-One

```bash
# Download and install Security Onion
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/VERIFY_ISO.md
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.190-20231101.iso

# Verify ISO integrity
sha256sum -c securityonion-2.3.190-20231101.iso.sha256.txt

# Create VM with specific requirements
VBoxManage createvm --name "SecurityOnion" --ostype "Ubuntu_64" --register
VBoxManage modifyvm "SecurityOnion" --memory 16384 --cpus 4
VBoxManage modifyvm "SecurityOnion" --nic1 nat --nic2 intnet --intnet2 "MonitorNetwork"

# Post-installation setup
sudo so-setup

# Configure for standalone mode
sudo so-setup --allow-role standalone
```

### DetectionLab Environment

```bash
# Clone DetectionLab
git clone https://github.com/clong/DetectionLab.git
cd DetectionLab/Vagrant

# Customize Vagrantfile for your environment
cp Vagrantfile.example Vagrantfile

# Deploy full environment (requires significant resources)
vagrant up

# Individual VM deployment
vagrant up logger    # ELK stack
vagrant up dc        # Windows Domain Controller
vagrant up wef       # Windows Event Forwarding
vagrant up win10     # Windows 10 client
```

### HELK (Hunting ELK Stack)

```bash
# Clone HELK repository
git clone https://github.com/Cyb3rWard0g/HELK.git
cd HELK/docker

# Install with Docker Compose
sudo ./helk_install.sh

# Custom configuration
cat > helk-settings.yml << 'EOF'
version: '3.5'
services:
  helk-elasticsearch:
    image: cyb3rward0g/helk-elasticsearch:7.15.0
    environment:
      - ES_JAVA_OPTS=-Xms8g -Xmx8g
    volumes:
      - esdata:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"

  helk-logstash:
    image: cyb3rward0g/helk-logstash:7.15.0
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline:ro
    depends_on:
      - helk-elasticsearch

  helk-kibana:
    image: cyb3rward0g/helk-kibana:7.15.0
    ports:
      - "5601:5601"
    depends_on:
      - helk-elasticsearch
EOF

docker-compose -f helk-settings.yml up -d
```

## Automation and Orchestration

### Ansible Lab Provisioning

```bash
# Install Ansible
sudo apt install -y ansible

# Ansible inventory
cat > inventory.ini << 'EOF'
[kali]
kali-vm ansible_host=192.168.50.10 ansible_user=kali ansible_ssh_private_key_file=~/.ssh/lab_rsa

[targets]
target-ubuntu ansible_host=192.168.50.20 ansible_user=ubuntu
target-windows ansible_host=192.168.50.30 ansible_user=labuser ansible_connection=winrm

[all:vars]
ansible_python_interpreter=/usr/bin/python3
EOF

# Kali tools playbook
cat > setup-kali.yml << 'EOF'
---
- hosts: kali
  become: yes
  tasks:
    - name: Update package cache
      apt:
        update_cache: yes

    - name: Install security tools
      apt:
        name:
          - nmap
          - metasploit-framework
          - burpsuite
          - sqlmap
          - dirb
          - gobuster
          - john
          - hashcat
          - hydra
          - wireshark
        state: present

    - name: Start PostgreSQL for Metasploit
      service:
        name: postgresql
        state: started
        enabled: yes

    - name: Initialize Metasploit database
      shell: msfdb init
      become_user: kali
EOF

# Deploy configuration
ansible-playbook -i inventory.ini setup-kali.yml
```

### Terraform Multi-Cloud Lab

```hcl
# Multi-cloud security lab
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
  }
}

# AWS Security Lab
resource "aws_instance" "aws_kali" {
  provider      = aws.us_west
  ami           = var.kali_ami_id
  instance_type = "t3.medium"

  tags = {
    Name = "AWS-Kali-Lab"
  }
}

# Azure Security Lab
resource "azurerm_linux_virtual_machine" "azure_kali" {
  name                = "azure-kali-vm"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  size                = "Standard_B2s"

  source_image_reference {
    publisher = "kali-linux"
    offer     = "kali-linux"
    sku       = "kali"
    version   = "latest"
  }
}

# GCP Security Lab
resource "google_compute_instance" "gcp_kali" {
  name         = "gcp-kali-vm"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "projects/kali-linux-gcp/global/images/kali-linux"
    }
  }

  network_interface {
    network = "default"
    access_config {}
  }
}
```

### Lab Monitoring and Management

```bash
#!/bin/bash
# Lab environment health check script
LAB_VMS=("kali-vm" "target-ubuntu" "target-windows")
LOG_FILE="/var/log/lab-monitor.log"

log_message() {
    echo "$(date): $1" | tee -a $LOG_FILE
}

check_vm_status() {
    local vm_name=$1
    if VBoxManage showvminfo "$vm_name" | grep -q "running"; then
        log_message "VM $vm_name is running"
        return 0
    else
        log_message "VM $vm_name is not running - attempting to start"
        VBoxManage startvm "$vm_name" --type headless
        return 1
    fi
}

check_network_connectivity() {
    local target_ip=$1
    if ping -c 1 "$target_ip" > /dev/null 2>&1; then
        log_message "Network connectivity to $target_ip OK"
        return 0
    else
        log_message "Network connectivity to $target_ip FAILED"
        return 1
    fi
}

# Main monitoring loop
for vm in "${LAB_VMS[@]}"; do
    check_vm_status "$vm"
done

# Check network connectivity
check_network_connectivity "192.168.50.10"  # Kali VM
check_network_connectivity "192.168.50.20"  # Ubuntu target

# Snapshot management
create_lab_snapshots() {
    for vm in "${LAB_VMS[@]}"; do
        VBoxManage snapshot "$vm" take "daily-$(date +%Y%m%d)" \
            --description "Daily snapshot for $(date)"
    done
}

# Cleanup old snapshots (keep last 7 days)
cleanup_old_snapshots() {
    for vm in "${LAB_VMS[@]}"; do
        VBoxManage snapshot "$vm" list | grep "daily-" | head -n -7 | while read snapshot; do
            snapshot_name=$(echo "$snapshot" | cut -d' ' -f2)
            VBoxManage snapshot "$vm" delete "$snapshot_name"
        done
    done
}

# Run snapshot management
create_lab_snapshots
cleanup_old_snapshots
```

## Best Practices and Security Considerations

### Network Isolation
```bash
# Create isolated networks for lab environments
# VirtualBox network configuration
VBoxManage natnetwork add --netname LabNetwork --network "192.168.100.0/24" --enable

# iptables rules for lab isolation
iptables -A FORWARD -s 192.168.100.0/24 -d 10.0.0.0/8 -j DROP
iptables -A FORWARD -s 192.168.100.0/24 -d 172.16.0.0/12 -j DROP
iptables -A FORWARD -s 192.168.100.0/24 -d 192.168.0.0/16 ! -d 192.168.100.0/24 -j DROP

# Save iptables rules
iptables-save > /etc/iptables/lab-isolation.rules
```

### Resource Management
```bash
# Monitor resource usage
#!/bin/bash
# Resource monitoring script
while true; do
    echo "$(date): CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}'), Memory: $(free | grep Mem | awk '{printf("%.2f%%", $3/$2 * 100.0)}')"
    sleep 60
done > /var/log/lab-resources.log &

# Automatic VM shutdown during resource constraints
#!/bin/bash
MEMORY_THRESHOLD=90
CPU_THRESHOLD=80

current_memory=$(free | grep Mem | awk '{printf("%.0f", $3/$2 * 100.0)}')
current_cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')

if (( $(echo "$current_memory > $MEMORY_THRESHOLD" | bc -l) )) || (( $(echo "$current_cpu > $CPU_THRESHOLD" | bc -l) )); then
    echo "Resource threshold exceeded - shutting down non-essential VMs"
    VBoxManage controlvm "target-ubuntu" poweroff
    VBoxManage controlvm "target-windows" poweroff
fi
```

This comprehensive lab setup guide provides the foundation for building robust, scalable security research and testing environments across various platforms and technologies.