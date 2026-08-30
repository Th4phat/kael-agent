---
name: azure
description: Azure security testing - Entra ID privilege escalation, Storage Account SAS abuse, Managed Identity pivot, App Services/Function Apps as entry points, and Azure AD attack paths
---

# Azure Security Testing

Azure environments differ from AWS/GCP in important ways: Entra ID (Azure AD) is the unified identity layer, Managed Identities replace long-lived keys in many services, RBAC is the primary authorization model (with classic subscription Admin roles as the backstop), and ARM (Azure Resource Manager) is the single control plane. The fastest paths to impact are usually Managed Identity abuse, Storage Account SAS token leakage, and App Service / Function App source code access.

## Attack Surface

**Scope**
- Entra ID (Azure AD) users, groups, service principals, app registrations, managed identities
- Azure RBAC (built-in and custom role definitions) at subscription, resource group, and resource scope
- Classic subscription roles: Owner, Contributor, User Access Administrator
- Storage Accounts (blob, file, queue, table), Data Lake, Cosmos DB
- App Services, Function Apps, Logic Apps, Container Apps, AKS
- Key Vault, Managed HSM, Disk Encryption Sets
- Virtual Machines, VM Scale Sets, Bastion
- Azure DevOps (orgs, projects, pipelines, service connections)

**Entry Points**
- Service principal secrets and certificates in env vars, Key Vault, app settings
- Managed Identity tokens (IMDS endpoint at 169.254.169.254)
- Azure CLI tokens (`az login` cache), MSAL tokens
- User OAuth tokens with offline_access scope
- Storage Account SAS tokens in source control, URLs in code
- Pipeline service connections (Azure DevOps → Azure subscription)

**Identity Boundaries**
- Entra ID Conditional Access (MFA, device compliance, location)
- Privileged Identity Management (PIM) — time-bound role activation
- Resource Locks (CanNotDelete, ReadOnly)
- Management Groups and Blueprints / Deployments

## Key Vulnerabilities

### Entra ID Privilege Escalation

The classic path is a low-privilege user who can modify another principal's directory role, grant an app registration, or activate a PIM-eligible role.

**Role Modification**
- `microsoft.directory/roleAssignments/write` (e.g. Global Administrator, Privileged Role Administrator)
- `microsoft.directory/users/owner/update` on a subscription or resource group
- `Microsoft.Authorization/roleAssignments/write` at subscription scope → Owner role
- `Microsoft.Authorization/roleDefinitions/write` → modify a custom role's permissions

**Application & Service Principal Abuse**
- `Application Administrator` / `Cloud Application Administrator` → add credentials to an app
- `Application.ReadWrite.OwnedBy` → modify apps you own
- `App role assignment` with high-privilege role on a target resource
- Service principal with `Contributor` + the ability to create new SPNs via automation

**PIM Abuse**
- Eligible Global Administrator → activate and immediately act (less stealthy)
- Eligible role for which activation policy requires MFA but you've compromised the MFA device
- Time-window PIM escalation: eligible role + auto-approval policy

**OAuth Consent Abuse**
- `api://.../user_impersonation` with high-privilege Graph API permissions
- Tenant-wide admin consent granted to a malicious app
- `Mail.Read`, `Files.ReadWrite`, `Directory.ReadWrite.All`, `User.ReadWrite.All`

**Test:**
```bash
# Enumerate your roles
az role assignment list --assignee <object-id> --all

# Enumerate directory roles
az rest --method GET --url "https://graph.microsoft.com/v1.0/directoryRoles"

# Enumerate PIM-eligible roles
az rest --method GET --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules"

# Find apps you own
Get-MgServicePrincipal -Filter "appOwnerOrganizationId eq <tenant-id>"
```

### Managed Identity Abuse

Managed Identities (system-assigned and user-assigned) are the Azure equivalent of AWS instance roles / GCP service accounts. They appear in Entra ID as service principals with credentials held by Azure — applications running in Azure services can request a token for them via IMDS.

**Token Acquisition**
- IMDS endpoint: `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/`
- Required header: `Metadata: true`
- No equivalent of IMDSv2 — anything on the VM can read it
- Tokens are valid for ~1 hour, refresh by repeating the request

**Pivot to Other Resources**
- Get a token for `https://management.azure.com/` → enumerate resources
- Get a token for `https://vault.azure.net` → read Key Vault secrets
- Get a token for `https://storage.azure.com/` → access storage
- Get a token for `https://graph.microsoft.com/` → enumerate Entra ID
- Get a token for `https://<custom-audience>` → access that resource as the MI

**Test:**
```bash
# From a compromised Azure VM or App Service
curl -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Decode the JWT
echo "<token>" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

### Storage Account SAS Token Abuse

- SAS tokens are URL-embedded credentials; leakage = full account compromise
- Account SAS, Service SAS, User Delegation SAS — each has different abuse paths
- Long-lived tokens (`se=2030-...`) in source control are the most common finding
- Over-permissive permissions on the SAS (`sp=rwdlacu`) → read + write + delete
- Permissive IP allowlist (`sip=0.0.0.0-255.255.255.255` → not an allowlist at all)
- `ss=b` (blob) + `srt=sco` (service, container, object) + `sp=rw` → full data plane

**Test:**
```bash
# Decode SAS token parameters
echo "<sas-uri>" | grep -oE '[?&][a-z]+=[^&]+'

# Try the SAS against other storage resources
az storage blob list --account-name <account> --container <container> \
    --sas-token "<sas>"

# Find more containers with the same SAS
curl "<account>.blob.core.windows.net/?<sas>&comp=list"

# Generate new SAS if you have the account key
az storage account keys list --account-name <account>
az storage container generate-sas --account-name <account> \
    --name <container> --permissions racwdl --expiry <date>
```

### App Service / Function App Source Code Access

- `Microsoft.Web/sites/config/list` → read `appsettings` (often holds secrets, connection strings)
- `Microsoft.Web/sites/extensions` and `scm` endpoint (`https://<app>.scm.azurewebsites.net/`)
- Kudu (`/api/zip` or `/api/deployments`) → download deployed source
- `AZURE_APP_SERVICES_ENV` env vars in containerized apps
- `WEBSITE_RUN_FROM_PACKAGE` + the SAS-protected blob that holds the package
- `Microsoft.Web/sites/publishxml/action` → generate a publish profile with deploy credentials

**Test:**
```bash
# Read app settings
az webapp config appsettings list --name <app> --resource-group <rg>

# Kudu REST API
curl -u "<creds>" https://<app>.scm.azurewebsites.net/api/settings
curl -u "<creds>" https://<app>.scm.azurewebsites.net/api/zip

# Publish profile
az webapp deployment list-publishing-profiles --name <app> --resource-group <rg>
```

### Azure DevOps Abuse

- Pipelines often run with `Contributor` on the subscription via a service connection
- `Azure PowerShell` / `Azure CLI` tasks in pipelines run as the service connection identity
- Pipeline variable groups can hold secrets readable by anyone with Edit on the pipeline
- Service connections store service principal secrets (rotated manually)
- Compromised pipeline = write access to source, ability to run scripts, build artifact injection
- Build artifacts: signed but the signing happens in the build pipeline itself
- Self-hosted agents: full kernel access from the build job

**Test:**
```bash
az devops project list
az pipelines list
az pipelines run --name <pipeline> --variables key=value
```

### Key Vault and Managed HSM

- `Microsoft.KeyVault/vaults/secrets/getSecret` → read the secret
- `Microsoft.KeyVault/vaults/keys/decrypt` → decrypt data encrypted with the key
- `Microsoft.KeyVault/vaults/cryptoService/encrypt` → encrypt arbitrary data
- RBAC vs Vault Access Policy: the legacy model grants per-secret permissions; new model uses RBAC
- Soft-delete retention: deleted secrets are recoverable for 7-90 days
- MI access to Key Vault: `access policies` (legacy) or RBAC (new) — `getSecret` is the test

### Azure Kubernetes Service (AKS)

- Managed Identity assigned to AKS cluster has permissions in MC_ resource group (usually Contributor)
- AKS uses Entra ID for admin authentication; the cluster's MI has access to MC_ VMs, NICs, disks
- `kubelet` identity → MSAL token for the AKS MI
- Older AKS versions: legacy AAD admin → local accounts may be enabled
- Workload Identity (Entra Workload ID): `azure.workload.identity/client-id` annotation on K8s SA → federate to a User-Assigned MI
- Compromised pod → access to all data the bound MI can reach (Key Vault, Storage, etc.)
- `--enable-oidc-issuer` is required for Workload Identity to function

## Bypass Techniques

**PIM and Time-Based Access**
- If you control the user with the eligible role, just activate
- PIM notifications and ticket approval are the intended checkpoint — bypass requires either compromised approver or compromised MFA
- Eligible role for which activation is permanent (`"permanent": true` in the role setting) — no time limit

**Conditional Access Bypass**
- Legacy auth protocols (SMTP, POP, IMAP) often bypass MFA in older tenants
- Browser-based flows from a managed device may bypass MFA even for high-privilege apps
- `New York` / `San Francisco` location allowlist can be defeated via residential proxy

**Subscription-Level Bypasses**
- Tenant root group (`/providers/Microsoft.Management/managementGroups/<tenant-id>`) — the highest scope
- Management group assignments apply to all child subscriptions
- A subscription moved out of the management group loses the inherited assignments

**App Registration Trust**
- Multi-tenant apps with verified publisher status have implicit trust
- Apps with admin consent pre-granted for `User.ReadWrite.All` or `Directory.ReadWrite.All`
- A user's existing consent to an app is preserved — compromise the app credentials, not the user

**Cross-Tenant**
- External users / guests often have broader access than internal users
- B2B guest users from a trusted partner org may bypass tenant Conditional Access

## Testing Methodology

1. **Establish identity** - `az account show`, `az account get-access-token`, decode the JWT
2. **Enumerate role assignments** - `az role assignment list --all`, look for Owner/Contributor/UAA
3. **Enumerate Entra ID** - `Get-MgUser`, `Get-MgGroup`, `Get-MgServicePrincipal`, `Get-MgApplication`
4. **MI check** - If on an Azure VM or App Service, query IMDS for managed identity tokens
5. **App Service probe** - Kudu, `appsettings`, deploy profile for any accessible apps
6. **Storage audit** - For each storage account, check SAS tokens, public access, MI assignments
7. **Key Vault** - List vaults, check access policies and RBAC assignments
8. **PIM** - Check `roleEligibilitySchedules` for your user → activate
9. **Azure DevOps** - Project list, pipeline list, check for service connections
10. **Audit** - Check Activity Log and Entra ID Sign-in Logs for what your enumeration looks like

## Validation

1. Demonstrate a non-admin user gaining Owner / Contributor / Global Administrator via a documented chain
2. Prove Managed Identity abuse by getting a token from IMDS and using it against `az` or ARM API
3. Show actual credential extraction (SAS token, MI token, Key Vault secret) and verify it grants claimed access level
4. For Storage, demonstrate object read/write to a private blob using the SAS
5. For App Service, demonstrate downloading source code via Kudu or reading connection strings from appsettings

## False Positives

- `Contributor` on a single resource group (not subscription) with no path to escalate
- MI with `Storage Blob Data Reader` only (read, not write)
- Conditional Access enforcing MFA + device compliance (hard to bypass)
- PIM role requires multi-stage approval with no compromised approver
- Storage Account with `allowBlobPublicAccess=false` and no public containers
- App Service with managed identity disabled and no secrets in appsettings
- Azure DevOps with branch policies enforcing PR reviews and required builds
- AKS with Workload Identity disabled and legacy AAD auth requiring cluster admin role

## Impact

- Full subscription or tenant takeover from a single low-privilege user
- Cross-subscription pivot via management group inheritance
- Storage data exfiltration (PII, source code, credentials, customer data)
- App Service / Function code execution under a privileged MI
- AKS cluster compromise → node access → adjacent subscriptions via MC_ MI
- Persistence via new app registrations, new service principals, modified conditional access

## Pro Tips

1. Always start with `az account show` and `az role assignment list --all` to map your blast radius
2. `Get-MgRoleManagementDirectoryRoleAssignment` (Graph API) gives directory role assignments — often the highest-leverage permissions
3. `az rest --method GET --url "https://graph.microsoft.com/v1.0/me"` → decode the JWT to see your effective scopes
4. Managed Identity abuse is the most common path from a compromised App Service / VM / Function App — always check IMDS first
5. `az ad sp list --all` returns every service principal — look for ones with high-privilege app role assignments
6. SAS tokens in git history are catastrophic — use `gitleaks`, `trufflehog`, or `git secrets` to find them
7. `az keyvault secret list --vault-name <vault>` is the single most lucrative command in any Azure engagement
8. Azure DevOps pipelines are usually the softest underbelly — `az pipelines list` then check for service connections with broad access
9. PIM-eligible role activation is logged and notified — if you activate Global Administrator, expect alerts
10. After gaining access, check `az monitor activity-log list` to see what your activity looks like from the defender's view

## Summary

Azure failures chain: a low-privilege user → Entra ID modification or Managed Identity abuse → service principal or RBAC pivot → compute or data access. Managed Identities are the universal credential source (just like AWS instance roles); App Services and Function Apps are the most common MI-bearing entry points. Test the chain, not just individual findings, and start from the identity you have, not the one you wish you had.
