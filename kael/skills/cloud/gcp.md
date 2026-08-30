---
name: gcp
description: GCP security testing - IAM privilege escalation, Cloud Storage exposure, Workload Identity federation, metadata service abuse, and Cloud Functions as pivot
---

# GCP Security Testing

GCP environments share many attack patterns with AWS (IAM as the trust root, metadata service as the credential source) but differ in important ways: the `Metadata-Flavor: Google` header requirement, Workload Identity federation, Org Policies as the hard backstop, and the broader reliance on service accounts. The fastest paths to impact are usually storage bucket exposure, Workload Identity misconfiguration, and GKE metadata service abuse.

## Attack Surface

**Scope**
- IAM bindings (primitive roles like Owner/Editor/Viewer, predefined roles, custom roles)
- Service accounts and their IAM bindings, Workload Identity federation
- Cloud Storage (GCS) buckets, object ACLs, uniform bucket-level access
- Compute Engine, GKE, Cloud Run, Cloud Functions, App Engine
- Secret Manager, Cloud KMS, Cloud SQL
- Cloud DNS, VPC networks, firewall rules, Cloud NAT
- Cloud Build, Cloud Deploy, Artifact Registry
- Org Policies, IAM Conditions, Access Context Manager (Access Levels)

**Entry Points**
- Service account keys (JSON files in env vars, file system, metadata)
- Workload Identity-bound GKE service accounts
- OAuth user tokens, impersonation via `iam.serviceAccountTokenCreator`
- Application Default Credentials (ADC) populated from gcloud auth
- Cloud Shell session tokens

**Identity Boundaries**
- Org Policies are a hard backstop — they cannot grant permissions but can deny
- IAM Conditions (`iam.googleapis.com/.../condition`) add conditional constraints
- VPC Service Controls perimeters prevent data exfiltration even with valid credentials
- Access Context Manager (Access Levels) gate resource access by IP, device, etc.

## Key Vulnerabilities

### IAM Privilege Escalation

The classic path is a low-privilege principal that can modify another principal's IAM, create new service accounts, or impersonate higher-privileged accounts.

**Service Account Impersonation**
- `iam.serviceAccountTokenCreator` on a target SA → mint a short-lived OAuth token for that SA
- `iam.serviceAccountUser` → `actAs` the SA when creating resources that run as that identity
- `iam.serviceAccounts.actAs` on a service account's IAM policy
- `iam.workloadIdentityUser` role on the K8s SA binding → pivot to GKE pod identity

**Policy Modification**
- `resourcemanager.projects.setIamPolicy` → set any IAM binding on the project
- `resourcemanager.folders.setIamPolicy` → set IAM on a folder
- `orgpolicy.policy.set` → modify Org Policy (rare but high impact)
- `iam.roles.update` on a custom role → grant yourself more permissions

**Service Account Key Creation**
- `iam.serviceAccountKeys.create` on a target SA → mint long-lived JSON keys
- Keys are persistent (do not expire until manually deleted)
- Store in Secret Manager? Keys may be retrievable if the SA has `secretmanager.versions.access`

**Privilege Escalation Tools**
- `gcloud projects get-iam-policy`, `gcloud iam roles list`
- `gcloud projects add-iam-policy-binding` (if you have it)
- `python3 GCPBucketBrute.py` for bucket enumeration

**Test:**
```bash
gcloud auth list
gcloud config get-value account
gcloud projects get-iam-policy <project>
gcloud iam service-accounts list --project=<project>
gcloud iam service-accounts keys list --iam-account=<sa>@<project>.iam.gserviceaccount.com
```

### Cloud Storage Exposure

**Misconfigurations**
- Bucket with `allUsers` or `allAuthenticatedUsers` Reader
- Object ACLs granting public access (legacy, pre-uniform ACLs)
- Uniform bucket-level access disabled (allows per-object ACL overrides)
- Signed URLs with long expiration
- Public bucket policy via `roles/storage.objectViewer` for `allUsers`

**Test:**
```bash
# Public bucket check
curl https://storage.googleapis.com/<bucket>/
curl -I https://storage.googleapis.com/<bucket>/<known-object>

# Try with your own token
gsutil ls gs://<bucket>
gsutil iam get gs://<bucket>

# Anonymously-readable
curl https://storage.googleapis.com/storage/v1/b/<bucket>/o

# Brute force common names
python3 GCPBucketBrute.py -k <keyword>
```

### Workload Identity Federation Abuse

- Misconfigured trust domain → accept tokens from unintended OIDC providers
- `attribute-condition` too permissive (`assertion.email_verified==true` only) → any Google user with a verified email can federate
- AWS-style WIF (assume role from AWS) — over-permissive `google.subject == "system:serviceaccount:..."` conditions
- Kubernetes SA → GSA mapping via `iam.gke.io/gcp-service-account` annotation can be hijacked if pod admission isn't enforced
- Workload Identity binding for the `default` K8s namespace is common and overly broad

**Test:**
```bash
# Inspect WIF pools
gcloud iam workload-identity-pools list --location=global
gcloud iam workload-identity-pools providers list --workload-identity-pool=<pool> --location=global

# Try to impersonate
gcloud iam service-accounts generate-access-token \
    --impersonate-service-account=<sa>@<project>.iam.gserviceaccount.com
```

### Metadata Service Abuse

- IMDS-equivalent: `http://metadata.google.internal/computeMetadata/v1/`
- Required header: `Metadata-Flavor: Google` (returns 404 without it)
- Default service account token: `/computeMetadata/v1/instance/service-accounts/default/token`
- Scoped tokens: `?scopes=https://www.googleapis.com/auth/cloud-platform`
- Identity tokens: `?audience=<target-audience>` for WIF-bound services
- No equivalent of IMDSv2 hop limit — any container in a GKE pod with network access to `169.254.169.254/32` or `metadata.google.internal` can read it

**Test:**
```bash
curl -H "Metadata-Flavor: Google" \
    http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
curl -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes=https://www.googleapis.com/auth/cloud-platform"
```

### GKE-Specific Risks

- GKE metadata server (`http://169.254.169.254/computeMetadata/v1/` from inside a pod) → KSA token
- Workload Identity: `iam.gke.io/gcp-service-account: <gsa>@<project>.iam.gserviceaccount.com` annotation on the K8s SA
- Compromised pod with WIF → access GCP APIs as the bound GSA
- `containerd` / `kubelet` socket mounts in sidecars → host access
- GKE Autopilot clusters: no node SSH, but Workload Identity still works
- Older GKE versions: `metadata-overshadowing` — host network pod overwrites metadata response

### Cloud Functions / Cloud Run

- Function env vars hold secrets — runtime can read them
- `roles/cloudfunctions.functions.sourceCodeGet` → download source (secrets in code)
- `roles/run.services.update` → replace service with malicious image
- `roles/cloudbuild.builds.create` + service account as `buildServiceAccount` → arbitrary SA impersonation
- Service account runtime on Cloud Run: default compute SA is auto-created with broad access

### Secret Manager and KMS

- `roles/secretmanager.secretAccessor` on a secret → read it
- `roles/secretmanager.admin` → read, create, delete secrets
- `roles/cloudkms.cryptoKeyEncrypterDecrypter` → decrypt any data encrypted with the key
- Envelope encryption is everywhere in GCP — KMS access is often the highest-leverage finding

## Bypass Techniques

**Org Policy Bypasses**
- Org policies can be denied with a project-level override if the project isn't locked to the org
- Newly created projects can take ~30 seconds to inherit org policies
- VM instance creation can be permitted by a less-restrictive project policy

**VPC Service Controls Egress**
- Perimeter is enforced on the GCP API endpoint — direct IP access (e.g. to a GCS bucket IP) bypasses the perimeter
- GKE cluster API bypasses VPC-SC if the cluster is on the perimeter's excluded list
- Hybrid connectivity (Interconnect, VPN) into a perimeter can be a bypass vector

**IAM Conditions**
- `request.time` conditions can be defeated by waiting
- `request.auth.claims.email` conditions can be defeated by adding your email to the group
- `resource.name` conditions are easy to enumerate and find a path through

**Workload Identity**
- The K8s RBAC that gates which pods can use a GSA is *separate* from the GSA's GCP IAM
- If you can write to the K8s SA's annotation (`iam.gke.io/gcp-service-account`), you can redirect to a different GSA
- A K8s service account token can be reused against the metadata server from outside the pod for a few minutes after expiry

## Testing Methodology

1. **Establish identity** - `gcloud auth list`, `gcloud config get-value account`
2. **Enumerate projects** - `gcloud projects list`, check Org/Folder structure
3. **Service accounts** - List all SAs, inspect their IAM, check for unused SAs
4. **WIF audit** - List WIF pools, check providers and attribute conditions
5. **Storage scan** - For each project, list buckets and check public access
6. **Compute access** - Try `gcloud compute instances list`, GKE cluster enumeration
7. **Cloud Build / Deploy** - `roles/cloudbuild.builds.create` is often over-granted
8. **Pivot to admin** - Use `gcloud iam service-accounts generate-access-token --impersonate-service-account`
9. **Exfil test** - Confirm reach to GCS / Secret Manager / Cloud SQL with the assumed identity
10. **Audit** - Check Cloud Audit Logs for what your enumeration looks like

## Validation

1. Demonstrate a non-admin identity gaining project-level Editor or Owner via documented chain
2. Prove Workload Identity abuse by minting a token from outside the cluster and using it against a real GCP API
3. Show actual credential extraction (SA key, OAuth token, identity token) and verify it grants claimed access level
4. For GCS, demonstrate object read/write to a private bucket via the misconfiguration
5. For metadata service, confirm token extraction and use it to call `gcloud projects list` from a fresh shell

## False Positives

- `iam.serviceAccountTokenCreator` on an SA with no other roles (low impact by itself)
- Public bucket with VPC-SC perimeter preventing data exfil
- GKE pod with WIF where the GSA has only `storage.objects.get` on a specific bucket prefix
- WIF provider with strict `attribute-condition` like `assertion.sub matches "https://github.com/my-org/*"`
- Workload Identity binding blocked by `iam.googleapis.com/allowedPolicyMemberDomains` org policy
- Cloud Build / Run with binary authorization denying unapproved images

## Impact

- Full project takeover from a single low-privilege IAM principal
- Cross-project pivot via Workload Identity federation
- GCS data exfiltration (PII, source code, credentials, customer data)
- Cloud Function/Run code execution under a privileged runtime SA
- Persistence via new SA keys, backdoor Cloud Functions, modified IAM bindings
- Billing impact: crypto mining via high-privilege GKE / Compute / Cloud Run

## Pro Tips

1. Always start with `gcloud auth list` and `gcloud projects get-iam-policy <project>` to map your blast radius
2. `gcloud projects get-iam-policy <project> --flatten="bindings[].members" --format="table(bindings.role)"` gives a quick role census
3. `gcloud iam service-accounts generate-access-token --impersonate-service-account` is the closest equivalent to `aws sts assume-role` — try it on every SA you can list
4. `gcloud projects add-iam-policy-binding --member=user:me@<domain> --role=roles/owner` is the test every Org Policy should reject
5. GCS bucket misconfigurations are extremely common — `python3 GCPBucketBrute.py` finds them in seconds
6. The GCE metadata server has no hop limit — a compromised GKE pod can reach it via either the metadata server sidecar or `169.254.169.254/computeMetadata/v1/` directly
7. Workload Identity on GKE Autopilot is enabled by default and *cannot* be disabled — treat it as a permanent attack surface
8. Secret Manager and Cloud KMS are the highest-value targets in any project — `secretmanager.versions.access` and `cloudkms.cryptoKeyVersions.useToDecrypt` are the two roles to check first
9. Cloud Audit Logs are *not* enabled by default for all services — `gcloud services enable cloudaudit.googleapis.com` and check what's being recorded
10. After gaining access, always check `gcloud logging read "logName=projects/<project>/logs/cloudaudit.googleapis.com" --limit=50` to see what your activity looks like from the defender's view

## Summary

GCP failures chain: a low-privilege principal → IAM modification or impersonation path → service account pivot → compute access → data reach. The metadata server is the universal credential source; Workload Identity makes it usable from anywhere a K8s pod runs. Test the chain, not just individual findings, and start from the identity you have, not the one you wish you had.
