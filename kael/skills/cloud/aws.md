---
name: aws
description: AWS security testing - IAM privilege escalation, S3/STS exposure, Lambda/SSM as entry points, metadata service, and cross-service trust abuse
---

# AWS Security Testing

AWS environments expose a vast attack surface through IAM, S3, Lambda, EC2, and dozens of inter-service trust relationships. The fastest paths to impact are usually over-permissive IAM, public S3 buckets, and metadata service abuse. This skill covers direct AWS access scenarios. For SSRF-mediated AWS access, see the ssrf skill.

## Attack Surface

**Scope**
- IAM identities (users, roles, groups, policies) and STS-assumed roles
- S3 buckets, object ACLs, bucket policies, presigned URLs
- EC2 / ECS / EKS / Lambda runtimes and their execution roles
- SSM Session Manager, Systems Manager documents, parameter store
- CloudFront, API Gateway, ELB, Route 53 hosted zones
- Cognito identity pools, STS web identity federation
- AWS Organizations, service control policies (SCPs), account boundaries

**Entry Points**
- Long-lived access keys (env vars, ~/.aws/credentials, EC2 user-data, Lambda env)
- Assumed-role sessions (STS credentials) from CI/CD, ECS task roles, EKS IRSA, Lambda execution roles
- Cognito identity pool tokens, web identity tokens from OIDC providers
- SSO refresh tokens, SAML assertions
- Leaked GitHub repos containing workflow credentials

**Identity Boundaries**
- SCPs limit the *maximum* permissions in an account
- Permission boundaries limit a single principal's effective permissions
- Session policies (STS) further restrict an assumed role's permissions
- Resource-based policies (S3, KMS, Lambda) grant cross-account access

## Key Vulnerabilities

### IAM Privilege Escalation

The classic path is a low-privilege principal that can modify another principal's permissions or invoke a service that returns credentials.

**Policy Modification**
- `iam:CreatePolicyVersion` with `SetAsDefault=true` on a customer-managed policy attached to a role you can assume
- `iam:AttachUserPolicy` / `iam:AttachRolePolicy` / `iam:AttachGroupPolicy` against a principal you control
- `iam:PutUserPolicy` / `iam:PutRolePolicy` (inline)
- `iam:CreateAccessKey` for another user → forge CLI/SDK calls
- `iam:UpdateAssumeRolePolicy` on a role you can reach
- `iam:AddUserToGroup` on a group with more privilege

**Service-Based Credential Generation**
- `lambda:CreateFunction` + `lambda:InvokeFunction` + `iam:PassRole` → run code under a higher-privileged execution role
- `glue:UpdateDevEndpoint` → reset SSH key on a dev endpoint and SSH in
- `ec2:RunInstances` + `iam:PassRole` → launch an instance with an admin instance profile
- `ssm:SendCommand` / `ssm:StartSession` on managed instances
- `ecs:RegisterTaskDefinition` + `ecs:RunTask` + `iam:PassRole` → run a task under a privileged role
- `cloudformation:CreateStack` + a template that creates high-privilege resources

**Trust Policy Modification**
- `iam:UpdateAssumeRolePolicy` on any role you can already assume
- Adding yourself (`aws:SourceIp`, `aws:SourceVpc`, `aws:PrincipalTag/*`) to a permissive trust policy

**Test:**
```bash
# Enumerate effective permissions
aws sts get-caller-identity
aws iam get-account-summary
aws iam list-roles --output text | head -50
aws iam list-policies --scope Local --output text

# Generate a privilege-escalation report from your access key
python3 ~/tools/PMapper/pmapper.py graph
```

### S3 Bucket Exposure

**Misconfigurations**
- Public bucket via `PublicAccessBlock` not enforced
- Public ACLs on the bucket or its objects
- Bucket policy granting `Principal: "*"` with `Action: "s3:GetObject"`
- Unintentional cross-account access via permissive policies
- Presigned URLs in source control with long expiration

**Test:**
```bash
# Public bucket check
aws s3 ls s3://<bucket> --no-sign-request
curl -I https://<bucket>.s3.amazonaws.com/

# Try common misconfiguration
curl -X PUT https://<bucket>.s3.amazonaws.com/test-key
# If 200/204 → write access; bucket is wide open

# Enumerate via misconfigured S3 XML listing
curl https://<bucket>.s3.amazonaws.com/?list-type=2

# Dump your own access pattern
aws s3api get-bucket-policy --bucket <bucket>
aws s3api get-bucket-acl --bucket <bucket>
aws s3api get-public-access-block --bucket <bucket>
```

### Metadata Service Abuse

- IMDSv1: `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` returns the role's temporary credentials
- IMDSv2 (token required): `PUT /latest/api/token` with header `X-aws-ec2-metadata-token-ttl-seconds: 21600`, then include `X-aws-ec2-metadata-token` on subsequent GETs
- ECS task credentials: `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`
- EKS pod identity: `http://169.254.170.23/v1/credentials` (Pod Identity), or IMDSv2 from kubelet
- Lambda env: `AWS_LAMBDA_FUNCTION_NAME`, `AWS_LAMBDA_FUNCTION_VERSION`, `AWS_LAMBDA_INITIALIZATION_TYPE`

**Test:**
```bash
curl http://169.254.169.254/latest/meta-data/
curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
    http://169.254.169.254/latest/api/token
```

### Lambda as a Pivot

- Function env vars frequently hold DB credentials, API keys, third-party tokens
- `lambda:GetFunctionConfiguration` reveals env vars to anyone with `lambda:Get*`
- `lambda:UpdateFunctionCode` lets you replace a function's code and run it under its execution role
- Layers (`lambda:GetLayerVersion`) often contain secrets in the layer ZIP
- Function URLs without `AuthType: AWS_IAM` are publicly invocable
- `lambda:InvokeFunctionUrl` may not be IAM-gated if misconfigured

### Cognito Identity Pool Abuse

- Unauthenticated identity pools return temporary AWS credentials for any anonymous caller
- Misconfigured role trust on the authenticated/unauthenticated role → full account compromise
- Test:
  ```bash
  aws cognito-identity get-id --identity-pool-id <pool> --account-id <acct>
  aws cognito-identity get-credentials-for-identity --identity-id <id>
  ```

### SSM Session Manager

- `ssm:StartSession` on managed instances gives an interactive shell with the instance's IAM role
- No ingress rule required — sessions are outbound
- `ssm:SendCommand` runs commands asynchronously on many instances at once
- `ssm:DescribeInstanceInformation` enumerates accessible instances

## Bypass Techniques

**Policy Evaluation Order**
- Explicit deny > SCP > Resource policy > Identity policy > Session policy > Permission boundary
- Adding a session policy that grants the same permissions does not override a deny
- `iam:PassRole` is the most commonly missed action in least-privilege reviews

**Cross-Account Trust**
- Roles with `Principal: { AWS: "arn:aws:iam::ACCOUNT:role/..." }` trust any principal in the trusted account — pivot by assuming a role in that account
- `aws:SourceArn` / `aws:SourceVpc` conditions can be defeated if the trusted account's perimeter is weak

**Resource Policy Weakness**
- KMS key policies granting `Principal: "*"` allow any account that knows the key alias
- SNS topics / SQS queues with permissive policies → message injection
- EventBridge rules → cross-account Lambda invocation

**IMDS Hop**
- A compromised container without `AWS_EC2_METADATA_DISABLED=true` can reach IMDS
- A compromised EC2 instance with IMDSv1 can be reached via SSRF if the application has the `http://169.254.169.254` allowlist
- Hop limit (`PUT /latest/api/token` requires `X-aws-ec2-metadata-token-ttl-seconds` AND `X-Forwarded-For` is ignored)

## Testing Methodology

1. **Establish identity** - `aws sts get-caller-identity`, parse the role ARN and account
2. **Enumerate IAM** - `aws iam list-roles`, `aws iam list-policies --scope Local`, identify trust relationships
3. **Privilege escalation** - Run PMapper / enumerate PermissionsForResource / check for `iam:PassRole`
4. **S3 audit** - For each bucket you can describe, check PublicAccessBlock and policy
5. **Try public services** - Scan S3 / SNS / SQS / SES for public exposure
6. **Pivot to compute** - SSM Session Manager, Lambda invocation, ECS run-task with high-priv role
7. **Exfil test** - Confirm reach to STS, S3, KMS with the assumed identity
8. **CloudTrail audit** - Check CloudTrail for what your enumeration looks like (simulate detection)
9. **Cleanup** - Revert any resources you created (Lambda, EC2, role changes)

## Validation

1. Demonstrate a non-admin identity gaining admin or account-takeover-level access via a documented chain
2. Prove cross-account trust abuse by enumerating a role's trust policy and assuming it from the source account
3. Show actual credential extraction (STS, S3, RDS, KMS) and verify it grants claimed access level
4. For S3, demonstrate object read or write to a private bucket via the misconfiguration
5. For metadata service, confirm token extraction and use it to call `aws s3 ls` or `aws sts get-caller-identity` from a fresh process

## False Positives

- `iam:PassRole` listed but the service it pairs with is denied by an SCP
- Public S3 bucket policy that's restricted to a specific VPC endpoint (`aws:SourceVpce`)
- Cross-account role trust that requires an MFA condition you can't bypass
- IMDSv2 enforced with hop limit of 1 — SSRF can't reach the second hop
- Lambda `UpdateFunctionCode` denied by an explicit `iam:DeniedActions` SCP
- Permissions limited by a session policy at STS-AssumeRole time

## Impact

- Full account takeover from a single low-privilege IAM principal
- Cross-account pivot via permissive role trust
- S3 data exfiltration (PII, source code, credentials, customer data)
- Lambda code execution under a privileged execution role
- Persistence via new IAM access keys, backdoor Lambda functions, modified trust policies
- Billing impact: crypto mining via high-privilege EC2 / Lambda / ECS

## Pro Tips

1. Always start with `aws sts get-caller-identity` to map your blast radius before enumerating
2. PMapper (`pip install pmapper`) generates a privilege-escalation graph from your access key
3. `aws iam generate-service-last-accessed-details` shows which services a principal has touched
4. Public S3 misconfigurations are noisy in CloudTrail — expect to trip GuardDuty `S3BucketAnonymousAccess`
5. SSM Session Manager bypasses security groups entirely; outbound 443 to `ssm.<region>.amazonaws.com` is the only network requirement
6. Lambda env vars are encrypted at rest with a KMS key — `kms:Decrypt` on that key is required to read them via the console but the runtime can always read its own
7. `aws:ResourceTag/*` conditions can be defeated by `ec2:CreateTags` on the resource after launch
8. Cognito identity pools often accept unauthenticated identities even when the intent was authenticated-only
9. Test for `sts:AssumeRole` against every role you can list — most accounts have a "break glass" admin role with a permissive trust policy
10. Always check for unused access keys with `aws iam get-access-key-last-used` — the oldest one is usually the least-rotated and most-privileged

## Summary

AWS failures almost always chain: a low-privilege principal → IAM modification path → role assumption → compute pivot → data access. Test the chain, not just individual findings. Start from the identity you have, enumerate the trust graph, and escalate methodically along the shortest documented path.
