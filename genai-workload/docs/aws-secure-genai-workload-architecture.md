# Secure Generative AI Workload on AWS

**Architecture Specification**
**Status:** buildable target state
**Deployment mechanism:** CloudFormation

---

## 1. Scope

This document specifies a multi-account AWS architecture for a guarded LLM inference service with retrieval augmentation. It covers network isolation, authentication and authorization, guardrail enforcement, identity, cryptography, audit, cost governance, data lifecycle, backup, and delivery.

The design assumes two classes of caller — interactive human users and machine callers such as MCP tool invocations — and treats the model as an untrusted component whose output requires validation regardless of how the request was authenticated.

Section 17 states the constraints and residual risks that remain after every control described here is in place.

---

## 2. Account topology

| Account | Role | Key contents |
|---|---|---|
| **Management** | Org root, SCP attachment | AWS Organizations, delegated-admin registrations, Budgets and Cost Anomaly Detection at payer scope. No workloads |
| **Security** | Detection, posture, response | Security Hub (delegated admin), GuardDuty, Config aggregator, Macie, Inspector, EventBridge response runbooks, scanning-export bucket, `SecReadOnlyRole` origin |
| **Log Archive** | Immutable retention | Org Trail bucket, Object Lock compliance mode, model-invocation logs, `cmk/audit` |
| **Backup** | Recovery-point custody | Central AWS Backup vault, Vault Lock compliance mode, `cmk/backup`. No principal with delete rights |
| **Workload (prod)** | The application | Edge, API tier, VPC, Bedrock integration, application data |
| **Shared Services** | Delivery | CodePipeline, artifact store, template scanning, `PipelineExecRole` |
| **ML / Data Science** | Experimentation | SageMaker Studio, Bedrock dev models, MWAA, `DataScienceRole` under a permissions boundary |

The Workload account holds no long-lived audit data, no recovery points, and no deployment credentials.

Backup is separated from Log Archive because their threat models differ. Audit data must survive tampering; recovery points must survive destruction. An account holding both is a single target whose compromise removes both the record of an incident and the ability to recover from it.

---

## 3. Edge

| Component | Configuration |
|---|---|
| Route 53 | A/AAAA alias to CloudFront; DNSSEC signing on the hosted zone; Resolver DNS Firewall on outbound VPC resolution, allow-list aligned to the Network Firewall FQDN list |
| CloudFront | TLS 1.2+ minimum (1.3 preferred), custom certificate, response headers policy (HSTS with preload, CSP, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`); origin custom header `x-origin-verify` sourced from Secrets Manager |
| WAF (CloudFront scope) | Managed core, known-bad-inputs, and IP-reputation rule groups; custom rules for oversized bodies and prompt-payload ceilings; rate-based rule on source IP; logging to Firehose → Log Archive |
| Shield Advanced | L7 mitigation, cost protection, SRT engagement, protection groups on the distribution and hosted zone |
| S3 (static assets) | Origin Access Control, SigV4-signed origin requests, public access block, SSE-KMS |

**Origin cloaking.** The `x-origin-verify` header proves a request transited CloudFront. Because a static shared secret degrades into a permanent bypass credential once leaked, it is stored in Secrets Manager and rotated on a schedule. The rotation function updates the CloudFront origin custom header and the regional WAF rule in a single operation, using a dual-value overlap window so in-flight requests are not rejected mid-rotation. This is paired with an API Gateway resource policy denying any source other than the distribution ARN — the header is the fast check, the resource policy is the one that holds if the header leaks.

---

## 4. API and authorization

### 4.1 API tier

| Component | Configuration |
|---|---|
| API Gateway | REST, regional. Resource policy denies any source other than the CloudFront distribution ARN. Request validation on models. `X-Request-ID` required and propagated as the trace correlation key. JSON access logging to an encrypted log group |
| WAF (regional) | Rule 1: `x-origin-verify` header match against the current secret value. Rule 2: rate-based with a custom aggregation key on the caller identity (§4.6). Rule 3: managed rule groups mirroring the edge set |

**Why REST rather than HTTP API.** AWS WAF associates with API Gateway REST APIs only, and resource policies are likewise a REST-only feature. Both are load-bearing here: the regional WAF enforces origin verification and per-identity rate limiting, and the resource policy is the backstop for origin cloaking. An HTTP API would supply a native JWT authorizer with an audience parameter, but at the cost of the two controls that matter more. Claim validation is therefore performed by a Lambda authorizer, which is the documented path for JWT verification on REST APIs.

### 4.2 Identity provider

One Cognito user pool, two app clients:

| Client | Flow | Token in use | Purpose |
|---|---|---|---|
| Human | Authorization code + PKCE, hosted UI, refresh rotation | ID token or access token | Interactive users |
| Machine | `client_credentials` against a resource server with scopes `llm/invoke` and `llm/retrieve` | Access token | MCP tool callers and other service principals |

PKCE protects a public client performing an interactive redirect. It is not a machine-to-machine mechanism, and reusing it for service callers produces an identity that cannot be distinguished from a user in the audit trail. The two client types are separated at the app-client level so they carry different scopes, different token lifetimes, and different rate limits.

### 4.3 Token claim model

Claim availability differs by token type, and the difference determines what can be validated:

| Claim | ID token | Access token |
|---|---|---|
| `aud` | App client ID | **Absent**, unless the client requested an API resource binding — then the target API URL |
| `client_id` | — | App client ID |
| `token_use` | `id` | `access` |
| `scope` | — | Granted OAuth scopes |
| `sub` | End user | End user, or **the app client ID** on `client_credentials` |
| `origin_jti` | Revocation identifier | Revocation identifier |
| `cognito:groups` | Group membership | — |

The consequence: **an access token issued through `client_credentials` carries no `aud` claim at all.** A validator configured to check `aud` on that path does not fail closed — depending on the library it either errors or silently passes an empty audience set. Client binding on the machine path is established by `client_id`, not `aud`.

Where a true RFC 9068-style audience is required, request an API resource binding at the token endpoint; the issued access token then carries `aud` set to the target API URL, and that value survives refresh.

### 4.4 Validation matrix

The authorizer performs the following checks. Every row is mandatory; a token failing any check is rejected before the integration is reached.

| Check | Human path | Machine path |
|---|---|---|
| Signature | RS256 against the pinned JWKS | RS256 against the pinned JWKS |
| `iss` | Exact user pool issuer URL, hardcoded | Same |
| `token_use` | `id` or `access`, matching what the route expects | `access` |
| Client binding | `aud` equals a permitted app client ID | **`client_id`** equals a permitted app client ID — or `aud` equals the API URL where resource binding is enabled |
| Authorization | `cognito:groups` or `scope` | `scope` contains the scope required by the method |
| `exp` / `nbf` | Enforced with minimal clock skew | Same |
| Tenant | Tenant claim present and known | Delegated tenant claim present and known (§4.6) |

### 4.5 Authorizer implementation

A **REQUEST** authorizer is used rather than a TOKEN authorizer, for cache correctness.

**The caching hazard.** API Gateway caches the IAM policy an authorizer returns, keyed on its identity sources. A TOKEN authorizer's only identity source is the `Authorization` header, so the cache key is the token. If that authorizer returns a wildcard resource — `arn:aws:execute-api:*:*:*/*/*/*`, which most published examples do — the first request from a token holding only `llm/retrieve` caches a policy granting every method on the API. Every subsequent request from that token is authorized against the cached wildcard, and the scope check silently stops applying.

Two resolutions, applied together:

1. **Compose the cache key per method.** The REQUEST authorizer declares identity sources of `method.request.header.Authorization`, `context.httpMethod`, and `context.resourcePath`. The cached policy is then scoped to the method it was evaluated for. A missing identity source produces a 401 without invoking the authorizer, which is desirable.
2. **Never return a wildcard resource.** Enumerate exactly the method ARNs the token's scopes permit. A policy that is correct when computed remains correct when cached.

Cache TTL is set below the token lifetime and sized against revocation tolerance (§17.8).

**Key resolution.** The JWKS is fetched from the pinned issuer URL — never from the `iss` value inside the presented token, which is attacker-controlled and is the standard route to signature forgery. Keys are cached with `kid` rotation handling. Only RS256 is accepted; `alg: none` and all HMAC algorithms are rejected. A maintained library (`aws-jwt-verify`) is used rather than hand-rolled verification, because this is the layer where custom code fails silently rather than loudly.

**Context propagation.** The authorizer emits `sub`, `client_id`, granted scopes, and the tenant identifier into the request context. The integration consumes these from `$context.authorizer.*`, which API Gateway populates and a client cannot influence. The adapter re-checks the scope required for the operation it is about to perform — the authorizer establishes who is calling, the adapter establishes that this caller may perform this action on this resource. Client-supplied headers whose names collide with authorizer context keys are stripped at the integration.

### 4.6 Caller identity for rate limiting and attribution

On a `client_credentials` token, `sub` is the app client ID rather than a user. Aggregating rate limits or cost attribution on `sub` therefore collapses every end user behind a given machine caller into a single bucket: one noisy tenant throttles all of them, and per-identity attribution in the ledger degrades to per-server.

Where the machine caller is multi-tenant, a delegated tenant identity is required:

- A **pre-token-generation Lambda trigger** (event version 3 or later) injects a tenant claim into the access token. Client metadata supplied at the token endpoint is passed to the trigger on `client_credentials` requests, which is what makes the tenant determinable at issuance rather than at use.
- The authorizer validates the claim against a known tenant set and promotes it into the request context.
- The WAF rate-based rule and the token budget in §11 key on that claim, not on `sub`.

Single-tenant machine callers may key on `client_id` directly. What is not acceptable is keying on `sub` and assuming it denotes a user.

---

## 5. Network architecture

### 5.1 Subnet model

| Tier | Route table | Contents |
|---|---|---|
| **Isolated — data** | Local + gateway endpoints only | Aurora PostgreSQL Serverless v2 (pgvector, adversarial fingerprints, 5432/tcp) behind RDS Proxy; DynamoDB via gateway endpoint |
| **Isolated — compute** | Local + gateway endpoints only. **No `0.0.0.0/0`** | Express Adapter Lambda (`SafeguardExecRole`), secrets rotation function, VPC Link ENIs, all interface endpoint ENIs |
| **Private — egress proxy** | `0.0.0.0/0` → Network Firewall endpoint | Egress proxy Lambda only |
| **Public** | `0.0.0.0/0` → IGW | Network Firewall endpoints, NAT Gateway (1 per AZ) |

The adapter cannot reach the internet under any security-group misconfiguration, because it has no route. Third-party inference is an explicit function-to-function hop with its own identity, its own logging, and its own guardrail evaluation — the blast radius of a compromised adapter does not include arbitrary egress.

### 5.2 Endpoints

- **Gateway (no charge):** S3, DynamoDB — attached to all isolated route tables.
- **Interface:** `bedrock-runtime`, `bedrock`, `bedrock-agent-runtime`, `secretsmanager`, `kms`, `sts`, `logs`, `monitoring`, `xray`, `rds`, `ssm`, `backup`.

Private DNS enabled on all interface endpoints. Security groups permit 443/tcp inbound from the adapter security group only.

**Endpoint policies are restrictive by default.** Each names the permitted principal ARNs, the permitted actions, and — for `bedrock-runtime` — the approved inference profile ARNs. This is a resource-policy evaluation independent of the identity policy, so a compromised role still fails at the network boundary if it names an unapproved profile.

Keeping service traffic on endpoints also makes `aws:SourceVpce` available as a condition key, which is what turns the network path from a convention into a term of authorization (§8).

### 5.3 Egress

Network Firewall retains the FQDN allow-list, TLS SNI inspection, and single-entry pattern, but carries only the narrow third-party inference path plus package-registry access during build — all AWS service traffic bypasses it via PrivateLink. Stateful rule groups log alerts and flows to the Log Archive account.

---

## 6. Inference layer

### 6.1 Model access

| Path | Endpoint | Notes |
|---|---|---|
| Responder | `bedrock-runtime` via interface endpoint | `InvokeModel` / `Converse` against an **application inference profile ARN**, not a raw model ID. Cross-region inference profile for capacity, constrained to the approved region set |
| OpenAI-compatible workloads | `bedrock-mantle` | Keeps OpenAI-API-shaped traffic inside the AWS boundary. Structured outputs (`output_config.format`) are unsupported on this endpoint — verify any response-contract dependency before adopting. Cost attribution on mantle uses Projects rather than application inference profiles |
| Residual external / on-prem inference | Egress proxy Lambda → Network Firewall → NAT | Retained only where no in-boundary equivalent exists. Payload passes `bedrock:ApplyGuardrail` and deterministic redaction before egress; a hash of the transmitted payload is ledgered |
| Retrieval | `bedrock-agent-runtime` via interface endpoint | `Retrieve` against a specific knowledge-base ARN |

### 6.2 Guardrail enforcement

A guardrail is attached per invocation via `guardrailIdentifier`. Enforcement is layered so that no single misconfiguration permits an unguarded call:

1. **Identity policy** — `SafeguardExecRole` allows `bedrock:InvokeModel` and `InvokeModelWithResponseStream` only under `StringEquals: {"bedrock:GuardrailIdentifier": "<arn>:<version>"}`, paired with an explicit `Deny` under `StringNotEquals` so no other attached policy can widen it.
2. **SCP** — a `Null` check denies any invocation in the workload OU that omits the parameter entirely.
3. **Endpoint policy** — restricts principal and inference profile ARN independently of both.

Configured guardrail policies: content filters, denied topics, word filters, contextual grounding checks, sensitive-information filters with PII redaction on input and output, and automated reasoning checks where a policy is defined.

**Interaction with higher-level APIs.** A role hard-bound to a guardrail identifier is denied on calls that issue implicit model invocations — `RetrieveAndGenerate` and `InvokeAgent` — because those inner calls do not carry the required parameter. This design therefore uses `Retrieve`, which performs retrieval only, and executes generation as an explicit, guardrail-carrying `InvokeModel` call from the adapter. The role separation in §7.1 is what makes this workable; guardrail enforcement and agent-style roles must be designed together rather than layered onto each other.

### 6.3 Retrieval

S3 Vectors index with a per-index customer-managed key, and a separate data-source bucket under its own CMK. Both bucket policies carry `aws:SourceVpce` and `aws:PrincipalOrgID`. Knowledge base configuration and re-sync behavior on source deletion are covered in §12.

---

## 7. Identity model

### 7.1 Runtime roles

| Role | Trust | Permissions | Conditions |
|---|---|---|---|
| `SafeguardExecRole` | Lambda service, this function ARN | `bedrock:InvokeModel`, `InvokeModelWithResponseStream`, `ApplyGuardrail`, `dynamodb:GetItem`/`PutItem`/`Query`/`TransactWriteItems`, `secretsmanager:GetSecretValue`, `rds-db:connect`, `s3:PutObject`, `sts:AssumeRole` on `KBRetrieveRole` | `bedrock:GuardrailIdentifier` pinned; `bedrock:InferenceProfileArn` restricted to tagged profiles; `aws:SourceVpce` on all data calls; `dynamodb:LeadingKeys` scoped to the tenant partition; `s3:x-amz-server-side-encryption` = `aws:kms` with the key ID pinned; resource ARNs enumerated, no wildcards |
| `KBRetrieveRole` | `SafeguardExecRole` only, with `sts:ExternalId` and session tags | `bedrock:Retrieve` on one knowledge-base ARN | `aws:SourceVpce`. Deliberately excludes `RetrieveAndGenerate` |
| `KnowledgeBaseServiceRole` | `bedrock.amazonaws.com` | `s3:GetObject`/`ListBucket` on the data source, `s3vectors` query and write on the index, `bedrock:InvokeModel` on the embedding model, `kms:Decrypt`/`GenerateDataKey` on both CMKs | `aws:SourceAccount` and `aws:SourceArn` in the trust policy against confused-deputy |
| `EgressProxyRole` | Lambda service, proxy function ARN | `bedrock:ApplyGuardrail`, `secretsmanager:GetSecretValue` for the third-party key, `dynamodb:PutItem` on the ledger | Holds no inference permissions — it can guard a model call, not make one |
| `SecretsRotationRole` | Lambda service | Secrets Manager rotation actions, `rds:ModifyDBInstance` scope, `cloudfront:UpdateDistribution` and `wafv2:UpdateWebACL` for origin-verify rotation | Scoped to two secrets, one distribution, one web ACL |
| `LifecycleRole` | EventBridge Scheduler → Lambda | Aurora partition drop, DynamoDB Streams consumption for erasure receipts | Cannot read item content; operates on keys and partition names only |
| `SecReadOnlyRole` | Security account principals | `SecurityAudit` + `ViewOnlyAccess` | MFA required; `aws:PrincipalOrgID` |
| `SecResponderRole` | Security account automation | Containment only: revoke sessions, disable keys, set reserved concurrency to zero, quarantine security groups | Time-limited session; cannot modify audit, backup, or KMS resources |
| `DataScienceRole` | ML account human principals | SageMaker Studio, Bedrock dev models, MWAA | Permissions boundary capping to the ML account; SCP denies cross-account reach into Workload |

**Role chaining.** Every `AssumeRole` trust policy names the source role ARN explicitly, never the account root. Session tags carry the request correlation ID, so the CloudTrail chain from inbound API request through retrieval is reconstructible.

The `SafeguardExecRole` → `KBRetrieveRole` hop is a deliberate privilege boundary. A compromised adapter cannot query the vector store without performing a role assumption, and role assumption is a distinct, heavily auditable CloudTrail event rather than another indistinguishable data-plane call.

**Roles deliberately chosen over the broader alternative.** `SecReadOnlyRole` uses `SecurityAudit` + `ViewOnlyAccess` rather than `ReadOnlyAccess`, because the latter grants object and item reads — a security auditor needs to evaluate configuration, not read customer data.

### 7.2 Delivery roles

These hold the ability to mutate production infrastructure and are specified with the same rigor as runtime roles.

| Role | Account | Trust | Permissions | Boundary |
|---|---|---|---|---|
| `GitHubOIDCRole` | Shared Services | `sts:AssumeRoleWithWebIdentity` from `token.actions.githubusercontent.com`, conditioned on `aud` = `sts.amazonaws.com` **and** `sub` = `repo:<org>/<repo>:environment:prod` | Start a pipeline execution, write build artifacts | `PipelineBoundary` |
| `PipelineExecRole` | Shared Services | CodePipeline / CodeBuild service | Artifact bucket read/write, `kms` on the artifact key, `sts:AssumeRole` on `CfnDeploymentRole` in each target account | `PipelineBoundary` |
| `CfnDeploymentRole` | Each target account | `PipelineExecRole` only, with `sts:ExternalId` | `cloudformation:CreateStack`/`UpdateStack`/`DescribeStacks`/`CreateChangeSet`/`ExecuteChangeSet`, plus `iam:PassRole` on `CfnServiceRole` only | `DeploymentBoundary` |
| `CfnServiceRole` | Each target account | `cloudformation.amazonaws.com` only | The actual mutation permissions, scoped by resource type and required tag | `DeploymentBoundary` |

**Why three roles rather than one.** `CfnDeploymentRole` can start a stack operation but holds no service permissions of its own. `CfnServiceRole` holds the permissions but can only be exercised by CloudFormation, and only because `CfnDeploymentRole` is permitted to pass it. `iam:PassRole` is conditioned on `iam:PassedToService` = `cloudformation.amazonaws.com`. A compromise of the pipeline yields the ability to deploy a reviewed template, not the ability to call arbitrary APIs.

**No long-lived keys.** The build system authenticates by OIDC federation. The trust policy pins the `sub` claim to a specific repository **and environment**. A wildcard such as `repo:<org>/*` would allow any branch — and any fork opening a pull request — to assume the production role; this is the most common failure in OIDC pipeline configurations and warrants explicit review.

**Permissions boundaries.** `DeploymentBoundary` denies: detaching itself, creating roles without it attached, `iam:CreateUser` and access-key creation, any action on `cmk/audit` or `cmk/backup`, any action on the audit bucket or backup vault, any `organizations:*`, and deletion of the Bedrock guardrail. An SCP denies `iam:CreateRole` and `iam:PutRolePolicy` unless `iam:PermissionsBoundary` matches the boundary ARN, so the pipeline cannot mint a role more privileged than itself.

**Traceability.** Pipeline sessions are tagged with the commit SHA, so every infrastructure mutation in CloudTrail resolves to a commit. Production deployment is gated on a manual approval whose identity must differ from the commit author.

---

## 8. Data perimeter

Three conditions are applied consistently across resource policies, endpoint policies, and SCPs:

- `aws:PrincipalOrgID` — only identities in this organization.
- `aws:SourceVpce` — only through the designated endpoints.
- `aws:ResourceOrgID` — workload principals cannot reach resources outside the organization.

Trusted identity, trusted resource, expected network. A leaked credential used from outside the VPC fails the network condition. A role induced to write to an attacker-controlled bucket fails the resource condition.

---

## 9. Cryptography

| Key | Scope | Location |
|---|---|---|
| `cmk/app-data` | Application S3, DynamoDB | Workload |
| `cmk/secrets` | Secrets Manager | Workload |
| `cmk/rds` | Aurora storage, proxy secrets | Workload |
| `cmk/vector` | S3 Vectors index, KB data source | Workload |
| `cmk/logs` | CloudWatch log groups, Firehose | Workload |
| `cmk/audit` | Org Trail bucket, model invocation logs | **Log Archive** — workload principals excluded from the key policy |
| `cmk/backup` | Central backup vault, cross-region snapshot copies | **Backup** — workload and deployment principals excluded |
| `cmk/pipeline` | Artifact bucket | Shared Services |

Keys are separated by data class rather than by account convenience, so that a key-policy error is contained to one class of data. Annual rotation on all keys. Key policies enumerate principals; no `kms:*` granted to `Principal: "*"`.

In transit: TLS 1.2+ at every boundary; 5432/tcp inside the VPC is TLS-enforced to the proxy.

---

## 10. Logging, audit, and observability

| Stream | Destination | Controls |
|---|---|---|
| CloudTrail Org Trail | Log Archive bucket | Management events plus data events for S3 object-level operations on vector and app buckets and Lambda `Invoke`. Object Lock compliance mode, versioning, MFA delete on the bucket configuration |
| Model invocation logging | Log Archive bucket + CloudWatch | Prompt and completion bodies. CloudTrail records that a call occurred, never its content — these are different systems recording different things, and both are required. Encrypted under `cmk/audit`, access restricted to a named investigation role, retention set to the shortest defensible period |
| Guardrail intervention events | CloudWatch → Security Hub custom finding | Blocked prompts and redactions become detections, not merely log lines |
| WAF (both scopes), Network Firewall, VPC Flow Logs, Resolver query logs | Firehose → Log Archive | Encrypted, partitioned for Athena |
| API Gateway access logs | Encrypted CloudWatch log group | JSON, `X-Request-ID`, authorizer `sub`, `client_id`, and tenant claim |
| Application telemetry | ADOT → OTLP → CloudWatch / X-Ray via interface endpoints | **Prompt hashes only, never content.** Spans carry the correlation ID, inference profile ARN, guardrail verdict, latency, and token counts |

Retention: 90 days hot in CloudWatch; lifecycle transition to Glacier Flexible Retrieval at 90 days in S3; retention floor set by the compliance requirement and enforced by Object Lock.

---

## 11. Cost governance and abuse control

Metered inference fails open on cost. An attacker who cannot exfiltrate data can still consume budget, and at the billing layer a prompt-flood is indistinguishable from success. Cost controls are treated here as security controls.

### 11.1 Tagging

Required tags on every resource: `costCenter`, `environment`, `applicationId`, `dataClassification`, `owner`.

Enforcement is by **SCP**, not tag policies. Organizations tag policies govern tag format and case on supported services; they do not prevent an untagged resource from being created. The SCP denies create actions where `aws:RequestTag/costCenter` is null or `aws:TagKeys` omits a required key. `dataClassification` additionally drives the discovery scanning scope in §14.

### 11.2 Inference cost attribution

Model invocation cost does not inherit tags from the calling resource. Tagging the function, the API, or the agent does nothing for the line item that dominates the bill.

- **Application inference profiles** wrap a specific model and carry cost allocation tags. The adapter calls the profile ARN in place of the model ID, and the profile's tags land on the billing record. One profile per tenant or per use case — reusing a single profile discards the granularity it exists to provide.
- **An SCP requires `bedrock:InferenceProfileArn` to be present**, closing the bypass in which a direct foundation-model call escapes attribution. Denying foundation-model ARNs outright is not a workable alternative: inference profiles invoke the underlying foundation model, so a direct-ARN deny breaks them along with the bypass.
- **`bedrock-mantle` traffic uses Projects** — the inference-profile mechanism covers `InvokeModel` and `Converse` on `bedrock-runtime`. Where both endpoints are live, both attribution mechanisms must be configured or half the spend is invisible.
- Tags must be activated in Billing before they appear, are not retroactive, and take up to 24 hours to propagate. Activate at account bootstrap, not at incident time.
- Granularity ceiling: profiles report per usage type per day, not per request. Per-prompt token detail comes from per-request metadata tagging in the model invocation logs.

### 11.3 Three-tier circuit breaker

Detection latency differs by an order of magnitude at each tier, which is why all three exist.

| Tier | Mechanism | Latency | Action |
|---|---|---|---|
| 1 — Application | Token budget per caller identity (§4.6) in a DynamoDB counter, checked before invocation | Immediate | Reject with 429; Security Hub finding on repeated breach |
| 2 — Infrastructure | CloudWatch alarms on `InputTokenCount`, `OutputTokenCount`, `Invocations`, `InvocationThrottles`, with anomaly-detection bands | Minutes | Page on-call; optionally floor adapter reserved concurrency |
| 3 — Billing | AWS Budgets on the cost allocation tags, tiered at 50 / 80 / 100 percent of forecast, with **Budget Actions** attaching a deny policy at the ceiling | Hours to a day | Automatic restriction of non-critical tenants' invoke permission |

Tier 3 alone is inadequate — Cost Explorer updates daily, so a runaway loop can consume a month of budget before Budgets reacts. Tier 2 is the operational control; tier 3 is the backstop for when tier 2's alarm was misconfigured.

No provisioned throughput is purchased, so spend scales directly with request volume. The WAF rate rule and the tier-1 token budget are therefore the primary defenses, not the billing alarms.

### 11.4 Anomaly detection as a security signal

Cost Anomaly Detection runs two monitors: one on the Bedrock service, one on the cost-allocation-tag dimension. **Alerts route to the same EventBridge bus as GuardDuty findings.** An unexplained inference cost spike is a security indicator — credential abuse, an authorization bypass, a jailbreak used for free compute, or a retrieval loop — and routing it only to finance discards the fastest available signal for several of those.

---

## 12. Application data lifecycle

Prompt and response history in a hot datastore is the same content as the model invocation logs, held longer, in a system designed for access rather than archive. It receives an explicit lifecycle.

### 12.1 Classification and retention

| Data | Store | Retention | Mechanism |
|---|---|---|---|
| Raw prompt / response content | DynamoDB ledger | 30 days | TTL |
| Hashes, verdicts, guardrail outcomes, token counts | DynamoDB ledger | 400 days | TTL on a separate attribute |
| Audit-relevant ledger entries | Exported to Log Archive before TTL fires | Compliance floor | Scheduled export, then TTL |
| Adversarial fingerprints and embeddings | Aurora pgvector | Rolling 12 months | Partition drop |
| Source documents | S3 (KB data source) | Business-defined | S3 lifecycle |
| Derived embeddings | S3 Vectors index | Bound to source | KB re-sync on source deletion |

### 12.2 DynamoDB TTL

TTL uses an epoch-seconds attribute per item. Two properties govern how it can honestly be described:

- **Deletion is asynchronous.** Items typically clear within 48 hours of expiry, not at expiry, and remain readable and queryable in the interim. The adapter filters expired items at read time so application behavior matches policy even when the deletion has not landed. TTL is a cost and hygiene mechanism; it is not a compliance-grade deletion guarantee and should not be presented as one.
- **Deletions surface in Streams.** A consumer function writes an erasure receipt to the Log Archive, producing a provable record of what was deleted and when — which TTL alone does not.

### 12.3 Aurora pgvector

PostgreSQL has no native TTL. Fingerprint tables use declarative partitioning by ingest month, with partitions dropped on schedule by `pg_cron` or an EventBridge-triggered function holding `LifecycleRole`. A partition drop is instantaneous and reclaims storage; a bulk `DELETE` on a vector table leaves index bloat and forces a `VACUUM` window that a serverless configuration absorbs poorly.

### 12.4 Subject erasure

TTL and partition drops are time-based and cannot satisfy a right-to-erasure request, which is subject-based.

- Maintain a subject index mapping the caller identity to ledger partition keys and Aurora row identifiers. Without it, erasure requires a full scan of both stores.
- Deleting a source document must trigger a knowledge base re-sync. An embedding derived from personal data is personal data; deleting the S3 object without re-syncing leaves the vector — and frequently enough of the source text in the retrievable chunk — in place.
- **Backups are the erasure ceiling.** Recovery points cannot be selectively edited, and Vault Lock compliance mode makes them undeletable by design. Erasure from backups occurs by expiry, not by surgery. The defensible position is to set backup retention deliberately, document it, and state that window in the privacy notice — not to claim an erasure capability the storage layer does not provide.

---

## 13. Backup and recovery

### 13.1 Configuration

| Store | Continuous | Scheduled | Cross-region |
|---|---|---|---|
| DynamoDB ledger | PITR — restore to any second within 35 days | AWS Backup: daily 35 days, monthly 12 months | Recovery points copied to the DR region under `cmk/backup` |
| Aurora PostgreSQL Serverless v2 | Automated backups, 35-day retention, PITR within that window | AWS Backup on cluster snapshots, monthly 12 months | Encrypted snapshot copies to the DR region |
| S3 (app, vector, KB source) | Versioning and replication | Lifecycle to Glacier | Cross-region replication with its own CMK |

Two operational facts shape the runbooks. **Aurora Backtrack is MySQL-only and unavailable for PostgreSQL**, so PITR is the only rewind and it produces a *new* cluster — recovery includes the endpoint swap and the RDS Proxy target-group update. DynamoDB PITR likewise restores to a new table, so the runbook covers the alias or table-name cutover rather than only the restore call.

### 13.2 Custody

Recovery points are copied to the central vault in the **Backup account**. Cross-account copy is the control that matters: a full compromise of the Workload account cannot destroy recovery points that are not there.

**Backup Vault Lock in compliance mode** applies WORM semantics to recovery points — the direct analogue of Object Lock on the audit bucket. It carries a cooling-off period before becoming immutable, and once immutable it cannot be reverted by anyone, including the root user or AWS Support.

SCPs deny `backup:DeleteRecoveryPoint`, `backup:DeleteBackupVault`, `backup:PutBackupVaultLockConfiguration`, `dynamodb:DeleteTable`, `dynamodb:UpdateContinuousBackups`, and `rds:DeleteDBCluster` in the workload OU outside the documented break-glass path.

### 13.3 Restore testing

Quarterly restore exercise: recover both datastores into an isolated test account, run the application's integrity checks against the restored data, and record the measured RTO against the stated objective. An untested backup is an assumption. The measured number, not the configured retention, is what belongs in the recovery statement — and producing it is what surfaces the endpoint-swap and proxy-retarget steps that are otherwise discovered during the first real incident.

---

## 14. Sensitive data discovery

Macie scans S3 and only S3. The ledger and the vector store are outside its reach, and both can accumulate PII if the preventive control fails.

### 14.1 Prevention first

The primary control is the guardrail sensitive-information filter, which redacts PII on the way in; the adapter persists redacted content and hashes. Everything below is a backstop that detects failure of that control. The sequencing matters: a discovery pipeline that finds PII in the ledger has found a guardrail failure, and that is the finding worth paging on.

### 14.2 Detection

| Store | Mechanism |
|---|---|
| DynamoDB ledger | Scheduled point-in-time **export to S3** into a short-lived scanning bucket in the Security account. Export consumes no read capacity and does not touch the production table. Macie automated sensitive data discovery runs against the export; findings route to Security Hub; the export is deleted on completion. Sampling by default, full scan on schema change |
| Aurora pgvector | `rds:StartExportTask` writes a snapshot to S3 in Parquet; Macie scans the export; same teardown |
| Continuous inline option | AWS Glue sensitive data detection within an ETL job, where the export cadence is too slow |
| Scanning bucket | Security account, own CMK, lifecycle expiry at 24 hours, bucket policy denying every principal except the scanning role |

The scanning bucket is itself a concentration of the sensitive data the rest of the architecture works to disperse, and is the most attractive object this design creates. A short lifespan and a single-principal policy are what prevent it from becoming the easiest target in the environment.

### 14.3 Control-effectiveness testing

Discovery answers whether PII is present. It does not answer whether redaction works. Synthetic PII markers — structurally valid, uniquely identifiable, never real — are injected through the adapter on a schedule, and their absence asserted in the ledger, the vector store, and the telemetry spans. A canary surfacing downstream is a guardrail regression caught before a real record follows the same path.

---

## 15. Organizational guardrails

Service Control Policies attached at the workload OU:

1. Deny disabling or modifying CloudTrail, GuardDuty, Config, Security Hub, Inspector, Macie.
2. Deny deletion of the audit bucket, its Object Lock configuration, the backup vault, the vault lock, `cmk/audit`, and `cmk/backup`.
3. Deny `bedrock:InvokeModel` / `InvokeModelWithResponseStream` where `bedrock:GuardrailIdentifier` is null.
4. Deny Bedrock invocation where `bedrock:InferenceProfileArn` is null, forcing all inference through tagged application inference profiles.
5. Deny operations outside approved regions — reconciled against cross-region inference profiles, whose backing regions must appear in the approved set or inference fails at runtime.
6. Deny resource creation where required cost allocation tags are absent.
7. Deny creation of S3 buckets or DynamoDB tables without SSE-KMS.
8. Deny disabling PITR or continuous backups.
9. Deny creation of internet gateways, NAT gateways, or `0.0.0.0/0` routes outside designated public subnets.
10. Deny modification of VPC endpoint policies except by `CfnServiceRole`.
11. Deny `iam:CreateRole` / `iam:PutRolePolicy` without the required permissions boundary.
12. Deny root-user actions except the documented break-glass path.

Each SCP is capped at 5,120 characters, so this set does not fit in a single policy. Split by domain — detective-control protection, inference governance, data protection, identity — rather than by remaining space, so the reason a given deny exists stays legible during an incident.

---

## 16. Detection and response

Detective composition: GuardDuty (with Lambda protection and Malware Protection for S3), Config with conformance packs, Macie on S3 and the scanning exports, Inspector for function code and dependencies, Security Hub as aggregator with delegated admin in the Security account.

Response is closed-loop through EventBridge into SSM Automation documents and Lambda runbooks:

| Trigger | Automated action |
|---|---|
| GuardDuty credential exfiltration or anomalous IAM behavior | Revoke sessions on the affected role, disable the access key, notify |
| Repeated guardrail interventions from one caller identity | Add the identity to a WAF blocked-identity set, raise a Security Hub finding |
| Cost anomaly on the Bedrock monitor | Treat as a security event: correlate against per-identity token counts, page on-call, apply the tier-1 budget restriction to the top consumer |
| Macie finding in a ledger or Aurora export | Page — this indicates redaction failed, not merely that data was found |
| Synthetic PII canary detected downstream | Immediate page; block promotion in the pipeline |
| Config non-compliance: guardrail-less invocation possible | Attach a deny policy to the offending role, page |
| Secrets rotation failure | Alarm within one rotation interval, before the overlap window expires |
| Object Lock, vault lock, or audit-bucket policy change attempt | Immediate page — impossible under the SCPs, so an event here is either a control failure or an insider action |

Every runbook writes its own audit record and cannot modify audit, backup, or KMS resources.

---

## 17. Delivery pipeline

CloudFormation deploys from Shared Services through the role chain in §7.2. The Workload account has no interactive infrastructure-mutation identity.

- Template scanning with `cfn-guard` rules encoding the SCP set — so a template that would be denied at deploy time fails at build time instead — plus `checkov`, blocking on high severity.
- Tag validation in the pipeline, rejecting templates that omit required cost allocation tags, since the SCP would otherwise fail the deployment mid-stack and leave a partial rollback.
- Stack policies protecting the audit bucket, backup vault, KMS keys, and endpoint resources from replacement.
- Scheduled drift detection; drift raises a Security Hub finding.
- Inspector scans code and dependencies before artifact promotion.
- Guardrail configuration, IAM policies, authorizer code, and lifecycle rules are version-controlled and reviewed as security-relevant code.
- Manual approval gate on production, with an approver identity distinct from the commit author.

---

## 18. Constraints and residual risks

Every control described above can be correctly implemented and the following still hold. They are stated rather than resolved.

1. **Guardrail input tagging.** Input tags let a caller mark which prompt sections are evaluated, so a compromised adapter could leave content untagged. Model responses are evaluated unconditionally, bounding exposure to input-side evasion. The adapter's tagging logic is treated as security-relevant code, and the intervention rate is monitored for anomalous drops.
2. **TLS SNI is metadata.** The firewall sees destination, not payload, on the residual external path. `ApplyGuardrail` and redaction run before egress and payload hashes are ledgered, but the network layer contributes no payload visibility.
3. **Third-party retention.** Once a payload reaches an external model, that provider's logging and retention govern it. Contractual control only; no technical enforcement exists. This is the strongest argument for collapsing remaining traffic onto in-boundary endpoints.
4. **Object Lock and Vault Lock compliance mode are irreversible.** A retention period set too long cannot be corrected and accrues cost for its full duration.
5. **Backups cap erasure.** Subject erasure cannot reach immutable recovery points. The retention window is the honest limit and should be stated as such.
6. **TTL is not deletion at expiry.** Up to a 48-hour lag, mitigated by read-time filtering rather than eliminated.
7. **Discovery scans exports, not live stores.** Findings lag by the export cadence. Prevention, not detection, is the operative control.
8. **Token revocation lags the authorizer cache.** Cognito's `RevokeToken` invalidates access and ID tokens sharing an `origin_jti`, but a cached authorizer decision has no visibility into that. A revoked token remains accepted for up to the cache TTL. Containment invalidates at the WAF layer instead, which is not cached.
9. **Cross-region inference moves payloads across regions.** Data residency requirements must be reconciled against the approved region set and against the region-deny SCP before enabling.
10. **S3 Vectors latency.** Sub-second cold, roughly 100 ms warm. OpenSearch tiering is the escape hatch if requirements tighten, at higher cost.
11. **Single region.** Two Availability Zones provide infrastructure resilience, not regional disaster recovery. Recovery points are copied cross-region, so a regional event is slow rather than unrecoverable, but RTO and RPO objectives and the warm-standby decision remain open.
12. **Cost attribution has a floor.** Inference profiles resolve to per usage type per day. Per-request attribution requires correlating model invocation logs, which contain user content and therefore live under `cmk/audit` with restricted access.

---

## 19. Summary

Four properties characterize this design.

**Network isolation is structural.** The adapter has no route to the internet. Every AWS service call resolves to an endpoint interface inside the VPC, and `aws:SourceVpce` makes that path a condition of authorization rather than a matter of configuration convention.

**Guardrails are non-optional.** Identity policy, Service Control Policy, and endpoint policy must all be misconfigured before a model can be invoked unguarded. The role separation that makes this work also resolves the interaction with retrieval-and-generate APIs, which is the failure mode most guardrail-enforcement designs encounter after deployment rather than before.

**The audit trail sits outside the blast radius.** No principal in the Workload account can reach the audit bucket, the backup vault, or their keys. Model invocation logging closes the content gap that CloudTrail structurally cannot cover, and recovery points live in a third account so that neither record nor remedy shares a fate.

**Identity is scoped on three axes at once.** A leaked credential is insufficient on its own; it must also be presented from the expected endpoint, against an enumerated resource, within the organization. At the API tier, the claim actually validated is matched to the token type actually issued — the distinction between an ID token's `aud` and an access token's `client_id` is where token validation most often appears correct and is not.

Two things in this specification will be discovered rather than designed. The first is the measured recovery time, which only a real restore produces. The second is the set of prompts that pass the guardrail and should not — which only production traffic produces, and which is why guardrail intervention is monitored as a trend rather than checked as a configuration.
