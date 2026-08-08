# Security Cheat Sheet — Secure GenAI Workload on AWS

*Briefing reference. Organized by service, in request-path order.*

---

## Route 53

- DNSSEC signing on the hosted zone — prevents response forgery
- Alias records to CloudFront (no CNAME resolution overhead)
- **Resolver DNS Firewall** on outbound VPC resolution, allow-list aligned to the Network Firewall FQDN list
- *Talking point:* DNS is a control surface in both directions — inbound integrity and outbound exfiltration

---

## CloudFront — two distributions

**Why two:** the SPA and the API have opposite traffic shapes. One distribution risks a cache-behavior ordering mistake caching an API response and serving it to the next caller — cross-tenant disclosure with no attacker involved.

### Both distributions
- TLS 1.2+ minimum, enforced at the handshake *before* WAF evaluates
- ACM certificate, `sni-only`
- HTTP/2 and HTTP/3

### API distribution
- **Zero-TTL cache policy** — nothing on `/v1/*` is ever cached
- **Origin request policy** — explicit allow-list of forwarded headers (`Authorization`, `Content-Type`, `X-Request-ID`, `Origin`). Anything unnamed never reaches the adapter, turning header smuggling into defeating a whitelist rather than a blacklist
- **`x-origin-verify` injection** from Secrets Manager, rotated with dual-value overlap
- CSP `default-src 'none'`, HSTS preload, `X-Content-Type-Options`, `Referrer-Policy`

### SPA distribution
- **Origin Access Control** — SigV4-signed origin requests as the `cloudfront.amazonaws.com` service principal
- Bucket policy conditioned on `AWS:SourceArn` = this distribution. *Without it, any distribution in any account pointed at the origin can read it*
- 403 and 404 mapped to `/index.html` for client-side routing
- Application CSP with `connect-src` naming the API origin

---

## AWS WAF — three WebACLs

| WebACL | Scope | Attached to |
|---|---|---|
| SPA edge | CLOUDFRONT (us-east-1) | SPA distribution |
| API edge | CLOUDFRONT (us-east-1) | API distribution |
| API regional | REGIONAL | API Gateway stage |

**Three rules invert between the two edge WebACLs — this is the briefing's best example of "one size does not fit two workloads":**

| Rule | SPA | API | Why |
|---|---|---|---|
| Bot Control | **On** | **Off** | MCP machine callers are non-browser *by design* |
| Anonymous IP | **Block** | **Count** | MCP servers run in datacenters |
| Rate limit | IP-keyed, 5000/5min | Token-keyed, 500/5min | Browser requests carry no `Authorization` header to aggregate on |

### Regional WAF (API only)
- `x-origin-verify` exact match at **priority 0** — rejects direct-to-API-Gateway before consuming managed rule capacity
- **Rate limit keyed on the token, not source IP.** IP aggregation buckets every caller behind a corporate NAT or a single MCP server together
- Blocked-identity IP set, populated by the containment runbook
- `SizeRestrictions_BODY` overridden to Allow — prompts routinely exceed the default
- **Logs redact `authorization` and `x-origin-verify`.** Without redaction the bearer token is written in full on every blocked request, into an immutable bucket where it cannot be removed

*Deliberately absent:* SQLi and Linux rule sets. No SQL concatenation, no shell exec, and both fire on prose containing SQL keywords — which prompts do.

---

## AWS Shield

- Standard is automatic and covers every resource, including regional
- **Advanced can only protect the CloudFront distribution and Route 53** — API Gateway is not a supported resource type
- L3/L4 volumetric mitigation happens inline at the edge, before traffic heads toward a region

---

## API Gateway

- **REST, not HTTP API — deliberate.** WAF association and resource policies are REST-only, and both are load-bearing here
- **Resource policy** denies any `aws:SourceArn` other than the CloudFront distribution. The header is the fast check; this is what holds if the header leaks
- Request validator: JSON schema with `additionalProperties: false`, required `X-Request-ID`
- Stage throttle as an aggregate capacity limit (*not* an abuse control — it can't distinguish callers)
- Access logs capture authorizer context, not request headers
- `DataTraceEnabled: false` — request/response bodies carry prompt content
- **29-second integration ceiling** governs the whole timeout chain

---

## Amazon Cognito

- **Two app clients, one pool.** Human: authorization code + PKCE (S256 only). Machine: `client_credentials` against a resource server
- **PKCE is not for machines.** Reusing a human flow for service callers produces an identity indistinguishable from a user in the audit trail
- **RFC 8707 resource binding on the human path** — token carries a real `aud`, so a token minted for another API fails here
- **The machine path cannot have `aud`.** Cognito does not permit a resource indicator on `client_credentials`. Binding is `client_id`, and the two paths carry genuinely different validation rules
- `ALLOW_USER_PASSWORD_AUTH` omitted — sends the password to the API and defeats SRP
- Refresh token rotation — a stolen refresh token is detectable, because the legitimate client's next refresh fails
- **Pre-token-generation trigger (V3_0)** derives the tenant claim server-side from an entitlement table and *ignores* client-supplied metadata

> **The single best slide.** Cognito passes client metadata straight through to that trigger. A tenant read from it is a value the *caller* chose. Deriving it makes the claim a fact; reading it makes it an assertion — and an assertion validated only for membership in a known tenant set is the confused-deputy pattern: every credential valid, the authorization decision wrong, the audit trail faithfully recording the attacker's claim.

---

## Lambda authorizer

**Eight checks, each one denies, order is deliberate:**

1. Route in the scope map — else deny before parsing the token
2. `Bearer` prefix present
3. Signature, `iss`, `exp`, `nbf`, `token_use`, `client_id`
4. **Revocation denylist** — `JTI#` and `SUB#`, consistent read
5. **Audience** — required on human, *forbidden* on machine
6. Scope for this specific method
7. `client_id` present
8. **Tenant entitlement** — intersection of requested and provisioned

**Three things to call out:**

- **REQUEST type, per-method cache key.** A TOKEN authorizer keys only on the token; if its policy names a wildcard resource, the first request caches a policy covering every method and the scope check silently stops applying from request two onward
- **JWKS pinned to the configured issuer**, never read from the token's own `iss` — the difference between key pinning and signature forgery
- **Fails closed on revocation.** An unreachable store gives an unknown answer, and "unknown" for *is this credential revoked* is not a yes

---

## VPC — five subnet tiers per AZ

| Tier | Route table | Contents |
|---|---|---|
| Isolated — data | Local + gateway endpoints | Aurora, RDS Proxy |
| Isolated — compute | **No `0.0.0.0/0`** | Adapter, authorizer, endpoint ENIs |
| Private — egress | → Network Firewall | Egress proxy only |
| Firewall | → NAT | Network Firewall endpoints (must be dedicated) |
| Public | → IGW | NAT Gateway |

- **The absence of a default route is the control.** A security-group misconfiguration cannot create internet access the route table does not provide
- **Egress order is firewall → NAT → IGW.** Reversed, everything appears to come from the NAT address and per-source rules become meaningless

---

## VPC endpoints

- Gateway (free): S3, DynamoDB. Interface: `bedrock-runtime`, `bedrock-agent-runtime`, Secrets Manager, KMS, STS, `cognito-idp`, Logs, CloudWatch, X-Ray
- **Not for connectivity — every call would work over NAT.** They exist so `aws:SourceVpce` becomes available as a condition key
- **Endpoint policies are a second, independent authorization evaluation.** The `bedrock-runtime` policy restricts principal, inference profile ARN, *and* guardrail — so a compromised role still fails at the network boundary
- `bedrock-agent-runtime` allows `Retrieve` and not `RetrieveAndGenerate`

---

## AWS Network Firewall

- FQDN allow-list, TLS SNI inspection, single egress chokepoint
- **`aws:drop_established` under `STRICT_ORDER`.** Without strict order the default is to *pass* unmatched traffic, which inverts an allow-list into a suggestion
- Carries only third-party inference and build-time package registries — all AWS traffic bypasses it via PrivateLink
- *Honest limit:* SNI is metadata. The firewall sees destination, never payload — which is why redaction happens before this hop

---

## Amazon Bedrock

### Guardrail enforcement — three independent layers
1. **Identity policy** — Allow conditioned on `bedrock:GuardrailIdentifier`, paired with an explicit `Deny` under `StringNotEquals` so no other policy can widen it
2. **Org SCP** — `Null` check denies any invocation omitting the parameter
3. **Endpoint policy** — restricts principal and inference profile independently

- **Pinned to `identifier:version`, not a bare identifier.** A bare identifier lets a guardrail be weakened in place with no deployment and no review
- Content filters, denied topics (incl. system-prompt disclosure), contextual grounding, PII filters — **BLOCK for credentials, ANONYMIZE for names.** A redacted credential is still a credential the model was shown

### The counter-intuitive one
> Bedrock evaluates the **whole** message set only when **no** `guardContent` blocks are present. One tagged block narrows evaluation to tagged blocks alone. **Partial tagging is the hazard, not tagging.** We tag everything.

### Interaction most designs discover in production
> A role hard-bound to a guardrail identifier is **denied** on `RetrieveAndGenerate` and `InvokeAgent`, because those issue implicit model calls carrying no guardrail parameter. Our `Retrieve` + explicit `InvokeModel` split is what makes enforcement workable.

### Application inference profiles
- Adapter calls the **profile ARN**, never a raw model ID
- Two reasons, both required: SCP denies a null `bedrock:InferenceProfileArn`, and cost allocation tags only reach the billing record through a profile
- Tagging the Lambda, the API, or the agent does nothing for the line item that dominates the bill

---

## S3 Vectors + Knowledge Base

- Per-index CMK; separate data-source bucket with its own CMK
- **Tenant metadata filter derived from the authorizer context**, never from a request parameter — a client-supplied filter is a client-supplied authorization decision
- **Post-retrieval assertion on every chunk.** A metadata filter fails *silently* when ingestion omits the attribute; the assertion turns a silent isolation failure into a 500
- `AMAZON_BEDROCK_*` reserved keys declared non-filterable — omitting them fails at **sync time, not deploy time**
- `tenantId` deliberately absent from the non-filterable list, which is what keeps it filterable
- `DataDeletionPolicy: RETAIN` — an embedding derived from personal data *is* personal data

---

## Aurora PostgreSQL + RDS Proxy

- **No database password exists.** RDS Proxy `IAMAuth: REQUIRED`; the client presents a short-lived IAM token, the proxy holds the master secret for its own connection
- `rds.force_ssl: 1` at the engine — the one TLS control that cannot be bypassed from the application side
- App role has `SELECT, INSERT` only — no UPDATE, no DELETE, no DDL
- **Row-level security with `FORCE`.** Without `FORCE` the table owner bypasses the policy. A query omitting the tenant predicate returns *nothing*, not another tenant's rows
- `statement_timeout` set at the role level so a compromised client cannot raise it
- `SessionPinningFilters: EXCLUDE_VARIABLE_SETS` — without it a `SET` pins the connection and collapses the pool to one per invocation

---

## DynamoDB

| Table | Purpose | Notable |
|---|---|---|
| Ledger | Audit records | `pk = TENANT#` is what `dynamodb:LeadingKeys` binds against |
| Budget | Tier-1 cost breaker | Two counters — `TENANT#` and `CLIENT#` |
| Entitlement | `clientId → tenants` | Authorizer has `GetItem` + explicit write `Deny` |
| Revocation | `origin_jti` / `sub` denylist | Consistent reads; TTL matches token expiry |

- **Two budget counters, not one.** A caller entitled to several tenants would otherwise multiply its budget by rotating the tenant it asserts
- Atomic conditional `UpdateItem` — a read-then-write lets concurrent invocations both pass on a stale value
- Ledger records hashes and the guardrail verdict, **never content**
- TTL deletion is asynchronous (up to 48h) — the adapter filters at read time. *A hygiene mechanism, not a compliance-grade deletion guarantee*

---

## AWS Lambda

| Function | Key property |
|---|---|
| Authorizer | VPC-attached so its entitlement lookup carries `aws:SourceVpce` |
| Adapter | 28s timeout, no default route, reserved concurrency |
| **Egress proxy** | `ApplyGuardrail` and an **explicit Deny on every inference action** |
| Secrets rotation | Updates the CloudFront header and the WAF rule in one operation |
| Lifecycle | Can delete data, cannot read item content |

> **The asymmetry worth a slide.** The proxy can *guard* a model call and not make one. The adapter can make one and cannot reach the internet. Neither component alone can send an unguarded payload outside the boundary.

- The adapter reaches the proxy by **Lambda invoke, not routing** — that is what makes "cannot reach the internet" structurally true
- Egress proxy reserved concurrency is set **below the `ApplyGuardrail` throughput limit**, converting a guardrail throttle from a fail-open pressure point into a queueing delay
- No secrets in environment variables — readable by anyone with `lambda:GetFunctionConfiguration`
- Every function declares its own log group; an auto-created one has no KMS key and no retention

---

## AWS KMS — eight keys

| Key | Account |
|---|---|
| `cmk/app-data`, `cmk/secrets`, `cmk/rds`, `cmk/vector`, `cmk/logs` | Workload |
| `cmk/audit` | **Log Archive** |
| `cmk/backup` | **Backup** |
| `cmk/pipeline` | Shared Services |

- Separated by data class so a key-policy error is contained to one class
- `kms:ViaService` on service-use statements — a principal with a broad IAM policy cannot use the key outside its intended service
- **`cmk/logs` is the exception:** CloudWatch Logs calls KMS *directly*, so `ViaService` does not apply. It needs a service-principal grant with an `EncryptionContext` condition
- **`cmk/audit` denies `ScheduleKeyDeletion` to every principal.** Without that, an administrator renders every archived log unreadable without deleting a single object

---

## Logging & audit

- **CloudTrail Org Trail** with data events (S3 object-level, Lambda invoke) → Log Archive account
- **S3 Object Lock compliance mode** — cannot be shortened or overridden by anyone, including root and AWS Support
- **Bedrock model invocation logging** — prompt and completion bodies. *CloudTrail records that a call occurred, never its content.* Different systems, both required
- Invocation logs land under their own prefix, readable only by a named investigation role
- Application telemetry carries **prompt hashes only**
- Firehose delivery role holds `GenerateDataKey` **without** `Decrypt` — it writes objects it can never read back

---

## Detection & response

- GuardDuty (Lambda protection, S3 malware), Config, Macie, Inspector, Security Hub — delegated admin in the Security account
- **Alarms on latency and anomaly bands, not just errors.** The judge alarm watches p95 duration below the 25s cap: an attacker slowing the judge toward the ceiling forces 504s *without producing a single error*
- **`GuardrailInterventionDropAlarm` fires on a DROP.** Weakening a guardrail is not deleting it — it passes every policy check while all three enforcement layers keep reporting success
- **Cost anomalies route to the security topic, not finance.** An unexplained inference spike is often the fastest indicator of credential abuse or an authorization bypass
- Containment runbook holds an explicit `Deny` on KMS, Backup, CloudTrail — *a containment action must never be able to erase its own trace*

---

## Cost as a security control

**Three tiers, because detection latency differs by an order of magnitude:**

| Tier | Latency | Mechanism |
|---|---|---|
| Application | Immediate | Per-tenant + per-client token budget |
| Infrastructure | Minutes | CloudWatch anomaly bands on token counts |
| Billing | Hours–day | Budget Actions attaching a deny policy |

> Cost Explorer updates **daily** — a runaway loop consumes a month of budget before the billing tier reacts. Tier 2 is the operational control; tier 3 is the backstop for when tier 2's alarm was misconfigured.

*Framing:* for a metered inference endpoint, the abuse case is **consumption** — the one attack that succeeds while every access control functions exactly as designed.

---

## Organizations — SCPs

Split into four policies by domain (5,120-char cap):

1. Detective-control protection — cannot disable CloudTrail, GuardDuty, Config, Security Hub, Inspector, Macie
2. Audit and backup immutability — Object Lock, Vault Lock, key destruction, PITR
3. **Inference governance** — deny null `GuardrailIdentifier`, deny null `InferenceProfileArn`
4. Data protection — region restriction, tagging, egress-path creation, root

**Two subtleties worth mentioning if asked:**
- Region restriction uses `NotAction` to exempt global services — without it, IAM/STS/CloudFront/Route 53 break across the OU
- Denying foundation-model ARNs is *not* the alternative to the inference-profile check: profiles invoke the underlying model, so an ARN deny breaks them along with the bypass

---

## Backup & recovery

- Cross-account copy to a Backup account — **a full compromise of the workload account cannot destroy recovery points that are not there**
- Vault Lock compliance mode; `LockConfiguration` **with** `ChangeableForDays` is compliance mode — omitting that field gives governance mode, which a privileged principal can override
- Aurora Backtrack is MySQL-only, so PITR is the only rewind and it produces a **new cluster** — the runbook must include the RDS Proxy target-group retarget
- Quarterly restore exercise. *An untested backup is an assumption; the measured RTO is what belongs in the recovery statement*

---

## Delivery pipeline

- **GitHub OIDC, no long-lived keys.** Trust policy pins `sub` to repository **and** environment — `repo:<org>/*` lets any branch and any fork's PR assume the production role
- **Three roles, not one:** `CfnDeploymentRole` starts a stack operation and passes exactly one role, only to CloudFormation. `CfnServiceRole` holds the permissions and is assumable only by `cloudformation.amazonaws.com`. A pipeline compromise yields the ability to deploy a *reviewed template*, not to call arbitrary APIs
- Permissions boundary denies self-detachment, IAM user creation, audit/backup mutation, key destruction
- Actions pinned to commit SHAs — a tag is mutable
- `npm ci --ignore-scripts` — blocks the lifecycle-script path most npm supply-chain attacks use

---

## To-dos

- **Corpus ingestion has no content validation.** Writers are restricted; content is not. It is the one injection route that lands *inside* the boundary and bypasses the pre-egress guardrail
- **Output handling is unspecified** because the downstream consumer is unstated — that also blocks the AI impact assessment
- **No adversarial regression corpus.** Guardrail quality is inferred from intervention rate, which moves with attack volume rather than control effectiveness
- **Bearer tokens are not sender-constrained.** Cognito lacks DPoP; closing it needs mTLS or a different IdP
- **Five Lambda functions are unwritten** — egress proxy, secrets rotation, lifecycle, pre-token-generation, containment runbook
- **Nothing is deployed.** 20 templates, `cfn-lint` clean; runtime behaviour unverified

---

## Closing line

> Every failure mode in the request path is a **deny or a stop**. There is no step whose failure mode is "continue."
