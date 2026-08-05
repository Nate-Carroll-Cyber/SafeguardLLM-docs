# CloudFormation — Secure Generative AI Workload

Implements `aws-secure-genai-workload-architecture.md`. Layered stacks rather than
one template: the 500-resource limit is reachable, but the real reason is blast
radius — a change to Lambda code should not put the KMS keys or the VPC in a
changeset.

## Stack order

| # | Stack | Status | Depends on |
|---|---|---|---|
| 00 | `00-kms.yaml` | **delivered** | — |
| 01 | `01-network.yaml` | **delivered** | 00 |
| 02 | `02-endpoints.yaml` | **delivered** | 01 |
| 03 | `03-identity.yaml` | **delivered** | 00, 02 |
| 04 | `04-data.yaml` | **delivered** | 00, 01 |
| 05 | `05-cognito.yaml` | **delivered** | 04 |
| 06 | `06-bedrock.yaml` | **delivered** | 00, 03 |
| 07 | `07-compute.yaml` | **delivered** | 01–06 |
| 08 | `08-api.yaml` | **delivered** | 00, 07 |
| 09 | `09-edge.yaml` | **delivered** | 08 — **deploy to us-east-1** |
| 09b | `09b-spa-edge.yaml` | **delivered** | — **deploy to us-east-1** |
| 10 | `10-observability.yaml` | **delivered** | 00, 06, 08 |
| 11 | `11-log-delivery.yaml` | **delivered** | 08, 10, **20** |
| 12 | `12-backup-plan.yaml` | **delivered** | 04, **21** |

### Other accounts — deploy before layer 11

| # | Stack | Target account | Status |
|---|---|---|---|
| 20 | `20-log-archive.yaml` | Log Archive | **delivered** |
| 21 | `21-backup.yaml` | Backup | **delivered** |
| 22 | `22-pipeline.yaml` | Shared Services | **delivered** |
| 22b | `22b-deployment-roles.yaml` | **each target account** | **delivered** |
| 23 | `23-scp.yaml` | Management | **delivered** |
| 24 | `24-security.yaml` | Security | **delivered** — prerequisite for layer 10 |

**Dependency cycle, and how it is broken.** Endpoint policies (02) name IAM roles;
IAM policies (03) need endpoint IDs for `aws:SourceVpce`. Layer 02 constructs role
ARNs from a deterministic naming convention rather than importing them, so 03 can
import endpoint IDs normally. The names in 02 and 03 must stay in sync:

```
${ApplicationId}-${Environment}-SafeguardExecRole
${ApplicationId}-${Environment}-KBRetrieveRole
${ApplicationId}-${Environment}-EgressProxyRole
${ApplicationId}-${Environment}-AuthorizerRole
${ApplicationId}-${Environment}-SecretsRotationRole
```

Layer 02 also takes the guardrail and knowledge base ARNs as parameters. Both are
created in 06. Either create the guardrail out of band first, or deploy 02 with
placeholders and update after 06 — the second is cleaner in a pipeline and the
endpoint policy is not load-bearing until 07 exists.

## Deploy

```bash
aws cloudformation deploy \
  --stack-name genai-kms-prod \
  --template-file 00-kms.yaml \
  --parameter-overrides \
      Environment=prod CostCenter=CC-1234 Owner=platform-sec \
      KeyAdminRoleArn=arn:aws:iam::111122223333:role/KeyAdmin \
  --capabilities CAPABILITY_IAM \
  --role-arn arn:aws:iam::111122223333:role/CfnServiceRole
```

`--role-arn` is not optional in this design. Deployment permissions belong to
`CfnServiceRole`, which only CloudFormation can assume; `CfnDeploymentRole` can
start the operation and pass that role, and nothing else.

## What layer 00 does

Five customer-managed keys separated by data class, so a key-policy error is
contained to one class of data rather than all of it. `cmk/audit` and `cmk/backup`
are absent by design — they live in the Log Archive and Backup accounts, with
workload principals excluded from their key policies.

Every key policy grants root access. This looks wrong and is not: without it, the
key becomes unmanageable and CloudFormation cannot update it. Least privilege is
enforced by the `kms:ViaService` conditions on the service-use statements, which
prevent a principal with a broad IAM policy from using the key outside the service
it was created for.

`cmk/logs` is the exception. CloudWatch Logs calls KMS directly rather than through
another service, so `ViaService` does not apply. It takes a service-principal grant
with an `EncryptionContext` condition scoping it to log groups in this account —
without that condition, any log group in the account can use the key.

## What layer 01 does

**Five subnet tiers per AZ, not the four in spec §5.1.** Network Firewall requires
a dedicated subnet containing nothing else, so the firewall endpoints cannot share
the public tier. Amend §5.1.

Egress order is **firewall → NAT → IGW**, not the reverse. Traffic reaching the
firewall after NAT would all appear to come from the NAT address, making per-source
rules useless and source attribution in the flow logs impossible.

The isolated compute and data route tables have no `0.0.0.0/0` entry at all. That
absence is the control described in §5.1 — a security-group misconfiguration cannot
create internet access the route table does not provide.

The firewall policy defaults to `aws:drop_established` under `STRICT_ORDER`. The
default without strict order is to pass unmatched traffic, which inverts the
allow-list into a suggestion.

## What layer 02 does

Gateway endpoints for S3 and DynamoDB (free, route-table based); interface endpoints
for Bedrock runtime and agent-runtime, Secrets Manager, KMS, STS, Cognito IDP, Logs,
CloudWatch, and X-Ray.

The `bedrock-runtime` endpoint policy restricts principal, inference profile ARN,
**and** `bedrock:GuardrailIdentifier` — independently of the identity policy. That
is the third of the three guardrail enforcement layers in §6.2, and the only one
that survives an IAM policy error.

`bedrock-agent-runtime` allows `Retrieve` and not `RetrieveAndGenerate`. The latter
issues an implicit model invocation carrying no guardrail identifier, so a role
bound by the enforcement condition would be denied on it anyway.

Two endpoint policy details that break deployments if omitted:

- The S3 policy needs an allow for `prod-${region}-starport-layer-bucket`. Lambda
  pulls deployment packages from it, and every function in the isolated tier fails
  to start without it.
- `cognito-idp` has no policy but must exist. A VPC-attached authorizer fetches the
  JWKS over it, and with no default route there is no fallback — cold start hangs
  and every request 500s.

## What layer 03 does

Seven runtime roles. Names are fixed by `RoleName` because layer 02 endpoint
policies construct these ARNs from a naming convention — rename a role here and
the corresponding endpoint policy breaks silently, denying at the network
boundary with no IAM error to point at.

**Guardrail enforcement** on `SafeguardExecRole` is an Allow conditioned on
`bedrock:GuardrailIdentifier` plus an explicit Deny under `StringNotEquals`. The
Deny is what makes it hold: an Allow in any other attached policy cannot override
it. `GuardrailArn` is pattern-constrained to require a numeric version, so a bare
identifier fails at parameter validation rather than deploying a weakenable
guardrail.

**Two Bedrock actions that do not exist.** `bedrock:Converse` is not an IAM
action — the Converse API authorizes on `bedrock:InvokeModel`.
`dynamodb:TransactWriteItems` is likewise not an IAM action; the API authorizes
on the item-level action for each operation plus `ConditionCheckItem`. Both
appeared in the original role specification. A policy granting either saves
cleanly and denies at runtime.

**`KBRetrieveRole` and `KnowledgeBaseServiceRole` are separate roles.** The
first holds the caller-side `bedrock:Retrieve`; the second is assumed by Bedrock
and holds the data-source read, vector index query, and embedding model
invocation. Conflating them produces a knowledge base that cannot sync.

**ENI permissions are a documented carve-out.** Every VPC-attached function needs
`ec2:CreateNetworkInterface` / `DescribeNetworkInterfaces` / `DeleteNetworkInterface`
on `Resource: "*"`, and those calls cannot carry `aws:SourceVpce` — they are made
by the Lambda service before any endpoint is in the request path. Each role has
them in a separately named policy so the exception stays visible in review.

**`rds-db:connect` names a database user, not a cluster.** The resource ARN is
`dbuser:*/${ApplicationId}_app`. Layer 04 must create a Postgres role of exactly
that name with `rds_iam` granted, or IAM auth fails with a generic
authentication error.

## What layer 04 does

Aurora PostgreSQL Serverless v2 (0.5–4 ACU), RDS Proxy, and three DynamoDB
tables. A second Aurora instance is created in prod only — a single-instance
Serverless v2 cluster has no failover target, so the two-AZ subnet layout buys
nothing without it.

**`EnableIAMDatabaseAuthentication` is only half of IAM auth.** The cluster flag
permits it; a Postgres role must also be granted `rds_iam`. `sql/01-bootstrap.sql`
does that, and the role name there must match the `rds-db:connect` resource ARN
in layer 03 exactly. Divergence produces a generic authentication failure that
reads like a networking problem.

**RDS Proxy uses `IAMAuth: REQUIRED`.** The client presents an IAM token; the
proxy uses the master secret for its own connection to the cluster. That is what
lets the adapter hold no database password at all. `SessionPinningFilters` is set
to `EXCLUDE_VARIABLE_SETS` — without it, a `SET` statement pins the connection
and silently collapses the pool to one connection per invocation.

**`rds.force_ssl: 1`** rejects non-TLS connections at the engine. `data.mjs` sets
`rejectUnauthorized: true`, but a client can be changed and this cannot be
bypassed from the application side.

**Ledger `pk` is `TENANT#<id>`.** That prefix is what `dynamodb:LeadingKeys` binds
against in layer 03. Changing the key shape disables the condition with no error —
the policy still evaluates, it just stops scoping.

**The entitlement table has no TTL and read-only access from the authorizer.**
Every tenant boundary in the system resolves back to a row in it, which makes it
the highest-integrity data in the workload account. The authorizer role carries
`GetItem` plus an explicit `Deny` on every write.

**Postgres row-level security is the backstop for tenant isolation**, not the
primary control. `data.mjs` puts `tenant_id` in the query predicate; RLS with
`FORCE` means a query that omits it returns nothing instead of returning another
tenant's rows. The adapter must set `app.tenant_id` per connection from the
authorizer context for the policy to evaluate.

**HNSW index uses `vector_cosine_ops`** to match the `<=>` operator in `data.mjs`.
An L2 index with a cosine query silently falls back to a sequential scan — correct
results, no index, and no error to notice.

## What layer 05 does

One user pool, one resource server with `llm/invoke` and `llm/retrieve`, and two
app clients. Human: authorization code + PKCE, no secret, SRP only. Machine:
`client_credentials`, secret generated, custom scopes only.

**`UserPoolTier: ESSENTIALS` is load-bearing.** The V3_0 pre token generation
trigger is the only version that fires for `client_credentials`, and V3_0
requires Essentials or Plus. On LITE the trigger silently never fires for M2M —
the tenant claim never appears, and every machine request is denied by the
authorizer with nothing in the logs pointing at the cause. V2_0 has the same
failure: it covers human access tokens only.

**The tenant provenance question is resolved in the trigger, and the answer is
server-side derivation.** Cognito passes `aws_client_metadata` from the
`client_credentials` request straight through to the trigger, so any tenant read
from that metadata is a value the caller chose. The trigger here ignores client
metadata entirely and reads `defaultTenant` from the entitlement table keyed on
`event.callerContext.clientId`. Deriving makes the claim a fact; reading would
make it an assertion.

The authorizer re-checks entitlement anyway. By the time a claim reaches the API
it is just a claim again, and the trigger and the authorizer are separately
compromisable.

**The trigger is not VPC-attached** — Cognito invokes it on the service plane, so
its DynamoDB lookup cannot carry `aws:SourceVpce`. Documented exception to the
data perimeter, compensated by a resource-scoped policy and an explicit write
`Deny`. It is the second such exception in the build; both are listed here rather
than buried in the template.

**`ExplicitAuthFlows` omits `ALLOW_USER_PASSWORD_AUTH`** on the human client.
That flow sends the password to the API in plaintext-over-TLS and defeats SRP.
Refresh token rotation is on, so a stolen refresh token is detectable — the
legitimate client's next refresh fails.

M2M token requests are billed separately from MAU. A machine caller that requests
a token per API call rather than caching until expiry will show up in the bill
before it shows up in the metrics.

## What layer 06 does

Guardrail with a published numeric version, S3 Vectors bucket and index,
knowledge base with an S3 data source, and the responder application inference
profile.

**Deploy order has a knot here.** Layers 02 and 03 take `GuardrailArn` and
`KnowledgeBaseArn` as parameters, so this stack is logically upstream of them but
deploys after — it needs the KMS keys and the KB service role. Deploy 02 and 03
with placeholder ARNs, then 06, then update 02 and 03 with the real values. The
placeholders are inert until layer 07 creates something that can call them.

**`GuardrailVersion` exists to make weakening a deployment.** DRAFT is mutable in
place, so pinning DRAFT in the IAM condition leaves exactly the gap the condition
was meant to close. Every edit to the guardrail must be published as a new
version and the layer 03 condition updated to match. That update is deliberate
friction — it is what forces a guardrail change through the pipeline's
adversarial regression gate rather than letting it land in a console session.

Use `GuardrailVersionedArn` from the outputs, not `GuardrailArn`.

**`PROMPT_ATTACK` takes `OutputStrength: NONE`.** The filter applies to input
only; setting an output strength on that type is rejected at create time.

**System prompt disclosure is a denied topic**, not just a system-prompt
instruction. This closes appsec A-13 — instruction asks the model, a denied topic
enforces at the guardrail.

**PII actions split BLOCK and ANONYMIZE deliberately.** Names, emails, phones,
addresses anonymize and the request proceeds. Credentials — SSN, card numbers,
passwords, AWS keys — block outright, because a redacted credential is still a
credential the model was shown.

**`DataDeletionPolicy: RETAIN`** on the data source. An embedding derived from
personal data is personal data, so deleting it must be a decision rather than a
side effect of a stack change. The consequence for spec §12.4: subject erasure
requires an explicit re-sync after deleting the source object. Deleting the
object alone leaves the vector, and usually enough of the source text in the
retrievable chunk to reconstruct it.

**`tenantId` is filterable by omission.** `NonFilterableMetadataKeys` lists what
*cannot* be filtered; `tenantId` is absent from that list, which is what makes
the tenant-scoped retrieval filter in `inference.mjs` work. Adding it there would
silently break tenant isolation at retrieval with no error.

**The KB source bucket policy restricts writers**, and that is necessary but not
sufficient. Anything landing in that bucket is chunked, embedded, and served to
the model as grounding context, so the write path is the corpus-poisoning surface
(MAESTRO L3-T01). Content validation before indexing remains open.

## What layer 07 does

Five functions: authorizer, adapter, egress proxy, secrets rotation, lifecycle.
All `nodejs24.x` — `nodejs20.x` was deprecated 2026-04-30 and creation is
disabled from 2027-02-01.

**Code comes from an S3 artifact bucket, not inline.** Inline `ZipFile` is capped
at 4096 bytes and cannot carry `node_modules`, so anything with an SDK dependency
needs a packaged artifact. `ArtifactVersion` is the commit SHA, which is what
makes a deployed function traceable to a review.

**Every function declares its own log group.** A group auto-created by Lambda on
first invoke has no KMS key and no retention — it inherits nothing, and by the
time anyone notices it already holds data.

**The timeout chain is tight and deliberate.** API Gateway's integration ceiling
is 29 s hard. Adapter is 28 s, egress proxy 26 s, judge cap 25 s. That leaves
roughly 3 s for the authorizer, budget check, pgvector query, guardrail call,
Converse, and ledger write. An attacker who slows the judge to 24 s forces 504s
across the board — worth alarming on judge latency specifically, not just on
error rate.

**Egress proxy reserved concurrency is a safety control, not a cost one.** Set
below the `ApplyGuardrail` throughput limit, it converts a guardrail throttle —
which is the fail-open pressure point identified in the MAESTRO L8-T03 finding —
into a queueing delay upstream.

**The adapter reaches the egress proxy by Lambda invoke, not over the network.**
The adapter has no route to the egress subnets; the hop is a function-to-function
call on the service plane. That is what makes "the adapter cannot reach the
internet" true rather than aspirational.

**Environment variables carry names and endpoints, never secrets.** They are
readable by anyone holding `lambda:GetFunctionConfiguration`. The judge API key
is referenced by secret name and fetched at runtime.

**Ledger stream filtering** is `{"eventName":["REMOVE"]}`. TTL deletions arrive
as REMOVE records with `userIdentity` set to the DynamoDB service principal,
which is how an expiry is distinguished from an application delete. The receipt
written from these is the provable record of what was deleted and when — TTL
alone produces no such record.

## What layer 08 does

REST API with two methods, a REQUEST authorizer, and the regional WAF.

**`IdentitySource` includes the method and resource path.** This is the fix for
the authorizer cache hazard: a TOKEN authorizer keys only on the token, so the
first request from a scope-limited token caches a policy, and if that policy
names a wildcard resource, every subsequent request is authorized against the
wildcard. The scope check stops applying with no visible symptom. Include the
method in the key **and** never return a wildcard resource — both, not either.

**`AuthorizerResultTtlInSeconds` must stay below the token lifetime.** A revoked
token remains accepted for up to the cache TTL. Containment happens at the WAF
layer, which is not cached.

**The WAF rate rule aggregates on the `authorization` header, not source IP.** IP
aggregation buckets every caller behind a corporate NAT or a single MCP server
together — the token is the only value that distinguishes them.

**`SizeRestrictions_BODY` is overridden to Allow** in the common rule set.
Prompts routinely exceed its default and trip it. Body size is bounded by the API
Gateway request model and by the adapter instead.

**WAF logs redact `authorization` and `x-origin-verify`.** Without redaction the
bearer token is logged in full on every blocked request, in a workload-account
log group.

**`DataTraceEnabled: false`** on the stage. Request and response bodies carry
prompt content, and this log group is the one destination in the architecture
that is not restricted-access.

The WAF log group name must begin `aws-waf-logs-`. A different name is rejected
at association time with a generic error.

## What layer 09 does

**Deploy this stack to us-east-1 regardless of the workload region.** A
`Scope: CLOUDFRONT` WebACL can only exist there, and so must the ACM certificate.
That is why this stack takes `ApiEndpoint` as a parameter rather than importing
it — `Fn::ImportValue` does not cross regions.

Edge rules that are absent on purpose: `x-origin-verify` (the header does not
exist yet at this point), per-tenant limits (no token parsing at the edge), and
the blocked-identity set (containment belongs where identity is known). SQLi and
Linux managed rule sets are also absent — no SQL concatenation and no shell exec
anywhere in this workload, and both fire on prose containing SQL keywords.

`AnonymousIpAction` defaults to `count`. That rule catches corporate VPNs and
datacenter ranges, and MCP callers run in datacenters by definition. Measure
before blocking.

**The edge rate limit is deliberately far above the regional one.** It counts
every request from an IP including static assets; the regional rule counts only
authenticated API calls keyed on the token. Same number on both means the edge
one fires first on legitimate traffic.

**Nothing is cached.** A cached response on `/v1/*` would be a cross-tenant
disclosure with no attacker involved.

The **origin request policy** is the least-discussed control here and the most
structural: an explicit allow-list of headers that cross into the region, which
turns header smuggling into a problem of defeating a whitelist.

## What layer 09b does

The SPA: private S3 bucket with Origin Access Control, its own CloudFront
distribution, its own edge WAF.

**Two distributions rather than one, deliberately.** With a single distribution
serving both workloads, a cache-behavior ordering mistake caches an API response
and serves it to the next caller — a cross-tenant disclosure with no attacker
involved. Two distributions cannot make that mistake.

**Three WAF rules invert between the two edge WebACLs**, which is the other half
of the argument:

| Rule | SPA | API |
|---|---|---|
| Bot Control | On | **Off** — machine callers are non-browser by design |
| Anonymous IP | Block | **Count** — MCP servers run in datacenters |
| Rate limit | IP-keyed, 5000/5min | Token-keyed, 500/5min |

Browser requests carry no `Authorization` header, so token aggregation would put
every SPA request in one bucket and let one active user throttle everyone. Bot
Control is also the expensive rule and only runs here.

`SizeRestrictions_BODY` is **not** overridden on this WebACL. The API needs the
override because prompts are large; the SPA has no request bodies, so the default
is correct.

**Four OAC details that fail silently if wrong:**

- `RegionalDomainName`, not the website endpoint. `s3-website-*` does not accept
  SigV4, so OAC against it returns 403 on every object with no indication why.
- `S3OriginConfig.OriginAccessIdentity` must be an empty string. A value there is
  the legacy OAI field and conflicts with `OriginAccessControlId`.
- The bucket policy's `AWS:SourceArn` condition is the actual control. The
  service principal alone is not a boundary — without the condition, any
  CloudFront distribution in any account pointed at this origin can read it.
- SSE-S3, not a CMK. OAC with SSE-KMS needs `cloudfront.amazonaws.com` granted
  `kms:Decrypt` in the key policy, and `kms:ViaService` does not cover it because
  CloudFront calls KMS as itself.

**403 is mapped to the app shell alongside 404.** With a private bucket and no
`ListBucket` grant, a missing key returns AccessDenied rather than NoSuchKey, so
client-side deep links break unless both are mapped.

**The CSP is distinct from the API's.** `default-src 'none'` is right for a JSON
API and fatal for an application — it blocks the app's own scripts and styles.
`connect-src` names the API origin.

**Two cross-stack couplings this creates.** The SPA is now a different origin
from the API, so `ALLOWED_ORIGINS` on the adapter (layer 07) must include the SPA
URL, and Cognito's `CallbackUrls` (layer 05) must point at it.

## What layer 10 does

Model invocation logging, alarms, cost circuit breakers, response runbook role.

**Invocation logs are the only user-content store in this stack.** Own retention
(30 days default), own read path. CloudTrail records that a call occurred, never
its content — different systems, both required, but only this one holds prompts.

**Alarms are on latency and anomaly bands, not just errors.** The judge alarm
watches p95 duration against a threshold below the 25 s cap: an attacker who
slows the judge toward the ceiling forces 504s across the board without producing
a single judge error.

**`GuardrailInterventionDropAlarm` fires on a DROP, not a spike.** A weakened
guardrail and a quieter attack environment look identical in aggregate — which is
why per-attack-class rates belong in the adversarial regression suite, and why
this alarm exists at all. Weakening a guardrail is not deleting it, so the
permissions boundary does not catch it.

**Cost anomalies route to the security topic, not finance.** An unexplained
inference cost spike is frequently the fastest available indicator of credential
abuse, an authorization bypass, or a retrieval loop.

**The response runbook role carries an explicit `Deny` on KMS, Backup, and
CloudTrail.** A containment action must never be able to erase its own trace.

### Known deviation from spec section 10

WAF, Network Firewall, and VPC Flow Logs land in workload-account CloudWatch
groups rather than Firehose to the Log Archive account. Closing this needs the
Log Archive bucket, its policy, and `cmk/audit` — none of which exist in the
00–10 sequence, which is workload-account only.

Note also that GuardDuty does not read WAF logs at all; its sources are
CloudTrail, VPC Flow Logs, DNS logs, and the protection plans. Security Hub
aggregates findings, not log lines. So "which rule blocked this request, and what
did it contain" is answerable *only* from the WAF log — and in this architecture
most interesting behaviour happens at the application layer, which is precisely
the layer GuardDuty does not cover.

## What layers 20, 21, and 11 do

**Layer 20 — Log Archive account.** `cmk/audit`, the WORM audit bucket, the Org
Trail. No workload principal appears in the key policy or the bucket policy, and
that absence is the control — a full compromise of the workload account yields no
path to decrypt or delete the record of the compromise. The workload account gets
`PutObject` on one prefix and an explicit `Deny` on read, list, and every delete
action.

The key policy also denies `kms:ScheduleKeyDeletion` and `kms:DisableKey` to
every principal. Without that, an account administrator can render every archived
log unreadable without deleting a single object.

Model invocation logs land under their own prefix so the bucket policy can
restrict reads to a named investigation role. That prefix holds prompt and
completion bodies — user content, unlike everything else in the bucket. A broad
security-audit role gets the rest and not this.

Object Lock is COMPLIANCE mode and `ObjectLockEnabled` cannot be turned on after
creation. Getting it wrong means recreating the bucket and re-delivering every
log.

**Layer 21 — Backup account.** `cmk/backup` and the central vault. Separate from
Log Archive deliberately: audit data must survive tampering, recovery points must
survive destruction, and one account holding both is a single target whose
compromise removes the record of an incident and the ability to recover from it.

`VaultLockEnabled` defaults to **false**. Enabling it starts a countdown to
permanence — past the cooling-off window no principal including root and AWS
Support can shorten retention or delete a recovery point. Leave it false until the
retention figures are settled, then arm it.

Note that `LockConfiguration` *with* `ChangeableForDays` is compliance mode.
Omitting that field gives governance mode, which a sufficiently privileged
principal can override — and that principal is exactly the one an attacker would
obtain.

**Layer 11 — log delivery.** Closes the spec §10 deviation. Firehose from the
workload account to the Log Archive bucket for WAF, Network Firewall, and Bedrock
invocation logs. The delivery role holds `GenerateDataKey` without `Decrypt`: it
writes objects it can never read back.

CloudWatch stays as a short-retention operational copy — fast to query during an
incident. The archive is the copy that survives a compromise of the account being
logged.

VPC Flow Logs are deliberately excluded. GuardDuty consumes them directly, and
their volume makes archive delivery expensive for low investigative value. WAF
and Network Firewall are security logs and do go to the archive — GuardDuty reads
neither, and "which rule blocked this request and what did it contain" is
answerable only from those logs.

Subscription filters use `FilterPattern: ""`. A filter here would decide at write
time what is worth keeping, which is the decision an investigation needs to make
later.

## What layers 22, 22b, 23, and 24 do

**Layer 22 — Shared Services.** `cmk/pipeline`, artifact bucket, GitHub OIDC
provider, `GitHubOIDCRole` and `PipelineExecRole`, plus the `DeploymentBoundary`
managed policy.

The OIDC trust policy pins `sub` to `repo:<org>/<repo>:environment:<env>`. A
wildcard like `repo:<org>/*` lets any branch — and any fork opening a pull
request — assume the role. This is the most common failure in OIDC pipeline
setups and warrants explicit review.

The boundary denies escape, IAM user creation, audit and backup mutation, key
destruction, and guardrail *deletion*. It does not deny guardrail *modification*
— weakening is not deleting, and a boundary cannot express "may update but not
weaken." That gap is closed by the adversarial regression gate in the pipeline,
not here.

`DeploymentBoundaryArn` is a parameter defaulting to empty. Deploy once to create
the policy, then re-run with the output value to attach it — a role cannot
reference a boundary created in the same stack operation.

**Layer 22b — deployment roles, one per target account.** A role must be created
in the account it acts on, so this half cannot live in the Shared Services stack.

`CfnDeploymentRole` can start a stack operation and pass exactly one role, only
to CloudFormation. `CfnServiceRole` holds the mutation permissions and can only
be assumed by `cloudformation.amazonaws.com` — no human and no pipeline role can
assume it directly. Neither alone can call an arbitrary API.

`CfnServiceRole` uses `PowerUserAccess` plus scoped IAM management, bounded by
the permissions boundary rather than by enumeration. Enumerating every action
across eighteen stacks produces a policy that is long, incomplete, and revised on
every deployment failure.

The role names here are referenced by layer 02 endpoint policies, the layer 06
bucket policy, and SCP 4. Renaming breaks those silently.

**Layer 23 — SCPs, split into four policies.** Each SCP is capped at 5,120
characters, so the twelve controls do not fit in one. Split by domain — detective
protection, audit and backup immutability, inference governance, data protection
— so the reason a given deny exists stays legible during an incident.

Two subtleties. The region restriction uses `NotAction` to exempt global services;
without that exemption IAM, STS, CloudFront, and Route 53 break across the whole
OU. And `ApprovedRegions` must include every region backing a cross-region
inference profile — a profile whose backing region is denied fails at runtime with
an access-denied that reads like a permissions bug.

The inference SCP denies a *null* `bedrock:InferenceProfileArn` rather than
denying foundation-model ARNs. Denying model ARNs directly is not the
alternative: profiles invoke the underlying model, so an ARN deny breaks them
along with the bypass it was meant to close.

**Layer 24 — Security account.** Detection services, the alert topic every layer
10 alarm points at, `SecReadOnlyRole`, `SecResponderRole`, and the scanning
bucket from spec §14.

**This is a prerequisite for layer 10 despite the higher number.** Layer 10 takes
`SecurityAlertTopicArn` as a parameter and that topic is created here.

`EnableDefaultStandards` is false. Default-enabled standards produce hundreds of
findings unrelated to this workload, which is how alert fatigue starts.

The scanning bucket has a 1-day lifecycle and a single-principal read policy. It
is a deliberate concentration of the sensitive data the rest of the architecture
works to disperse — the most attractive object this design creates.

Macie findings route at *every* severity. A finding in a scanning export means
guardrail redaction failed; that is the alert worth paging on, not the fact that
data was found.

Delegated-administrator registration for Security Hub, GuardDuty, Config, and
Macie happens in the Management account and is not expressible in CloudFormation.
One-time CLI step:

```bash
aws organizations register-delegated-administrator \
  --account-id <security-account-id> \
  --service-principal securityhub.amazonaws.com
# repeat for guardduty, config, macie2, inspector2
```

## Deploy order across accounts

1. **Management** — enable all features in Organizations, register delegated
   admins, deploy `23-scp.yaml` last (SCPs will block later steps otherwise)
2. **Log Archive** — `20-log-archive.yaml`
3. **Backup** — `21-backup.yaml` with `VaultLockEnabled=false`
4. **Shared Services** — `22-pipeline.yaml`, twice (boundary bootstrap)
5. **Each target account** — `22b-deployment-roles.yaml`
6. **Security** — `24-security.yaml`
7. **Workload** — `00` through `11` in order, with the placeholder updates noted
   above
8. **us-east-1** — `09-edge.yaml`
9. Back to **Management** — `23-scp.yaml`
10. Back to **Backup** — re-run `21` with `VaultLockEnabled=true` once retention
    is settled

## What layer 12 does

Populates the central vault. Without it layer 21 creates an empty vault and the
cross-account custody claim in spec §13.2 is not true — Aurora automated backups
and DynamoDB PITR are account-local and survive an operator mistake, not a
compromise of the account holding them.

A local staging vault exists because AWS Backup copies *from* a vault; the copy
action to the Backup account is the control. Selection is by explicit ARN rather
than by tag: a tag-based selection silently stops covering a resource whose tag
was removed, while an ARN list fails loudly at deploy time.

The entitlement table is in the selection deliberately. It is small and rarely
changes, but every tenant boundary in the system resolves back to a row in it —
losing it is an authorization outage, not a data-loss incident.

## Corrections applied after review

Seven issues found reviewing the completed set. Recorded because several were
the kind that pass `cfn-lint` and fail in production.

**SCP 4 denied every bucket and table creation.** The condition was `Null` on
`s3:x-amz-server-side-encryption`, an object-level key that is absent on
`s3:CreateBucket` and does not exist for `dynamodb:CreateTable`. Null evaluated
true for every create, so the deny always fired. Because SCPs deploy last, the
initial build would have succeeded and nothing could ever have created a bucket
or table in that OU again.

Encryption-at-creation is not expressible as an SCP — the resource properties an
SCP would need to inspect are not condition keys. The replacement denies
unencrypted `s3:PutObject`, where the key *is* populated, and bucket-default and
table encryption move to Config rules and `cfn-guard`.

**Layer 21's vault policy blocked its own lock.** `PutBackupVaultLockConfiguration`
was denied to `Principal: "*"`, so the documented "re-run with
`VaultLockEnabled=true`" step was denied by the policy the first run installed.
Now carved out for `CfnServiceRole`. The carve-out is one-directional: compliance
mode cannot be weakened once the cooling-off window passes, so the deployment
role can arm the lock and can never disarm it.

**Nothing populated the central vault** — no backup plan existed anywhere. Layer
12 above.

**Layer 02 still carried `dynamodb:TransactWriteItems`**, corrected in layer 03
but not here, and omitted `ConditionCheckItem`. A transaction with a condition
check was allowed by the identity policy and denied at the endpoint.

**Layer 20's invocation-log restriction exempted every role in the Log Archive
account**, making "only the named investigation role" cosmetic. Narrowed to the
investigation role in either the Security or Log Archive account. Consequence
worth knowing before an incident: no local administrator can read that prefix.

**SCP 2 had no exceptions** where the statement directly below it did, and denied
`s3:PutBucketVersioning` outright — so any later update touching the audit
bucket's versioning would fail. Split into a deletion deny with no exception and
a configuration deny exempting the deployment role.

**SCP 4 denied root entirely.** AWS reserves a handful of tasks that only root
can perform — closing an account, changing the root email, restoring a bucket
policy that locked everyone out. An unconditional deny removes recovery from
exactly the situations root exists for. Now `NotAction` leaves that narrow set
reachable; the practical control is alerting on root sign-in, not denying the
last resort.

## Still outside CloudFormation

- `sql/01-bootstrap.sql` — schema, `rds_iam` grants, pgvector extension
- Function artifacts. Layer 07 references five zips; only the authorizer and
  three adapter modules exist as code. The egress proxy, secrets rotation, and
  lifecycle functions are unwritten, as is the Express handler wiring the adapter
  modules together
- Delegated administrator registration
- Entitlement table seed data — no client can authenticate until a
  `clientId → defaultTenant` row exists

## Decisions made during the build

Recorded because each one is a place the templates and the specification could
drift apart.

| Question | Resolved as | Where |
|---|---|---|
| Authorizer VPC attachment | **In-VPC** — `aws:SourceVpce` on the entitlement lookup is worth the ENI cold-start cost. This is why `cognito-idp` is in the endpoint set | 02, 07 |
| Guardrail version pinning | **Numeric version required.** `GuardrailArn` is pattern-constrained, so a bare identifier fails parameter validation rather than deploying something weakenable in place | 03, 06 |
| Tenant claim provenance | **Server-side derivation.** The V3_0 trigger ignores `aws_client_metadata` and reads `defaultTenant` from the entitlement table keyed on `clientId`. Deriving makes the claim a fact; reading client metadata would make it an assertion. Closes MAESTRO L7-T06 | 05 |
| Aurora minimum capacity | **0.5 ACU** | 04 |
| Subnet tiers | **Five, not four.** Network Firewall requires a dedicated subnet. Spec §5.1 needs amending | 01 |
| WAF and firewall log destination | **Firehose to Log Archive**, with CloudWatch retained as a short-retention operational copy | 11 |

## Still open

1. **`bedrock-mantle`.** No PrivateLink service name confirmed, and the
   `bedrock:GuardrailIdentifier` condition covers `InvokeModel` / `Converse` on
   `bedrock-runtime` — whether it reaches the OpenAI-compatible surface is not
   established. Until it is, treat that path as external inference and route it
   through the egress proxy, which changes the FQDN allow-list in layer 01.
2. **Corpus ingestion validation.** The layer 06 bucket policy restricts who may
   write to the knowledge base data source. Nothing validates *what* they write,
   and anything landing there is chunked, embedded, and served to the model as
   grounding context. This is MAESTRO L3-T01 and it is not closed anywhere in
   this build.
3. **Adversarial regression corpus.** `ci/deploy.yml` calls
   `scripts/guardrail-regression.mjs`, which does not exist. Without it, guardrail
   quality is inferred from intervention rate — a metric that moves with attack
   volume rather than with control effectiveness.

## Validation

```bash
cfn-lint *.yaml
checkov -d . --framework cloudformation
```

All eighteen templates pass `cfn-lint 1.53.3` clean. **None have been deployed.**
`cfn-lint` validates schema and intrinsic function usage, not runtime behaviour —
IAM condition evaluation, endpoint policy enforcement, Network Firewall rule
matching, and the Bedrock and S3 Vectors resource types all need a real
deployment to confirm.

The `cfn-guard` step referenced in `ci/deploy.yml` needs
`policy/scp-equivalents.guard`, which is not written. Its purpose is to encode
the layer 23 SCP set as build-time rules, so a template that would be denied at
deploy time fails at build time instead — with a readable message rather than a
partial rollback.
