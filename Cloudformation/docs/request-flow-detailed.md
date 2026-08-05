# Request Flow — Detailed Reference

**Scope:** one authenticated request through the deployed architecture, from client
to response. Every step names where it is implemented and what happens when it
fails.

**Read this alongside** `docs/aws-secure-genai-workload-architecture.md` (the
specification) and `infrastructure/README.md` (deployment). This document is the
runtime view of both.

---

## 0. The shape of it

Only three things are network hops:

1. Client → CloudFront
2. CloudFront → API Gateway (`<api-id>.execute-api.<region>.amazonaws.com`)
3. API Gateway → Lambda (service plane, not the VPC)

Everything else is an evaluation attached to one of those three. WAF is not a
proxy; it is a filter bolted to a distribution or a stage. Nothing has a "WAF
endpoint address." The same is true of resource policies, authorizers, and
request validators — they all run at API Gateway, at the same place, in order.

**Two transactions, not one.** Token acquisition happens before any of this and
is not part of the request path. Cognito is contacted at issuance and never at
use: the authorizer verifies signatures offline against cached public keys. A
Cognito outage breaks new token issuance, not in-flight requests holding valid
tokens.

---

## 1. Edge

### 1.1 DNS

Route 53 A/AAAA alias to the CloudFront distribution. DNSSEC signing on the
hosted zone; Resolver DNS Firewall on outbound VPC resolution with an allow-list
aligned to the Network Firewall FQDN list.

*Implemented:* `09-edge.yaml` — `AliasRecord`, `AliasRecordIpv6`.

### 1.2 TLS handshake

`MinimumProtocolVersion: TLSv1.2_2021`, ACM certificate in us-east-1, `sni-only`.

This runs **before** WAF. A client offering only TLS 1.0 is rejected at the
handshake and never produces a WAF log line — which is worth knowing when a
client reports failures that leave no trace anywhere.

*Implemented:* `09-edge.yaml` — `Distribution.ViewerCertificate`.

### 1.3 Edge WAF

`Scope: CLOUDFRONT`, which can only exist in us-east-1 regardless of workload
region. Rules in priority order:

| Priority | Rule | Action |
|---|---|---|
| 0 | `AWSManagedRulesAmazonIpReputationList` | Block |
| 1 | `AWSManagedRulesAnonymousIpList` | **Count** by default |
| 2 | Geo allow-list | Block (optional) |
| 3 | Method allow-list (`POST`/`GET`/`OPTIONS`) | Block 405 |
| 4 | `AWSManagedRulesCommonRuleSet` | Block |
| 5 | `AWSManagedRulesKnownBadInputsRuleSet` | Block |
| 6 | Rate limit, aggregated on source IP | Block 429 |

Anonymous-IP is set to count, not block, because it catches corporate VPNs and
datacenter ranges — and MCP callers run in datacenters by definition. Measure
before blocking.

`SizeRestrictions_BODY` is overridden to Allow in the common rule set. Prompts
routinely exceed its default. Body size is bounded by the API Gateway request
model and by the adapter instead.

SQLi and Linux rule sets are deliberately absent: there is no SQL string
concatenation and no shell exec anywhere in this workload, and both groups fire
on prose containing SQL keywords, which prompts do.

*Implemented:* `09-edge.yaml` — `EdgeWebAcl`.

### 1.4 Cache policy

Zero TTL on everything. `CookieBehavior: none`, `HeaderBehavior: none`,
`QueryStringBehavior: none`.

A cached response on `/v1/*` would be a cross-tenant disclosure with no attacker
involved at all.

*Implemented:* `09-edge.yaml` — `NoCachePolicy`.

### 1.5 Origin request policy

An explicit allow-list of headers forwarded to the origin: `Authorization`,
`Content-Type`, `X-Request-ID`, `Origin`. No cookies, no query strings.

Anything not named here never reaches the adapter, which turns header smuggling
into a problem of defeating a whitelist rather than a blacklist. This is the
least-discussed control in the design and one of the most structural.

*Implemented:* `09-edge.yaml` — `OriginRequestPolicy`.

### 1.6 `x-origin-verify` injection

CloudFront injects an origin custom header sourced from Secrets Manager.

The edge WAF runs **before** injection and never sees the value, which is why the
origin-verify check is structurally regional-only.

Rotation updates the CloudFront origin header and the regional WAF rule in one
operation, with a dual-value overlap so in-flight requests are not rejected
mid-rotation.

*Implemented:* `09-edge.yaml` — `Distribution.Origins.OriginCustomHeaders`;
rotation in `07-compute.yaml` — `SecretsRotationFunction`.

**→ Hop to API Gateway.**

---

## 2. API tier

CloudFront's origin is the public API Gateway endpoint. That endpoint is
reachable by anyone who knows the hostname, which is why the next two controls
exist.

### 2.1 Regional WAF

| Priority | Rule | Action |
|---|---|---|
| 0 | `x-origin-verify` exact match | Block 403 |
| 1 | Rate-based, custom key on the `authorization` header | Block 429 |
| 2 | `AWSManagedRulesCommonRuleSet` | Block |
| 3 | `AWSManagedRulesKnownBadInputsRuleSet` | Block |
| 4 | Blocked-identity set | Block |

Origin-verify is priority 0 so a direct-to-API-Gateway request is rejected
without consuming managed rule capacity.

The rate rule aggregates on the token, not source IP. IP aggregation buckets
every caller behind a corporate NAT or a single MCP server together; the token is
the only value that distinguishes them.

The edge rate limit is set far higher than this one. It counts every request from
an IP including static assets; this one counts authenticated API calls. The same
number on both means the edge rule fires first on legitimate traffic.

WAF logs redact `authorization` and `x-origin-verify`. Without redaction the
bearer token is written in full on every blocked request — and after layer 11,
into an immutable bucket where it cannot be removed.

*Implemented:* `08-api.yaml` — `WebAcl`, `WafLoggingConfiguration`.

### 2.2 Resource policy

Denies any `aws:SourceArn` other than the CloudFront distribution.

The header is the fast check; this is what holds if the header value leaks. Two
controls for origin cloaking because a static shared secret degrades into a
permanent bypass credential once disclosed.

*Implemented:* `08-api.yaml` — `RestApi.Policy`.

### 2.3 Stage throttle

`ThrottlingRateLimit: 100`, `ThrottlingBurstLimit: 200`.

This is a **capacity** limit, not an abuse control. It does not distinguish
callers at all, so one abusive tenant consuming the bucket starves everyone else
and API Gateway cannot say which one. Set it above expected aggregate; if it is
the limit that trips, per-caller attribution has been lost.

*Implemented:* `08-api.yaml` — `Stage.MethodSettings`.

### 2.4 Authorizer invocation

REQUEST type. `IdentitySource: method.request.header.Authorization,
context.httpMethod, context.resourcePath`.

The method and path in the identity source make the policy cache key per-method.
A TOKEN authorizer keys only on the token: the first request from a
scope-limited token caches a policy, and if that policy names a wildcard
resource, every subsequent request is authorized against the wildcard and the
scope check silently stops applying.

Both halves are required — per-method cache key **and** never returning a
wildcard resource. Either alone leaves the hole.

`AuthorizerResultTtlInSeconds` must stay below the token lifetime.

*Implemented:* `08-api.yaml` — `ApiAuthorizer`.

### 2.5 Request validation

JSON schema with `additionalProperties: false`, `X-Request-ID` required.
Unexpected fields are rejected at the gateway rather than in the adapter.

*Implemented:* `08-api.yaml` — `RequestValidator`, `InferenceRequestModel`.

**→ Invoke the adapter with `$context.authorizer.*`.**

---

## 3. Inside the authorizer

Runs in the isolated compute subnet, VPC-attached so its DynamoDB lookups carry
`aws:SourceVpce`. That costs an ENI attach at cold start, in the hot path of
every uncached request — a deliberate trade against leaving one
identity-critical call outside the data perimeter.

Checks in order. Each one denies; none of them upgrade.

### 3.1 Route

`SCOPE_BY_ROUTE` maps method + path to a required scope. A route absent from the
map is denied before the token is parsed.

### 3.2 Signature and standard claims

`aws-jwt-verify` resolves the JWKS from the issuer derived from `userPoolId` — it
never reads `iss` out of the presented token. That distinction is the difference
between key pinning and signature forgery.

| Check | Value |
|---|---|
| `alg` | RS256 only; `none` and HMAC rejected |
| `iss` | Derived from `userPoolId`, hardcoded |
| `kid` | From the JWKS at that issuer; `jku`/`x5u`/`jwk` headers ignored |
| `exp` / `nbf` | Enforced, `graceSeconds: 30` |
| `token_use` | `access` — both verifiers |
| Client binding | `client_id` against the permitted list |

Machine verifier is tried first: higher volume, narrower client set.

**No ID-token path exists.** Every route requires a scope, ID tokens carry none,
so an ID-token verifier could never succeed. A fallback that cannot succeed is
worse than absent — it reads as though ID tokens are accepted somewhere.

Failure reasons are not surfaced to the caller. Distinguishing "expired" from
"wrong client" from "bad signature" is an oracle.

### 3.3 Revocation

Two consistent reads against the denylist:

- `JTI#<origin_jti>` — one token family
- `SUB#<sub>` — every token for a caller

JWTs are stateless, so a valid signature says nothing about whether the token was
revoked after issuance. Cognito's `RevokeToken` invalidates tokens sharing an
`origin_jti`, and offline verification has no visibility into that. This closes
it.

**Fails closed.** An unreachable revocation store gives an unknown answer, and
"unknown" for *is this credential revoked* is not a yes. A missing `origin_jti`
is also treated as revoked — Cognito emits it on all current access tokens, so
absence means an unexpected token shape.

`ConsistentRead: true` on both. An eventually-consistent read can return a stale
miss for a token revoked seconds ago, which is precisely the window that matters.

Runs **before** the scope check and the entitlement lookup: a revoked token
should not reach a log line describing what it asked for.

### 3.4 Scope

The token's `scope` claim must contain the scope required by this method.

### 3.5 Tenant entitlement

`GetItem` on the entitlement table keyed by `client_id`, returning
`{defaultTenant, allowedTenants}`.

The token may carry `custom:tenant`. That value is a **request**, not an
assertion — on a `client_credentials` token it originates in caller-supplied
metadata at the token endpoint. Authorization is the intersection:

| Requested | Result |
|---|---|
| absent | `defaultTenant`, not delegated |
| equals `defaultTenant` | `defaultTenant`, not delegated |
| in `allowedTenants` | requested, **delegated** |
| anything else | deny |

Membership in a known-tenant set is not authorization. Entitlement is.

This is checked here even though the pre-token-generation trigger already derived
it server-side, because a claim minted at issuance is just a claim by the time it
reaches the API, and the two components are separately compromisable.

### 3.6 Policy

Allow on a **single method ARN**. Never a wildcard.

Context returned: `sub`, `clientId`, `tenantId`, `callerClass`, `scopes`,
`delegated`, `originJti`. API Gateway populates this and a caller cannot
influence it, which makes it the only sanctioned identity source downstream.

`delegated` lets the adapter emit a distinct audit event when a caller acts for a
tenant other than its own. `originJti` lets a containment runbook revoke the
exact token seen misbehaving rather than the whole subject.

*Implemented:* `src/authorizer/index.mjs`.

---

## 4. Adapter

`SafeguardExecRole`, isolated compute subnet, **no `0.0.0.0/0` route**. That
absence is the control — a security-group misconfiguration cannot create internet
access the route table does not provide.

Timeout 28s, under API Gateway's 29s integration ceiling.

### 4.1 Context adoption

Reads `$context.authorizer.*` into a frozen `req.auth`. Returns 401 if `tenantId`
or `sub` is absent.

Handlers must never read identity from a request header. This is the only
sanctioned source.

*Implemented:* `src/adapter/security.mjs` — `requestContext`.

### 4.2 Budget check

Atomic conditional `UpdateItem` on two counters:

- `TENANT#<id>` — the business limit
- `CLIENT#<id>` — because a caller entitled to several tenants would otherwise
  multiply its budget by rotating the tenant it asserts

`ADD` with a `ConditionExpression` is a single conditional write, so concurrent
invocations cannot both pass on a stale read. Breach returns 429.

This is tier 1 of the three-tier circuit breaker. Tier 2 is CloudWatch alarms on
token counts (minutes); tier 3 is Budget Actions (hours to a day). Cost Explorer
updates daily, so a runaway loop consumes a month of budget before tier 3 reacts
— tier 3 is the backstop for when tier 2's alarm was misconfigured.

*Implemented:* `src/adapter/data.mjs` — `consumeBudget`.

### 4.3 Similarity search

Aurora pgvector through RDS Proxy, 5432/tcp.

- IAM auth token, no password anywhere in the function
- `rejectUnauthorized: true` with an explicit CA bundle
- `rds.force_ssl: 1` at the engine — the one that cannot be bypassed from the
  application side
- `WHERE tenant_id = $1` as a bound parameter
- `statement_timeout` 5s at the role level, so a compromised client cannot raise
  it
- Row-level security with `FORCE` as backstop: a query omitting the predicate
  returns nothing rather than another tenant's rows

The monthly partitioning is a retention mechanism, not a tenant boundary. The
predicate and RLS are the boundary.

*Implemented:* `src/adapter/data.mjs` — `findSimilarFingerprints`;
`sql/01-bootstrap.sql`.

### 4.4 Retrieval

`bedrock:Retrieve` under an assumed `KBRetrieveRole` with `sts:ExternalId`.

The role hop is the point. A compromised adapter cannot query the corpus without
performing a distinct, CloudTrail-visible `AssumeRole` — not just another
indistinguishable data-plane call.

Tenant filter derived from the authorizer context, never from a request
parameter: a client-supplied filter is a client-supplied authorization decision.

Post-retrieval assertion on every chunk's `tenantId` metadata. A metadata filter
fails silently when the ingestion pipeline omits the attribute — it matches
nothing or everything depending on configuration, and neither produces an error.
The assertion turns that into a loud failure.

`RetrieveAndGenerate` is explicitly denied on this role. It issues an implicit
model invocation carrying no guardrail identifier, so granting it would create a
path around the enforcement condition.

*Implemented:* `src/adapter/inference.mjs` — `retrieve`; `03-identity.yaml` —
`KBRetrieveRole`.

### 4.5 Context assembly

Retrieved chunks are wrapped in `<document>` elements and never concatenated into
instruction position. An instruction embedded in a corpus document should read to
the model as quoted material, not as a command.

Truncation is by whole chunk, bounded before assembly rather than left to the
context window. Silent truncation at the window boundary can displace system
content.

*Implemented:* `src/adapter/inference.mjs` — `assembleContext`.

### 4.6 Pre-egress guardrail

`bedrock:ApplyGuardrail(source=INPUT)` before anything crosses the trust
boundary.

The Bedrock path fails closed **structurally** — an IAM condition denies the call
outright. This path is an in-code call, and an in-code call has a failure branch.
That branch is the whole control:

| Condition | Result |
|---|---|
| SDK error | throw 503 |
| Timeout or throttle | throw 503 |
| No `action` in response | throw 503 |
| `GUARDRAIL_INTERVENED` with redacted text | proceed with redaction |
| `GUARDRAIL_INTERVENED` without | throw 422 |

Callers must treat a throw as terminal. Retry with backoff is acceptable;
proceeding is not.

The egress proxy's reserved concurrency is set below the `ApplyGuardrail`
throughput limit, which converts a guardrail throttle — the fail-open pressure
point — into a queueing delay upstream.

*Implemented:* `src/adapter/inference.mjs` — `guardEgress`; `07-compute.yaml` —
`EgressProxyReservedConcurrency`.

### 4.7 Judge hop

The adapter **invokes the egress proxy as a Lambda function**, not over the
network. It has no route to the egress subnets; the hop is on the service plane.
That is what makes "the adapter cannot reach the internet" structurally true
rather than aspirational.

`EgressProxyRole` holds `ApplyGuardrail` and an explicit `Deny` on every
inference action. It can guard a model call, not make one.

Proxy → NAT → Network Firewall (FQDN allow-list, TLS SNI inspection,
`aws:drop_established` default under `STRICT_ORDER`) → judge API. 25s cap.

SNI inspection is metadata only. The firewall sees destination, never payload —
which is why redaction happens at 4.6, before this hop.

*Implemented:* `07-compute.yaml` — `EgressProxyFunction`; `01-network.yaml` —
`FirewallPolicy`, `EgressRouteTableA/B`.

---

## 5. Verdict branch

Three branches. The third is the one most designs omit.

### 5.1 `CLEAN` → inference

`Converse` against an **application inference profile ARN**, not a raw model ID.
Two independent reasons, both required: SCP 3 denies invocation where
`bedrock:InferenceProfileArn` is null, and cost allocation tags only reach the
billing record through a profile.

`guardrailConfig` pinned to `identifier:version`. A bare identifier lets a
guardrail be weakened in place with no deployment and no review — the permissions
boundary denies deletion only.

**Every content block is a `guardContent` block.** This is the counter-intuitive
part: Bedrock evaluates the whole message set only when *no* `guardContent`
blocks are present. The moment one block is tagged, evaluation narrows to tagged
blocks alone. Partial tagging is therefore the dangerous state — an untagged
block becomes a channel the guardrail never sees.

"Tag nothing" is unavailable because contextual grounding requires the
`grounding_source` and `query` qualifiers. So: tag everything.

Enforcement is three independent layers:

| Layer | Mechanism |
|---|---|
| Identity policy | Allow conditioned on `GuardrailIdentifier`, paired with an explicit `Deny` under `StringNotEquals` so no other policy can widen it |
| SCP | `Null` check denies invocation omitting the parameter |
| Endpoint policy | Restricts principal and inference profile ARN independently |

### 5.2 `SUSPICIOUS` / `ADVERSARIAL` → block

Responder never invoked.

### 5.3 Judge error, timeout, or unavailable → **also block**

Fail closed. Without this branch, inducing latency against a third-party endpoint
you do not control bypasses the entire shield — and a 25s cap under a 29s ceiling
means that attack needs only to add a few seconds.

*Implemented:* `src/adapter/inference.mjs` — `infer`; `06-bedrock.yaml` —
`Guardrail`, `GuardrailVersion`, `ResponderInferenceProfile`;
`23-scp.yaml` — `InferenceGovernancePolicy`.

---

## 6. Ledger and response

### 6.1 Ledger append

`TransactWriteItems`, partition key `TENANT#<id>` — that prefix is what
`dynamodb:LeadingKeys` binds against, so changing the key shape disables the
condition with no error.

Schema-validated with Zod. Model-derived values are confined to designated fields
and length-capped: the IAM conditions prevent writing to the wrong table, they do
not prevent writing attacker-chosen structure into the right one.

Records `promptHash`, `responseHash`, `guardrailAction`, verdict, token counts.
**Never content.** Bodies live in Bedrock model invocation logging, which lands
in the Log Archive account under `cmk/audit` with a restricted read path.

Recording the guardrail verdict alongside the hash is what makes a guarded call
and an unguarded one distinguishable after the fact.

Idempotent via `ConditionExpression` — a retry must not double-write an audit
record.

*Implemented:* `src/adapter/data.mjs` — `writeLedgerEntry`.

### 6.2 Response

`200` with the verdict and `X-Request-ID`.

Flags, reasoning, and per-stage latencies stay in the ledger. Returning them
makes the response a detection oracle: submit a variant, read which flags fired,
iterate until clean. Latencies alone are a side channel — they reveal which stage
rejected.

Errors return a correlation ID and an error class, never a message. `err.code`
carries classes; `err.message` carries values like table names and ARNs.

*Implemented:* `src/adapter/security.mjs` — `errorHandler`.

**→ Response back up the same three hops.**

---

## 7. Timing budget

API Gateway's integration timeout is **29 seconds, hard**.

| Component | Budget |
|---|---|
| Judge cap | 25s |
| Egress proxy timeout | 26s |
| Adapter timeout | 28s |
| API Gateway ceiling | 29s |

That leaves roughly 3 seconds for the authorizer, budget check, pgvector query,
guardrail call, `Converse`, and ledger write combined.

**An attacker who slows the judge to 24s forces 504s across the board** without
producing a single judge error. This is why the alarm in layer 10 watches p95
duration against a threshold below the cap, not error rate.

---

## 8. Outside the request path

Asynchronous, and easy to forget when reasoning about the flow.

| Stream | Path |
|---|---|
| Ledger TTL deletions | DynamoDB Streams (filtered to `REMOVE`) → lifecycle function → erasure receipts in Log Archive |
| Aurora partition rotation | EventBridge monthly → lifecycle function → `pg_cron` drop |
| Bedrock invocation logs | CloudWatch → Firehose → Log Archive under `cmk/audit` |
| WAF and Network Firewall logs | Firehose → Log Archive, `authorization` redacted |
| Backups | Plan → local vault → copy to Backup account vault |
| Secrets rotation | Secrets Manager schedule → rotation function → DB creds and `x-origin-verify` |

TTL deletions arrive as `REMOVE` records with `userIdentity` set to the DynamoDB
service principal, which is how an expiry is distinguished from an application
delete. The receipt is the provable record of what was deleted and when — TTL
alone produces none.

---

## 9. Failure modes by step

What a caller sees, and what it means.

| Step | Failure | Response | Note |
|---|---|---|---|
| 1.2 | TLS below 1.2 | connection reset | No log anywhere |
| 1.3 | Edge WAF block | 403 / 405 / 429 | Edge WAF log only |
| 2.1 | Missing `x-origin-verify` | 403 | Direct-to-API-Gateway attempt |
| 2.2 | Wrong `SourceArn` | 403 | Backstop for the above |
| 2.3 | Stage throttle | 429 | No per-caller attribution |
| 3.1 | Unknown route | 401 | Denied before token parse |
| 3.2 | Any token defect | 401 | Reason not disclosed |
| 3.3 | Revoked, or store unreachable | Deny | Fails closed |
| 3.4 | Insufficient scope | Deny | |
| 3.5 | Tenant not entitled | Deny | |
| 4.2 | Budget exhausted | 429 | Tier 1 breaker |
| 4.4 | Cross-tenant chunk returned | 500 | Filter misconfiguration — loud by design |
| 4.6 | Guardrail unavailable | 503 | Fails closed |
| 4.6 | Guardrail intervened, no redaction | 422 | |
| 5.3 | Judge unavailable | 503 | Fails closed |
| 7 | Total time exceeds 29s | 504 | Watch judge p95, not error rate |

Every one of these is a deny or a stop. There is no step in this flow whose
failure mode is "continue."

---

## 10. Known gaps in the flow

Carried from the threat model and audit, unresolved:

- **Corpus ingestion has no content validation.** The KB source bucket restricts
  writers; nothing validates what they write. Anything landing there is chunked,
  embedded, and served as grounding context at 4.4. This is the highest-yield
  injection route and it bypasses 4.6 entirely, because the content is already
  inside the boundary.
- **Output handling is unspecified** because the downstream consumer of the
  response is unstated. Browser rendering, datastore write, and pass-through to
  another system each need a different control at 6.2.
- **Bearer tokens are not sender-constrained.** Possession is sufficient at 3.2.
  Cognito does not support DPoP; closing this needs mTLS at CloudFront or a
  different IdP.
- **Third-party retention is contractual only.** Once a payload reaches the judge
  at 4.7, that provider's logging governs it. Redaction at 4.6 and the payload
  hash in the ledger are the only technical controls, and both are pre-egress.
