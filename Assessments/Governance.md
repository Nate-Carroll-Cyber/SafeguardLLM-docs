# Agent Governance & Control-Plane Assessment — Secure Generative AI Workload

**Objective:** Assess the target-state architecture in this repository against the
control-plane standard: human-linked authentication, identity chain integrity,
ephemeral credentialing, fine-grained authorization, and lifecycle governance
through a unified control plane.

**Assessment date:** 2026-08-03
**Source of record:** this repository — 19 CloudFormation templates across six
accounts, four source modules, SQL bootstrap, CI configuration
**Deployment state:** none. `cfn-lint` clean; no stack deployed, no runtime
behaviour observed.

---

## Executive Summary

This system is not an agent, and that fact drives the assessment more than any
individual control.

The model invokes nothing. There is no orchestration framework, no planning loop,
no tool registry, no sub-agent delegation. `RetrieveAndGenerate` and `InvokeAgent`
are explicitly denied at the role level; retrieval and generation are separate,
sequential calls made by deterministic application code. Several control-plane
concerns that dominate agent governance — agent-to-agent identity, autonomy
scoping, tool-invocation authorization — have no surface here, and marking them
"absent" would misdescribe the system.

What the architecture *is* is a **multi-tenant inference gateway that other
people's agents consume as a tool.** MCP tool callers are a first-class caller
class with their own OAuth client and scopes. In control-plane terms the
organization is a **tool provider**, and that role is the least-governed thing in
the design: there is no registry of consuming systems, no tool contract, no
per-consumer credential lifecycle, and no defined responsibility boundary.

Identity engineering is strong and, in one respect, unusually so — the tenant
claim is derived server-side at issuance and re-verified as an entitlement at
use, which closes the confused-deputy path that multi-tenant machine callers
normally open. Credential handling is genuinely ephemeral: no database password
exists anywhere, and no secret appears in a Lambda environment variable.

The load-bearing gaps are **ownership and intent** (thirteen workload identities,
zero accountability records), **asynchronous human authorization** (none, for
operations that shape every future response), and **corpus governance** (writers
are restricted, content is not — the one path into the model that bypasses every
pre-egress control).

Governance maturity snapshot:

| Control domain | Current state | Target state | Gap severity |
|---|---|---|---|
| Human identity tethering | Per-request OIDC validation on every route; signature against pinned JWKS; access tokens only | Same | **None** |
| Identity chain integrity | Correlation ID and tenant stamped downstream; no token exchange; `sub` is a client ID on the machine path | Token exchange preserving end-user identity for multi-tenant callers | **Medium** |
| Credential vaulting | Secrets Manager under a dedicated CMK; no secret in any environment variable; IAM database auth | Same | **None** |
| Ephemeral credentialing / rotation | 15-min tokens, ~15-min RDS IAM tokens, rotation infrastructure defined | Rotation function implemented and exercised | **Medium** (code, not design) |
| Fine-grained / relationship-based authz | Scope per method, tenant entitlement, `LeadingKeys`, RLS with `FORCE`, retrieval metadata filter | Same, extended when corpus operations are added | **Low** |
| Async human-in-the-loop (CIBA/RAR) | None. Containment exists; authorization does not | Backchannel approval for guardrail and corpus changes | **High** |
| Agent/component registry | Thirteen named IAM roles; no owner, intent, or egress record | Registry doubling as Service BOM | **High** |
| Shadow AI discovery | Enforcement strong (no default route, FQDN chokepoint); reconciliation absent | Egress enumerated and reconciled against a registry | **Medium** |
| Universal logout / revocation | `origin_jti` and `sub` denylist, consistent read, fails closed | Writer implemented; runbook exercised | **Low** |
| Lifecycle (onboarding/review/deprovision) | Data lifecycle implemented; identity lifecycle absent | Access review and deprovisioning over the entitlement table | **Medium** |
| **Tool-provider governance** | Consuming systems undefined; no contract, no registry, no per-consumer isolation | Documented boundary, per-consumer credentials and limits | **High** |

---

## Phase 1 — Identity & Access Design

### 1.1 Human identity tethering

**Current.** Two Cognito app clients on one user pool: humans use authorization
code + PKCE, machine callers use `client_credentials` against a resource server
with `llm/invoke` and `llm/retrieve` scopes. A REQUEST Lambda authorizer runs on
every uncached request and verifies signature, `iss`, `exp`, `nbf`, `token_use`,
client binding, and scope-per-method with deny-by-default on unmapped routes.

Two implementation details carry real weight:

**The JWKS is resolved from the issuer derived from configuration, never from the
`iss` inside the presented token.** That distinction is the difference between
key pinning and signature forgery, and it is the single most common failure in
hand-rolled JWT verification.

**The policy cache key is per-method.** `IdentitySource` includes `httpMethod`
and `resourcePath`, and the returned policy names one method ARN. A TOKEN
authorizer keyed only on the token would cache one decision across every route,
and a wildcard resource in that cached policy silently disables the scope check
from the second request onward — with no error and no symptom.

**Governance finding.** Identity tethering is complete on the human path. On the
machine path it is complete for the *client* and absent for the *end user*: `sub`
on a `client_credentials` token is the app client ID, not a person. Where a
single MCP server serves multiple end users, no verified human identity reaches
this system at all.

The architecture compensates rather than solves — the tenant claim (§1.3) gives
per-tenant attribution, which is coarser than per-user and is the correct
granularity for rate limiting and cost, but not for accountability.

**Recommendation.** Where an MCP consumer is multi-tenant, require token exchange
(RFC 8693) so the end-user subject crosses the boundary, or accept explicitly and
in writing that attribution stops at the consuming organization. The second is a
legitimate choice; the current state is the third option, where it is unstated.

### 1.2 Identity chain integrity across downstream calls

**Current.** Three downstream classes:

| Path | Identity carried |
|---|---|
| Bedrock inference | `requestMetadata` with tenant, client ID, correlation ID, delegation flag |
| Knowledge base retrieval | `KBRetrieveRole` assumed with `sts:ExternalId`; session tags carry the correlation ID |
| Third-party judge | System credential from Secrets Manager; payload hash ledgered |

The role-assumption hop is the strongest link in the chain. Reaching the corpus
requires a distinct `AssumeRole` event that is separately visible in CloudTrail —
a compromised adapter cannot query the vector store as a side effect of already
running, and the assumption is alarmable in a way that another data-plane call is
not.

**Governance finding.** The chain is intact within the AWS boundary and breaks at
the third-party judge, as it must for an opaque provider. The compensating
control is correct in shape — a payload hash is ledgered pre-egress so a
provider-side abuse report can be reconciled — but incomplete: **the ledger
records the hash and the guardrail verdict, not the model identity or version.**
A provider that silently changes the model behind its endpoint is undetectable
after the fact.

**Recommendation.** Record model identity and version alongside the payload hash
on the external path. Where an internal service is added later (a split
retrieval service, a second inference tier), use token exchange rather than a
shared service credential — the pattern is easier to establish before there is
one to migrate.

### 1.3 Relationship-based / fine-grained authorization

**Current.** Authorization is enforced at four layers, and they are not
redundant:

| Layer | Mechanism | Failure mode |
|---|---|---|
| API | Scope per method, deny-by-default on unmapped routes | 403 |
| Identity | `dynamodb:LeadingKeys` bound to `TENANT#` prefix | AccessDenied |
| Query | `tenant_id` as a bound parameter | No rows |
| Storage | Postgres RLS with `FORCE ROW LEVEL SECURITY` | No rows |
| Retrieval | Knowledge base metadata filter plus post-retrieval assertion | 500, loudly |

`FORCE` matters: without it the table owner bypasses the policy. A query that
omits the tenant predicate returns nothing rather than another tenant's rows.

The retrieval assertion is the one I would call out as good practice rather than
adequate practice. A metadata filter fails *silently* when the ingestion pipeline
omits the attribute — it matches nothing or everything depending on configuration,
and neither produces an error. Asserting the tenant on every returned chunk turns
a silent isolation failure into a 500.

**Governance finding — the strongest control in the design.** The tenant claim is
derived **server-side at issuance** by a pre-token-generation trigger that reads
an entitlement table keyed on client ID and deliberately ignores
`aws_client_metadata`, then **re-verified as an entitlement at use** by the
authorizer.

Cognito passes client metadata from the token endpoint straight through to that
trigger. A tenant read from that metadata is a value the caller chose. Deriving
it makes the claim a fact; reading it would make it an assertion — and an
assertion validated only for *membership in a known tenant set* is the
confused-deputy pattern, where every credential is valid, the authorization
decision is wrong, and the audit trail faithfully records the attacker's claim.

The double check is not redundancy. The trigger and the authorizer are separately
compromisable, and a claim minted at issuance is just a claim by the time it
reaches the API.

**Recommendation.** Two scopes exist because two operations exist. When corpus
management is added — promotion, labeling, deletion — its scopes must be defined
with it. The knowledge base source bucket currently restricts writers by IAM
principal, which is a deployment-time control, not an authorization model, and it
will not survive the addition of a human-facing curation workflow.

---

## Phase 2 — Operations & Control Plane

### 2.1 Credential vaulting

**Current.** Secrets Manager under `cmk/secrets`, with three properties worth
stating separately because each closes a different failure:

**No secret appears in a Lambda environment variable.** Those are readable by
anyone holding `lambda:GetFunctionConfiguration` — a permission commonly granted
with read-only roles. The third-party API key is referenced by secret *name* and
fetched at runtime.

**No database password exists to leak.** RDS Proxy with `IAMAuth: REQUIRED` means
the client presents a short-lived IAM token; the proxy holds the master secret
for its own connection to the cluster. There is no password path from the
application at all — this is stronger than vaulting a password well.

**No secret can reach a log or a model.** Application telemetry carries prompt
hashes only. WAF logs redact `authorization` and `x-origin-verify` — without
that, a bearer token is written in full on every blocked request, into an
immutable bucket where it cannot be removed. The guardrail's sensitive-information
filter BLOCKs rather than anonymizes credentials (`PASSWORD`, `AWS_ACCESS_KEY`,
`AWS_SECRET_KEY`, plus regex for bearer tokens and PEM headers) on the reasoning
that a redacted credential is still a credential the model was shown.

**Governance finding.** No gap.

### 2.2 Ephemeral credentialing & rotation

**Current.**

| Credential | Lifetime | Mechanism |
|---|---|---|
| Access token | 15 min | Cognito, configurable |
| Refresh token | 1 day, rotated on use | Cognito refresh rotation |
| RDS auth token | ~15 min | Signed per connection |
| `KBRetrieveRole` session | 1 hour max | `sts:AssumeRole` |
| DB master secret | Rotation function defined | Secrets Manager schedule |
| `x-origin-verify` | Rotation function defined | Dual-value overlap |

Refresh rotation makes a stolen refresh token detectable: the legitimate client's
next refresh fails.

The `x-origin-verify` rotation is the operationally interesting one. It must
update the CloudFront origin custom header **and** the regional WAF rule in a
single operation with an overlap window, or in-flight requests are rejected
mid-rotation. Splitting them opens a window where the header does not match the
rule and the API is down.

**Governance finding.** The design is sound and **the rotation function is not
written.** A rotation schedule pointing at a function that does not exist is
worse than no schedule — it will fail on first invocation, and the alarm for that
failure is one of the few in layer 10 that fires on something genuinely
unrecoverable, since a partially-rotated secret leaves the API unreachable.

**Recommendation.** Write the rotation function before enabling the schedule, and
exercise it once in a non-production environment. The four-step Secrets Manager
rotation contract (`createSecret`, `setSecret`, `testSecret`, `finishSecret`) has
a failure mode at `finishSecret` that only surfaces under real invocation.

### 2.3 Central agent/component registry

**Current.** Thirteen IAM roles with enumerated permissions, explicit conditions,
named trust relationships, and no wildcards in resource ARNs. Every role is
reachable only by a named principal or service.

**Governance finding — one of the two highest-severity gaps.** An IAM role is a
*workload identity*. It answers "what may this call." It does not answer "who
decided that, and why, and who is accountable when it is wrong." There is no
record anywhere of:

- the human owner of each component
- its documented purpose and intended data classifications
- its approved egress set
- when its permissions were last reviewed, and by whom

This is not a paperwork observation. Three concrete things are blocked by its
absence: Shadow AI reconciliation has nothing to reconcile *against* (§3.1);
access review has no baseline to certify (§3.3); and the Service BOM required for
supply-chain governance is the same artifact viewed from a different angle.

**Recommendation.** Build one registry serving all three purposes. Minimum
columns: workload identity (role ARN), human owner, purpose, allowed egress FQDNs,
data classifications touched, upstream and downstream dependencies, last review
date. Version it in this repository next to the templates, so a role added without
a registry entry fails code review rather than passing silently.

**Include the consuming MCP servers as first-class entries.** They hold
credentials to this system and are the least-visible identities in the design.

### 2.4 Async human-in-the-loop (CIBA / RAR)

**Current.** Containment exists and is well built:

| Mechanism | Latency | Scope |
|---|---|---|
| WAF blocked-identity set | Immediate, not cached | One identity |
| Revocation denylist | One cache TTL | One token family or one subject |
| Reserved concurrency to zero | Immediate | One function |
| Budget Actions | Hours | Non-critical tenants |

**Governance finding — the other highest-severity gap.** Every mechanism above is
*containment*. None is *authorization*. There is no operation in this system that
requires a human to approve it before it takes effect.

The operation that most needs it is **guardrail configuration change**, and the
reason is specific. Weakening a guardrail is not deleting it:

- The permissions boundary denies `bedrock:DeleteGuardrail` and says nothing about `UpdateGuardrail`
- Lowering a filter threshold passes `cfn-guard`, passes `checkov`, and satisfies every policy check
- All three enforcement layers continue reporting success, because the guardrail still exists at the pinned identifier
- The only signal is a drop in intervention rate — which is indistinguishable from a quieter attack environment

Today the compensating controls are a two-person approval gate in the pipeline (a
process control, defeated by collusion or by one person with two identities) and
an anomaly alarm on intervention rate (a lagging signal, measured in hours).

The second candidate is **corpus promotion**. Content entering the knowledge base
is served as grounding context to every subsequent request. It is the highest-
consequence write in the system and currently has no approval step at all — see
§3.4.

**Recommendation.** Implement CIBA with Rich Authorization Requests for:

1. Guardrail configuration changes, with the RAR payload naming the specific
   filter and threshold being changed so the approver sees the delta, not a
   commit hash
2. Corpus promotion, naming the document and its source
3. Entitlement table writes — adding a tenant to `allowedTenants` grants
   cross-tenant access and is a single `PutItem`

Keep the existing containment as the containment layer. Approval is a different
control and does not replace it.

---

## Phase 3 — Monitoring, Lifecycle & Revocation

### 3.1 Shadow AI discovery

**Current.** The enforcement half is strong. Compute has no default route at all;
the only path outward is a dedicated egress proxy in its own subnet, reached by
Lambda invoke rather than by routing. All egress traverses a single Network
Firewall chokepoint with an FQDN allow-list and TLS SNI inspection, defaulting to
`aws:drop_established` under `STRICT_ORDER` — without strict order the default is
to *pass* unmatched traffic, which inverts an allow-list into a suggestion.

An unregistered inference endpoint cannot be reached from this architecture.

**Governance finding.** Enforcement without reconciliation. There is no workflow
that enumerates actual egress and compares it to an approved set. The specific
risk is not an attacker adding an allow-list entry — that requires the deployment
role — but a **legitimate entry added for a legitimate reason and never removed**.
Allow-lists accrete. Nothing in this design causes an unused entry to surface.

The data now exists: firewall flow and alert logs land in the Log Archive account
via Firehose. The reconciliation does not.

**Recommendation.** A scheduled job that reads firewall flow logs, extracts
distinct destinations, and diffs them against the registry from §2.3. Two finding
types: a destination not in the registry (should be impossible; if it happens,
something is very wrong), and a **registry entry with no observed traffic in 90
days** — the one that actually fires, and the one that keeps the allow-list from
growing monotonically.

### 3.2 Centralized visibility

**Current.** Telemetry is well-separated by sensitivity, which is uncommon:

| Stream | Content | Destination |
|---|---|---|
| Application spans | Prompt hashes, verdicts, token counts — never content | CloudWatch / X-Ray |
| Model invocation logs | Prompt and completion bodies | Log Archive, `cmk/audit`, investigation role only |
| CloudTrail Org Trail | API activity plus data events | Log Archive, Object Lock compliance mode |
| WAF and firewall | Request metadata, credentials redacted | Log Archive via Firehose |

The audit layer meets the audit-grade criterion — tamper-evident via Object Lock,
retained, segregated from the execution environment, queryable. That is
genuinely uncommon and worth preserving through any future change.

**Governance finding.** Detection is **content-blind in the fast path**. Spans
carry hashes, so semantic anomaly detection, coordinated prompt patterns across
identities, and slow-burn extraction have no near-real-time surface. Content
analysis requires assuming a restricted role in a different account.

This is a deliberate trade and the right one — but it has a consequence nobody
usually plans for: **time-to-content during an incident is unmeasured.** The
access path exists on paper and has never been exercised.

**Recommendation.** Rehearse the investigation-role access path and record the
elapsed time as an incident-response metric. Separately, emit non-content derived
signals into the fast path that support semantic detection without disclosing
anything: guardrail sub-verdicts by category, retrieval chunk IDs,
embedding-distance outliers.

### 3.3 Lifecycle

**Current.** Data lifecycle is implemented and thought through:

- Ledger content TTL 30 days, metadata TTL 400 days, on separate attributes
- Fingerprint partitions dropped monthly by schedule — a partition drop is
  instantaneous, where a bulk `DELETE` on a vector table leaves index bloat and
  forces a `VACUUM` window that Serverless v2 absorbs poorly
- Erasure receipts written from Streams, giving a provable record of what expired
  and when, which TTL alone does not produce
- Embeddings bound to source with re-sync required on deletion

The design is also honest about TTL's limits: deletion is asynchronous, items
remain readable for up to 48 hours after expiry, and the adapter filters at read
time so behaviour matches policy even when the deletion has not landed. It is
correctly documented as a hygiene mechanism rather than a compliance-grade
deletion guarantee.

**Governance finding.** Identity lifecycle is entirely absent. No access review,
no certification cadence, no deprovisioning workflow, no joiner-mover-leaver
process for either human or machine principals.

The entitlement table is the obvious anchor — it holds the authoritative
`clientId → {defaultTenant, allowedTenants}` mapping and is the highest-integrity
data in the workload account. Nothing reviews it. An `allowedTenants` entry added
for a temporary integration persists indefinitely, and the delegation it permits
is invisible unless someone reads the table.

**Recommendation.** Quarterly certification over the entitlement table and the
IAM role set, owner-attested from the §2.3 registry. Emit a Security Hub finding
for any entitlement row not certified in the current period — a review nobody
performs is not a control, and the finding is what makes the omission visible.

### 3.4 Corpus governance

**Not a domain in the standard control-plane taxonomy.** It belongs here because
in a retrieval-augmented system the corpus is an authorization surface, not just a
data store.

**Current.** The knowledge base source bucket restricts *writers* by IAM
principal, enforces TLS, and requires SSE-KMS. Data source deletion policy is
`RETAIN`, deliberately — an embedding derived from personal data is personal
data, so deletion must be a decision rather than a side effect of a stack change.

**Governance finding — highest-yield gap in the system.** Nothing validates *what*
those writers write. Anything landing in that bucket is chunked, embedded, and
served to the model as grounding context.

The severity comes from where it lands in the request path. Every other injection
route passes `ApplyGuardrail` before the trust boundary. **Corpus content is
already inside the boundary** — it arrives as grounding material with the same
standing as legitimate context, and it reaches a compute identity holding
`dynamodb:PutItem` and `s3:PutObject`. A content-injection becomes a
state-changing action.

**Recommendation.**

1. Define the ingestion path as an explicit trust boundary with named approvers
2. Validate content before indexing; attach provenance metadata to every chunk
3. Gate promotion behind the CIBA approval in §2.4
4. Add poisoned-document canaries alongside the synthetic PII canaries — inject a
   document containing a benign marker instruction and assert the model never
   acts on it

### 3.5 Universal logout / revocation

**Current.** Three surfaces at different latencies, described in §2.4.

The revocation denylist is the notable one because it closes a gap that stateless
tokens structurally create: a valid signature says nothing about whether the token
was revoked after issuance, and Cognito's `RevokeToken` is invisible to offline
verification. Two key shapes — `JTI#<origin_jti>` for one token family,
`SUB#<sub>` for every token a caller holds.

Three implementation choices matter:

**Fails closed.** An unreachable revocation store gives an unknown answer, and
"unknown" for *is this credential revoked* is not a yes. A missing `origin_jti`
is treated the same way — Cognito emits it on all current access tokens, so
absence means an unexpected token shape.

**Consistent reads.** An eventually-consistent read can return a stale miss for a
token revoked seconds ago, which is exactly the window that matters.

**Checked before authorization.** A revoked token does not reach a scope check,
an entitlement lookup, or a log line describing what it asked for.

**Governance finding.** The read path is implemented. **No writer exists.** The
containment runbook holds `PutItem` permission and the function is not written,
so today the denylist is a table nothing populates.

**Recommendation.** Implement the writer as part of the containment runbook, with
the TTL set to the token's own expiry so a row disappears exactly when checking it
stops mattering. Exercise it once end to end — the meaningful test is that a
revoked token is rejected on the *second* request as well as the first, which is
the authorizer cache test.

---

## Prioritized Remediation Roadmap

| Priority | Action | Domain | Closes |
|---|---|---|---|
| P0 | Corpus ingestion validation and provenance before indexing | Corpus governance | §3.4 — bypasses every pre-egress control |
| P0 | Implement the revocation writer; exercise end to end including the cache test | Revocation | §3.5 — read path without a write path |
| P0 | Write and exercise the secrets rotation function before enabling its schedule | Ephemeral creds | §2.2 — a schedule pointing at nothing |
| P1 | Component registry: owner, intent, egress, review date. Include consuming MCP servers. Double as the Service BOM | Registry | §2.3, and unblocks §3.1 and §3.3 |
| P1 | CIBA + RAR for guardrail configuration, corpus promotion, and entitlement writes | Async HITL | §2.4 — no authorization control exists, only containment |
| P1 | Adversarial regression corpus as a blocking pipeline gate on guardrail changes | Async HITL | §2.4 — converts a lagging signal into a test |
| P1 | Define the tool-provider boundary: contract, per-consumer credentials, per-consumer limits | Tool provider | Executive summary — least-governed relationship in the design |
| P2 | Record model identity and version on the external inference path | Identity chain | §1.2 — silent provider-side model change |
| P2 | Egress reconciliation: flow logs diffed against the registry, alerting on unused entries | Discovery | §3.1 — allow-lists accrete |
| P2 | Quarterly entitlement and role certification, owner-attested, with a finding for uncertified rows | Lifecycle | §3.3 |
| P2 | Rehearse investigation-role access; record time-to-content as an IR metric | Visibility | §3.2 |
| P3 | Token exchange (RFC 8693) for multi-tenant machine callers | Identity chain | §1.1 — end-user identity does not cross the boundary |
| P3 | Sender-constrained tokens via mTLS or an alternate IdP | Identity | Bearer possession is sufficient; Cognito lacks DPoP |

---

## Strengths to Preserve

Controls consistent with the standard, worth protecting through any future
change:

**Structural network isolation.** Compute has no default route. Every AWS service
call resolves to a VPC endpoint, and `aws:SourceVpce` makes that path a condition
of authorization rather than a convention. This is stronger than restricting
destinations — it removes the path.

**The egress proxy asymmetry.** It holds `ApplyGuardrail` and an explicit deny on
every inference action. It can guard a model call, not make one. The adapter can
make one and cannot reach the internet. Neither component alone can send an
unguarded payload outside the boundary.

**Server-side tenant derivation with re-verification at use.** The single best
decision in the design. It closes the confused-deputy path that multi-tenant
machine callers normally open, and it does so at both ends of the token's life.

**Guardrail enforcement in three independent layers.** Identity policy with a
paired explicit `Deny`, org SCP null check, and endpoint policy — all three must
be misconfigured before an unguarded call lands. The role split that makes this
work also resolves the `RetrieveAndGenerate` interaction, which most
guardrail-enforcement designs discover after deployment rather than before.

**No excessive agency, structurally.** The model invokes nothing. This is the
failure mode most systems back into by adding tool use incrementally, and this
one forecloses it by construction rather than by policy. **Preserve it
deliberately** — the day tool use or Bedrock Agents are introduced, this
assessment and the MAESTRO threat model both require re-scoping rather than
extension.

**Fail-closed everywhere.** Every failure mode in the request path is a deny or a
stop. There is no step whose failure mode is "continue."

**Audit outside the blast radius.** No workload-account principal can reach the
audit bucket, the backup vault, or their keys. The invocation-log prefix is
readable only by a named investigation role, in either the Security or Log
Archive account — narrowed deliberately, with the consequence that no local
administrator can read it either.

---

## Assessment Limitations

Stated because a governance assessment that overstates its own basis is the
failure it exists to prevent.

**Nothing has been deployed.** Every finding derives from templates and source
code. `cfn-lint` validates schema and intrinsic functions, not runtime behaviour.
IAM condition evaluation, endpoint policy enforcement, firewall rule matching,
and the Bedrock and S3 Vectors resource types are unverified.

**Five functions are unwritten** — egress proxy, secrets rotation, lifecycle,
pre-token-generation (placeholder inline), and the Express handler wiring the
adapter modules. Controls depending on them are assessed as designed, not as
operating.

**The consuming MCP systems are entirely unknown.** Who operates them, whether
they are first- or third-party, how they store the client secret, and whether
they hold per-end-user tokens are all unstated. The tool-provider findings
describe an undefined boundary, not a quantified exposure.

**The use case is unstated.** What consumes the model output, and whether any
consequential decision follows from it, is not documented anywhere. That question
blocks the AI impact assessment, the human-oversight definition, and the
output-handling control in the AppSec audit — and without it, regulatory exposure
is not calculable.

---

*Prepared using the Agent Governance Architect skill. Items marked "not written"
or "not implemented" reflect this repository's own stated status; they are
remediation targets, not assertions that the design is unsound.*
