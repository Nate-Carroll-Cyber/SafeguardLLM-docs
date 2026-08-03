# Application Security Audit — Secure Generative AI Workload on AWS

**Target:** `aws-secure-genai-workload-architecture.md`
**Lens:** AppSec / OWASP LLM Top 10 (2025), full development lifecycle
**Date:** 2026-07-31

---

## 1. Headline

The specification describes infrastructure in depth and the application almost not at all.

Seven accounts, twelve SCPs, thirteen IAM roles, eight KMS keys, a three-tier subnet model, and a three-role deployment chain are specified to the level of individual condition keys. The **Express Adapter** — the component that assembles the prompt, calls the model, holds `dynamodb:PutItem` and `s3:PutObject`, and decides what the caller gets back — appears as one line in a subnet table.

That asymmetry is the finding. Every control the specification is proud of terminates at the adapter's front door. Prompt assembly, output handling, error masking, CORS, input validation, dependency integrity, and log discipline are the layer where the guardrail's effective coverage is actually determined, and none of it is written down.

Section 4 delivers hardened implementations for that layer. Section 5 lists what the specification says that the code contradicts or must supersede.

---

## 2. Asset Map

**Entry points**

| Surface | Auth | Exposure |
|---|---|---|
| `POST /v1/inference` (API Gateway REST) | Cognito JWT via Lambda authorizer | Public via CloudFront |
| `POST /v1/retrieve` | Same, distinct scope | Public via CloudFront |
| CloudFront → S3 static assets | OAC + SigV4 | Public |
| GitHub Actions → AWS | OIDC federation | Public repo host |

**Data connections**

| Store | Path | Credential |
|---|---|---|
| Aurora PostgreSQL (pgvector) | RDS Proxy, 5432/tcp | IAM auth token — no password |
| DynamoDB ledger | Gateway endpoint | Task role, `LeadingKeys`-conditioned |
| DynamoDB budget counters | Gateway endpoint | Task role |
| S3 app bucket | Gateway endpoint | Task role, SSE key pinned |
| Secrets Manager | Interface endpoint | Task role |

**LLM entry points**

| Path | Guardrail posture |
|---|---|
| Bedrock `Converse` via inference profile | Enforced by IAM condition + SCP + endpoint policy |
| `bedrock-mantle` (OpenAI-compatible) | **Enforcement mechanism unspecified** — the `GuardrailIdentifier` condition applies to `InvokeModel`/`Converse` on `bedrock-runtime` |
| `bedrock-agent-runtime` `Retrieve` | No guardrail specified at retrieval |
| External inference via egress proxy | `ApplyGuardrail` in application code — failure branch unspecified |

The two rightmost rows are where the specification's "three independent enforcement layers" claim stops holding. Only the first path has all three.

---

## 3. Vulnerability Analysis

Findings are ordered by exploitability. `[FIXED]` means an artifact in Section 4 closes it; `[OPEN]` means it requires a decision or an artifact outside this delivery.

### A-01 — Partial guardrail tagging creates an unevaluated channel `[FIXED]`

§18.1 of the specification records input tagging as an accepted residual risk: "input tags let a caller mark which prompt sections are evaluated."

This is resolvable, and the mechanism is counter-intuitive. Bedrock evaluates **all** messages when **no** `guardContent` blocks are present. The moment any block is tagged, evaluation narrows to tagged blocks alone. So the risk is not tagging — it is *partial* tagging, where an untagged block becomes a channel the guardrail never sees.

"Tag nothing" is not available, because contextual grounding requires `grounding_source` and `query` qualifiers to score the response. The only safe posture is **tag everything**: system prompt, retrieved context, and user query each as a `guardContent` block.

`src/adapter/inference.mjs` implements this. §18.1 should be rewritten from an accepted risk to an implementation requirement.

### A-02 — Retrieval is not tenant-scoped `[FIXED]`

The `Retrieve` API supports a metadata filter in `retrievalConfiguration.vectorSearchConfiguration.filter`, and separately a `userContextData` parameter for access-control filtering. The specification uses neither, while giving DynamoDB `LeadingKeys` and Aurora a partition scheme.

`inference.mjs` applies a tenant filter derived from the authorizer context, plus a post-retrieval assertion that every returned chunk carries the expected tenant. The assertion exists because a metadata filter fails silently when the ingestion pipeline omits the attribute — the filter matches nothing, or matches everything, depending on configuration, and neither produces an error.

### A-03 — Tenant identity is asserted, not entitled `[FIXED]`

§4.6 validates the tenant claim "against a known tenant set." Membership is not authorization. On a `client_credentials` token the claim originates in client-supplied metadata at the token endpoint, so a client provisioned for tenant A can request tenant B and be validated successfully.

`src/authorizer/index.mjs` resolves tenant against an authoritative `clientId → {defaultTenant, allowedTenants}` mapping and emits a `delegated` flag when a caller acts for a tenant other than its own.

### A-04 — Authorizer cache scope `[FIXED]`

A REQUEST authorizer returning a wildcard resource caches an over-broad policy against a scope-limited token. The first request from a token holding only `llm/retrieve` caches a policy covering every method, and the scope check stops applying with no visible symptom.

The authorizer returns a single method ARN. `ci/deploy.yml` includes a regression test asserting this, because the failure mode is invisible in normal use and a future refactor would reintroduce it silently.

### A-05 — `ApplyGuardrail` failure branch `[FIXED]`

The Bedrock path fails closed structurally — an IAM condition denies the call. The egress path is an in-code call, and an in-code call has a failure branch. If it proceeds on throttle or timeout, an attacker who drives concurrency obtains unredacted egress to a third party.

`guardEgress()` throws on error, on timeout, and on a missing verdict. Callers must treat the throw as terminal; retry is acceptable, proceeding is not.

### A-06 — Output handling is entirely unspecified `[OPEN]`

OWASP LLM05. The specification never states what consumes the model response. Three destinations, three different exposures:

- **Rendered in a browser** — model output is untrusted HTML. Sanitize server-side (DOMPurify with a strict allowlist, or return plain text with a `Content-Type` that forbids interpretation) before it reaches a template.
- **Written to a datastore** — model output must not determine record structure. `data.mjs` constrains this with a strict schema and a single bounded free-text field.
- **Passed to a downstream system** — this is excessive agency (LLM06) and needs a human-in-the-loop gate on any consequential action.

This is the highest-priority open item, because the correct control cannot be chosen without knowing the destination.

### A-07 — Guardrail version pinning `[FIXED, requires policy change]`

If the `bedrock:GuardrailIdentifier` condition pins a bare identifier rather than `identifier:version`, a guardrail edited in place takes effect with no deployment and no review. Weakening is then invisible to the pipeline and to the permissions boundary, which denies deletion only.

`inference.mjs` requires `GUARDRAIL_VERSION` and refuses to start without it. **The corresponding IAM condition must also pin the numeric version** — code alone cannot enforce this, since a compromised adapter chooses its own parameters.

### A-08 — Budget evasion by tenant rotation `[FIXED]`

The tier-1 token budget keys on caller identity. A machine caller entitled to several tenants multiplies its budget by rotating the tenant it asserts. `consumeBudget()` charges both a per-tenant and a per-client counter, atomically, via conditional `UpdateItem` — a read-then-write would let concurrent invocations both pass a stale check.

### A-09 — TLS verification on the database path `[FIXED]`

RDS IAM authentication is specified. Certificate verification is not. `rejectUnauthorized: false` is the standard way an otherwise-correct IAM auth setup becomes a man-in-the-middle target inside the VPC — the token is short-lived, but the session it authenticates is not protected by anything else. `data.mjs` sets `rejectUnauthorized: true` with an explicit CA bundle.

### A-10 — CORS `[FIXED]`

The specification serves a SPA from CloudFront and an API from API Gateway and never mentions cross-origin policy. `security.mjs` restricts to an exact origin allowlist, permits `POST` only, and sets `credentials: false` — the token travels in `Authorization`, so cookie credentials should never be in play.

### A-11 — Error and log disclosure `[FIXED]`

Unmasked AWS SDK errors leak table names, role ARNs, model identifiers, and KMS key IDs. The terminal handler in `security.mjs` returns a correlation ID and an error class, never a message.

Separately: the specification commits telemetry to "prompt hashes only," but says nothing about application logs. A `console.log` in a Lambda writes to a workload-account log group — the one log destination in this architecture that is *not* restricted-access. The build step in `ci/deploy.yml` strips console statements; `auditLog()` provides the structured alternative.

### A-12 — Dependency integrity `[FIXED]`

Inspector scans for known vulnerabilities. Nothing in the specification addresses lockfile integrity or install-time code execution. Three additions:

- `npm ci --ignore-scripts` — `ci` fails when `package.json` and the lockfile disagree, which is the signal that a dependency changed outside review; `--ignore-scripts` blocks the lifecycle-script execution path that most npm supply-chain attacks use.
- Actions pinned to commit SHAs, not tags. A tag is mutable, and a compromised action repository can retag. Actions granted `id-token: write` can assume a deployment role.
- `permissions: {}` at workflow level, opted into per job.

### A-13 — System prompt leakage `[PARTIAL]`

OWASP LLM07. The system prompt in `inference.mjs` instructs against disclosure, and it is wrapped in a `guardContent` block so the guardrail evaluates it. Instruction alone is weak. **Add "system prompt or configuration disclosure" as a denied topic in the guardrail configuration** — that is a console/IaC change outside this code delivery.

### A-14 — Container reuse after unhandled rejection `[FIXED]`

A Lambda execution environment that survives an unhandled rejection serves subsequent requests from indeterminate state, including possibly a previous caller's context. `security.mjs` exits on unhandled rejection, forcing a cold start.

### A-15 — `bedrock-mantle` guardrail enforcement `[OPEN]`

The `bedrock:GuardrailIdentifier` condition applies to `InvokeModel`, `InvokeModelWithResponseStream`, `Converse`, and `ConverseStream`. The specification routes OpenAI-compatible traffic to `bedrock-mantle`, whose Responses and Chat Completions surface is not covered by that condition list.

Until the enforcement path is confirmed, treat mantle traffic as the external-inference path: guard it in application code via `guardEgress()`, fail closed. Do not assume the three-layer enforcement claim extends to it.

---

## 4. Hardening Artifacts

| File | Closes | Notes |
|---|---|---|
| `src/authorizer/index.mjs` | A-03, A-04 | Full §4.4 validation matrix; JWKS pinned to issuer; per-method policy scope; server-side tenant entitlement |
| `src/adapter/security.mjs` | A-10, A-11, A-14 | Helmet, CORS allowlist, body limits, authorizer-context lift, hash-only audit logging, terminal error masking |
| `src/adapter/inference.mjs` | A-01, A-02, A-05, A-07 | Tenant-filtered retrieval with post-assertion, full-coverage `guardContent` tagging, pinned guardrail version, fail-closed egress, delimited untrusted context |
| `src/adapter/data.mjs` | A-06 (partial), A-08, A-09 | Parameterized tenant-scoped pgvector, IAM auth with certificate verification, schema-constrained ledger writes, atomic dual-counter budget |
| `ci/deploy.yml` | A-04, A-07, A-12 | OIDC with environment pinning, SHA-pinned actions, scanning gates, adversarial regression gate, console stripping |
| `ci/dependabot.yml` | A-12 | npm, GitHub Actions, and IaC ecosystems; authorizer dependencies ungrouped for individual review |

**Verification before use.** The Bedrock SDK shapes used here — `guardContent` qualifiers, `Retrieve` metadata filter syntax, `requestMetadata` — are current as of this writing but move with SDK versions. Run the tenant-isolation and guardrail-regression suites against a real endpoint before relying on the boundaries they establish.

---

## 5. Specification Changes Required

The code cannot enforce these; they are policy or configuration.

1. **§18.1** — rewrite from accepted residual to implementation requirement. Partial tagging is the risk, and it is avoidable.
2. **§6.2 and §7.1** — pin `bedrock:GuardrailIdentifier` to `identifier:version`, not a bare identifier. Without this, A-07 remains open regardless of application code.
3. **§6.3** — add the retrieval metadata filter and state corpus tenancy explicitly.
4. **§6.2** — add system-prompt disclosure as a denied topic.
5. **§6.1** — state the guardrail enforcement mechanism for `bedrock-mantle`, or classify that path as external inference.
6. **§4.6** — replace "validates the claim against a known tenant set" with an entitlement check, and specify the provenance of the mapping.
7. **New section** — application-layer controls. Output handling, CORS, error masking, log discipline, and dependency integrity currently have no home in a document that specifies KMS key separation in a table.

---

## 6. Deployment and Repository Verification

Confirm before the first production deployment. Items marked **critical** are the ones whose absence silently invalidates a control that appears to be present.

**GitHub**

- [ ] Repository private; organization requires 2FA — **critical**
- [ ] Branch protection on `main`: required reviews, required status checks, no force push, no bypass for admins
- [ ] Environment `prod` protection rules: required reviewers, and the approver cannot be the commit author
- [ ] Secret scanning **and push protection** enabled — scanning alone reports after the fact
- [ ] Dependabot alerts and security updates on
- [ ] `GITHUB_TOKEN` default permissions set to read-only at the organization level
- [ ] No `.env`, no `*.pem`, no `credentials` in history — verify with `gitleaks detect --log-opts="--all"`, not just the working tree

**AWS OIDC**

- [ ] Trust policy `sub` condition pins repository **and** environment — **critical**. `repo:<org>/*` permits any branch and any fork's pull request
- [ ] `aud` condition equals `sts.amazonaws.com`
- [ ] Thumbprint current, or the provider uses the managed root
- [ ] No IAM users with access keys in any workload account

**Runtime**

- [ ] Adapter has no `0.0.0.0/0` route — verify the route table, not the security group — **critical**
- [ ] `rejectUnauthorized` is true in the deployed bundle, not only in source
- [ ] Guardrail IAM condition pins a numeric version — **critical**
- [ ] Reserved concurrency set on the egress proxy below the guardrail throughput limit, so a safety failure becomes a queuing failure
- [ ] Lambda environment variables carry no secrets — they are visible to anyone with `lambda:GetFunctionConfiguration`
- [ ] Log group retention and KMS encryption set on every function, including the authorizer
- [ ] CloudFront responds to a direct API Gateway request with 403 — test the bypass, do not assume the header check

**Post-deploy assertions**

- [ ] Tenant-A canary document does not surface in a tenant-B retrieval
- [ ] A token scoped to `llm/retrieve` is rejected at `POST /v1/inference` on the **second** request as well as the first — this is the authorizer cache test
- [ ] An invocation without a guardrail parameter returns `AccessDenied`
- [ ] Synthetic PII markers are absent from the ledger, the vector store, and telemetry spans
- [ ] Forced `ApplyGuardrail` throttling produces a 503, not an egress

---

## 7. OWASP LLM Top 10 (2025) Coverage

| ID | Status | Basis |
|---|---|---|
| **LLM01** Prompt Injection | **Strong** | Three-layer enforcement on the Bedrock path; full-coverage `guardContent` tagging closes the §18.1 residual; retrieved content structurally delimited and instructed as quoted material. Residual: indirect injection depends on the ingestion controls the specification does not define |
| **LLM02** Sensitive Information Disclosure | **Strong** | Guardrail PII filters, hash-only telemetry, error masking, restricted invocation logs. Residual: the scanning bucket in §14 is a deliberate concentration of what the rest of the design disperses |
| **LLM03** Supply Chain | **Adequate** | Inspector, `npm ci --ignore-scripts`, SHA-pinned actions, Dependabot. **Gap:** no SBOM, and the external inference provider has no attestation |
| **LLM04** Data and Model Poisoning | **Weak** | No ingestion validation, provenance verification, or approval workflow for the knowledge base corpus is specified anywhere. The largest open gap |
| **LLM05** Improper Output Handling | **Partial** | Schema-constrained writes implemented. Rendering and downstream consumption unaddressed because the destination is unstated — see A-06 |
| **LLM06** Excessive Agency | **Strong by construction** | The model invokes nothing. No tools, no agents, no `RetrieveAndGenerate`. The adapter's write permissions are resource-enumerated and condition-scoped. This is the architecture's best structural property |
| **LLM07** System Prompt Leakage | **Partial** | Instructed and guardrail-evaluated. Needs a denied topic — see A-13 |
| **LLM08** Vector and Embedding Weaknesses | **Improved** | Tenant filter plus post-retrieval assertion; per-index CMK; no `s3vectors` read on the adapter role. Residual: embedding drift is unmonitored |
| **LLM09** Misinformation | **Partial** | Contextual grounding configured and correctly qualified. No output accuracy measurement or hallucination-rate SLA |
| **LLM10** Unbounded Consumption | **Strong** | Three-tier circuit breaker with stated detection latencies; dual-counter budget closes the tenant-rotation evasion; WAF rate rule keyed on caller identity |

**Weakest to strongest:** LLM04 (no ingestion controls at all) → LLM05 (blocked on an unstated destination) → LLM07 / LLM09 (partial) → the rest.

LLM06 is worth naming as the standout. Excessive agency is the failure mode most GenAI applications back into by adding tool use incrementally, and this architecture forecloses it structurally rather than by policy — the model has nothing to invoke. Preserve that. The day `RetrieveAndGenerate`, Bedrock Agents, or tool use is introduced, this audit and the MAESTRO assessment both require re-scoping rather than extension.
