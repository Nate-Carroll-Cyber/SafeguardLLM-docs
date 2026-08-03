# MAESTRO v2.0 Threat Model Assessment

**Target of evaluation:** *Secure Generative AI Workload on AWS* — architecture specification
**Framework:** MAESTRO v2.0 (CSA, Apr 2026), ten layers / three domains, with Agent 3SRM ownership assignment
**Evidence basis:** the specification document only. No code, no deployed environment, no CloudFormation templates, no runtime telemetry.
**Date:** 2026-07-31

---

## 1. Understanding Confirmed

The request is a MAESTRO threat-model assessment of a written architecture specification for an LLM inference service with retrieval augmentation, deployed across a seven-account AWS organization. The specification is design-stage: it describes intended controls, not verified implementations.

Every finding below is derived from what the document states. Where the document is silent, the finding is marked `Unanswerable from current evidence` and the required artifact is named. No control is assumed present because it would be reasonable to have.

---

## 2. Scope and Assumptions

**In scope.** All ten MAESTRO layers, assessed against the specification text.

**Out of scope by evidence, not by choice.**

- **Multi-agent threat categories** (cascading leaks, jailbreak proliferation, collusion, Byzantine sub-agent impersonation, coordination manipulation). No sub-agents, no agent-to-agent protocol, and no multi-agent pattern appear anywhere in the specification. Per skill rule 3, these are not assessed.
- **TRAIT&R inverted-adversary lens.** No insider-threat, misalignment, or untrusted-internal-deployment framing was requested, and the specification does not treat the model as a potential adversary in the loss-of-control sense. Not applied.
- **Framework crosswalk** (STRIDE / ATLAS / OWASP / NIST / ISO 42001). Not requested; Section 11 is omitted. Where an OWASP extended scenario maps cleanly to a MAESTRO finding, it is cited parenthetically only.

**Assumption made explicit.** The specification is treated as an accurate statement of design intent. It is not treated as evidence that any control is implemented, configured correctly, or tested. Section 12 lists what would convert design intent into verified control.

---

## 3. System Summary

**This system is not agentic in the MAESTRO sense, and the assessment is scoped accordingly.**

The specification describes a request/response inference gateway. Evidence establishes: a REST API fronted by CloudFront and WAF; Cognito-issued tokens validated by a Lambda authorizer; a Lambda "Express Adapter" that calls Amazon Bedrock for inference and, separately, `bedrock:Retrieve` against a knowledge base backed by S3 Vectors; two persistence stores (a DynamoDB ledger, an Aurora PostgreSQL pgvector store); and an egress proxy Lambda for residual third-party inference.

What is absent is what would make it agentic:

- **No orchestration framework, planning loop, or reasoning cycle.** The adapter is a deterministic handler.
- **No tool invocation by the model.** The specification explicitly excludes `RetrieveAndGenerate` and `InvokeAgent` and executes generation as a discrete `InvokeModel` call. The model selects nothing and invokes nothing.
- **No sub-agents, no delegation between agents, no autonomy configuration.**
- **No persistent agent memory.** The ledger is an audit store, not a memory the model reads back into context — and the specification does not evidence that it is read back.

MAESTRO is built for agentic systems and is partially over-scoped here. L4 (Orchestration) is largely unevidenced and L6 (Tools/Ecosystem) applies in an inverted direction described below. The layers that carry real analytical weight for this system are **L2, L3, L7, L8, L9, L10**, with substantive but conventional coverage at L1 and L5.

**The structurally interesting fact.** The specification names "machine callers such as MCP tool invocations" as a first-class caller class with its own Cognito app client and OAuth scopes. This system is therefore consumed *as a tool* by agentic systems operated elsewhere. In Agent 3SRM terms, the organization occupies the **Tool Provider (TaaS)** role relative to those consumers — a role the specification never acknowledges and for which it defines no obligations. This inversion drives several findings below and is the single most consequential scoping observation in this assessment.

---

## 4. Evidence Available

**Explicitly evidenced facts** (drawn from the specification):

| Domain | Evidenced |
|---|---|
| Infrastructure (L1) | Seven-account topology; three-tier subnet model with a no-default-route compute tier; gateway and interface VPC endpoints with restrictive endpoint policies; Network Firewall with FQDN allow-list and TLS SNI inspection; Shield Advanced; eight CMKs separated by data class |
| Cognitive core (L2) | Amazon Bedrock via `InvokeModel` / `Converse` against application inference profiles; `bedrock-mantle` for OpenAI-compatible traffic; residual third-party/on-prem inference over an egress proxy; guardrails with content filters, denied topics, word filters, contextual grounding, sensitive-information filters, automated reasoning checks |
| Data / knowledge (L3) | S3 Vectors index with per-index CMK; separate KB data-source bucket; `Retrieve` against a single named knowledge base ARN; DynamoDB ledger with 30-day content TTL and 400-day metadata TTL; Aurora pgvector partitioned by ingest month; KB re-sync on source deletion |
| Deployment (L5) | CloudFormation from Shared Services; three-role deployment chain; GitHub OIDC with `sub` pinned to repo and environment; permissions boundaries; `cfn-guard` and `checkov`; drift detection; two-person production approval |
| Identity (L7) | Nine runtime roles and four delivery roles with enumerated actions and conditions; `aws:SourceVpce`, `aws:PrincipalOrgID`, `aws:ResourceOrgID` data perimeter; `sts:ExternalId` on role chaining; token claim model distinguishing ID-token `aud` from access-token `client_id`; REQUEST authorizer with per-method cache key; JWKS pinned to issuer |
| Safety (L8) | Three-layer guardrail enforcement (identity condition, SCP null check, endpoint policy); `ApplyGuardrail` on the external inference path; guardrail interventions raised as Security Hub findings |
| Monitoring (L9) | Org Trail with data events; Bedrock model invocation logging under a segregated key; WORM audit bucket in a separate account; ADOT telemetry carrying prompt hashes only |
| Governance (L10) | Twelve SCPs; Backup Vault Lock compliance mode; tag enforcement by SCP; cost circuit breakers at three tiers; synthetic PII canaries |

**Reasonable inferences** (bounded, and labelled as inference wherever used below):

- The knowledge base is single-tenant or tenant-undifferentiated. Inferred from `bedrock:Retrieve` being scoped to *one* knowledge-base ARN with no metadata-filtering or tenant-partitioning statement, while DynamoDB and Aurora both receive explicit tenant-partitioning treatment. Bounded: the document may simply have omitted a control that exists.
- The system is a synchronous request/response service. Inferred from the Express adapter pattern, API Gateway REST, and the absence of any queue, workflow, or long-running execution construct.

**Unknowns.** Enumerated in Section 5 and repeated per-threat.

---

## 5. Immediate Gaps / Missing Information

Ordered by effect on the assessment.

1. **Provenance of the tenant claim.** §4.6 states that a pre-token-generation trigger injects a tenant claim, that client metadata supplied at the token endpoint is passed to that trigger, and that the authorizer "validates the claim against a known tenant set." Whether the trigger *derives* the tenant from an authoritative server-side mapping or *accepts* the client's assertion is not stated. The two readings produce materially different risk (see L7-T06).
2. **Tenant isolation in retrieval.** No metadata filtering, per-tenant index, or retrieval-time authorization is evidenced for the knowledge base, while both other datastores receive explicit tenant scoping.
3. **Ingestion controls for the knowledge base data source.** The specification covers the data-source bucket's encryption and access policy. It says nothing about validation, sanitization, provenance verification, or approval of documents entering the corpus.
4. **Failure semantics of `ApplyGuardrail` on the egress path.** Fail-open versus fail-closed on error, throttle, or timeout is unspecified.
5. **SCP scope.** SCPs are stated as attached "at the workload OU." The ML / Data Science account holds `DataScienceRole` with Bedrock access and sits outside that OU. Whether guardrail and inference-profile enforcement reach it is not stated.
6. **Adversarial testing programme.** Synthetic PII canaries test redaction. No red-teaming, jailbreak corpus, or adversarial evaluation is evidenced.
7. **Downstream effect of model output.** What consumes the response, and whether any consequential action follows from it, is not stated. This blocks assessment of human-oversight requirements (GRC-15).
8. **The MCP caller.** Who operates it, whether it is first-party or third-party, its transport, and how it holds credentials are all unstated.
9. **Contradiction between §12.1 and §10.** §12.1 sets a 30-day TTL on raw prompt/response content in the ledger. §10 sets model invocation log retention to "the shortest defensible period" without a number. The same content therefore has two retention policies, one quantified and one not. Flagged rather than resolved.

---

## 6. MAESTRO Layer Mapping

Only evidenced components are listed.

| Layer | Domain | Evidenced components |
|---|---|---|
| **L1 Infrastructure** | 1 | VPC (3-tier subnets, 2 AZ), gateway + interface VPC endpoints with endpoint policies, Network Firewall, NAT Gateway, Shield Advanced, CloudFront, Route 53 with DNSSEC + Resolver DNS Firewall, eight KMS CMKs, S3, RDS Proxy |
| **L2 Cognitive Core** | 1 | Amazon Bedrock foundation models via application inference profiles; `bedrock-mantle` endpoint; embedding model (via KB service role); external/on-prem inference provider; Bedrock Guardrails as model-adjacent control |
| **L3 Data, Memory, Knowledge** | 1 | S3 Vectors index, KB data-source bucket, Bedrock Knowledge Base, DynamoDB ledger, Aurora PostgreSQL pgvector, TTL and partition-rotation lifecycle, KB re-sync on source deletion |
| **L4 Orchestration & Coordination** | 2 | **Minimal evidence.** Express Adapter Lambda as a deterministic request handler. No orchestration framework, planning loop, tool registry, sub-agent coordination, or HITL construct in the runtime path |
| **L5 Deployment & Execution** | 2 | CloudFormation, CodePipeline in Shared Services, three-role deployment chain, GitHub OIDC federation, permissions boundaries, `cfn-guard` / `checkov`, Inspector, stack policies, drift detection, Lambda managed runtime |
| **L6 Tools, Application, Ecosystem** | 2 | API Gateway REST as the consumed interface; MCP tool callers as an external consumer class; third-party inference API as an external dependency. **No tools invoked by the model** |
| **L7 Identity & Autonomy** | 3 | Cognito user pool with two app clients, REQUEST Lambda authorizer, nine runtime IAM roles, four delivery roles, role chaining with `sts:ExternalId`, data perimeter conditions, delegated tenant claim, secrets rotation |
| **L8 Safety & Security** | 3 | Bedrock Guardrails with three-layer enforcement, `ApplyGuardrail` on egress, WAF managed rule groups, guardrail interventions as Security Hub findings, EventBridge response runbooks |
| **L9 Monitoring & Observability** | 3 | CloudTrail Org Trail with data events, Bedrock model invocation logging, Object Lock WORM audit bucket in Log Archive, ADOT/OTLP telemetry (hashes only), CloudWatch alarms, GuardDuty / Config / Macie / Inspector / Security Hub |
| **L10 Governance & Compliance** | 3 | Twelve SCPs, permissions boundaries, tag enforcement, Backup Vault Lock, cost governance, subject-erasure position, synthetic PII canaries |

---

## 7. Assessment Status by Layer

| Layer | Status | Note |
|---|---|---|
| L1 | **Answerable** | Densely evidenced; findings are residual rather than structural |
| L2 | **Partially answerable** | Bedrock path well evidenced. Third-party model provider unattested; no fine-tuning evidenced, so L2-T02/T05/T06 are out of scope on current evidence |
| L3 | **Partially answerable** | Storage and lifecycle evidenced; ingestion controls and tenant isolation in retrieval are not |
| L4 | **Largely unanswerable — and largely inapplicable** | No orchestration surface evidenced. Not a gap in the document so much as a property of the system |
| L5 | **Answerable** | Among the most completely specified layers |
| L6 | **Partially answerable** | The system's own surface is evidenced; the MCP consumer boundary is not, and the Tool Provider role is unaddressed |
| L7 | **Partially answerable** | Exceptionally detailed for AWS-principal identity; the human/machine caller identity chain has one unresolved link |
| L8 | **Partially answerable** | Enforcement architecture strong; failure semantics and adversarial testing absent |
| L9 | **Partially answerable** | Audit-grade logging genuinely evidenced (rare); behavioural drift detection absent |
| L10 | **Partially answerable** | Infrastructure governance strong; AI-specific governance (GRC-09/10/11/12/15) entirely absent |

---

## 8. Detailed Threat Analysis

---

### L7-T06 — Improper Trust Escalation (tenant claim asserted by the caller)

**MAESTRO Layer**
- L7: Identity and Autonomy (Domain 3, horizontal). Cross-references L7-T08.

**Current Evidence**
- §4.6: on `client_credentials` tokens, `sub` is the app client ID, not a user.
- §4.6: a pre-token-generation Lambda trigger (event version 3+) injects a tenant claim into the access token; client metadata supplied at the token endpoint is passed to that trigger on `client_credentials` requests.
- §4.6: the authorizer "validates the claim against a known tenant set and promotes it into the request context."
- §7.1: `SafeguardExecRole` carries `dynamodb:LeadingKeys` scoped to the tenant partition.
- §11.3: the tier-1 token budget keys on the same caller identity.

**Reasonable Inferences**
- The `dynamodb:LeadingKeys` condition is evaluated against a tenant value that originates in the request context, which originates in the token, which was minted using client-supplied metadata. Bounded inference: this is the chain the document describes; it does not state where the chain is rooted.

**Unknowns / Missing Evidence**
- Whether the pre-token-generation trigger derives the tenant from an authoritative server-side mapping keyed on `client_id`, or accepts the client's asserted value.
- Whether "validates against a known tenant set" means membership checking or entitlement checking.

**Assessment Status**
- Partially answerable. The finding is conditional on the unknown above, and the two branches differ by roughly two risk classes.

**Attack Vector**
- A machine client legitimately provisioned for tenant A supplies metadata asserting tenant B at the token endpoint. The trigger injects tenant B. The authorizer confirms B is a known tenant and promotes it. The adapter's `LeadingKeys` condition then authorizes access to tenant B's ledger partition — correctly, against a wrong input. Every credential in the flow is valid; the authorization decision is wrong. This is the confused-deputy pattern (L7-T08) with the tenant claim as the misdirected assertion.

**Cross-Layer Impact**
- L3 (tenant-partitioned data access), L6 (the asserting caller is an external system), L9 (attribution in the ledger and access logs records the wrong tenant, so the compromise is invisible in audit), L11 n/a.

**Likelihood / Impact / Risk**
- Likelihood: **Medium** — requires a provisioned machine client, so the attacker is an authenticated tenant rather than an anonymous one.
- Impact: **High** — cross-tenant data access with correct-looking audit records.
- Risk: **High** if the trigger accepts client-supplied tenant values; **Low** if it derives them server-side.

**Recommended Mitigations**
- Root the tenant claim in an authoritative mapping from `client_id` to tenant, held server-side, with client metadata used only for values the client is entitled to vary.
- If one machine client legitimately serves multiple tenants, treat the tenant assertion as a delegation and apply token exchange (RFC 8693) with narrowed scope per tenant rather than a self-asserted claim.
- Enforce entitlement, not membership, at the authorizer: the check must be "may this `client_id` act for this tenant," not "does this tenant exist."
- Emit a distinct audit event whenever a caller's asserted tenant differs from its primary tenant.

**SSRM Ownership**
- Primary: AIC (AP) — L7 is AIC-primary.
- Shared: CSP (Cognito as identity infrastructure), OSP (federation).
- Agent Owner accountable: yes (always, per 3SRM §3.1 and MAESTRO §9.3).

**Required Evidence to Fully Answer**
- The pre-token-generation trigger source.
- The authorizer's tenant validation code path.
- The tenant provisioning record for machine app clients.

---

### L3-T02 — Vector Database Access-Control Bypass (cross-tenant retrieval)

**MAESTRO Layer**
- L3: Data, Memory, and Knowledge (Domain 1).

**Current Evidence**
- §6.1 and §7.1: `KBRetrieveRole` holds `bedrock:Retrieve` on **one** knowledge-base ARN.
- §6.3: S3 Vectors index with per-index CMK; separate data-source bucket; bucket policies carry `aws:SourceVpce` and `aws:PrincipalOrgID`.
- §7.1: DynamoDB access is tenant-scoped via `dynamodb:LeadingKeys`.
- §12.3: Aurora pgvector is partitioned **by ingest month** — a temporal partition, not a tenant partition.
- No metadata filtering, per-tenant index, or retrieval-time authorization appears anywhere in the specification.

**Reasonable Inferences**
- Retrieval is tenant-undifferentiated. Bounded: the specification's explicit tenant treatment of the other two stores, and its silence here, supports this reading but does not prove it.

**Unknowns / Missing Evidence**
- Whether the knowledge base applies metadata filtering by tenant at retrieval time.
- Whether the corpus is genuinely single-tenant, which would make the finding moot.

**Assessment Status**
- Partially answerable.

**Attack Vector**
- Any caller reaching the retrieval path obtains context chunks from the whole corpus. The controls that exist — CMK, endpoint conditions, role assumption — govern *whether* the process may retrieve, not *which subset* it may retrieve. Where tenant A's documents are in the index, a query from tenant B returns them as grounding context, and the model reproduces their content in a response that passes every guardrail, because leaked content is not unsafe content.

**Cross-Layer Impact**
- L2 (the model reproduces retrieved content), L6 (the response leaves via the API), L7 (the identity controls that succeed here are the ones that do not address the failure), L9 (a successful retrieval is indistinguishable from a legitimate one in telemetry that carries hashes only).

**Likelihood / Impact / Risk**
- Likelihood: **Medium** — requires only a valid credential and a well-chosen query; no bypass of any control is needed.
- Impact: **High** where the corpus is multi-tenant; **Low** where it is not.
- Risk: **High**, conditional on corpus tenancy.

**Recommended Mitigations**
- Apply metadata filtering on the knowledge base, with the tenant filter derived from the authorizer's request context rather than from any client-supplied parameter.
- Alternatively, per-tenant vector indexes with the retrieve role scoped per index — higher cost, stronger boundary, no reliance on filter correctness at query time.
- Extend the Aurora pgvector partitioning scheme to include tenant, so the fingerprint store has the same boundary as the ledger.
- Add a retrieval-time assertion test to the canary programme (§14.3): a tenant-A canary document must never surface in a tenant-B query.

**SSRM Ownership**
- Primary: AIC (Agent Owner) — L3 is AIC-primary for data governance and integrity.
- Shared: CSP (storage and encryption), MP (embedding-model integrity), OSP (data-pipeline orchestration).
- Agent Owner accountable: yes.

**Required Evidence to Fully Answer**
- Knowledge base configuration showing metadata filter definitions.
- Corpus tenancy statement.
- A retrieval-authorization test result.

---

### L3-T01 — RAG Poisoning (no evidenced ingestion control)

**MAESTRO Layer**
- L3: Data, Memory, and Knowledge (Domain 1). Context-engineering threat CE-T1 (poisoning). OWASP T18.

**Current Evidence**
- §6.3: data-source bucket with its own CMK, `aws:SourceVpce` and `aws:PrincipalOrgID` in the bucket policy.
- §10: CloudTrail data events cover S3 object-level operations on the vector and app buckets.
- §12.1: source documents have a business-defined retention; embeddings are bound to source.
- §6.2: guardrail policies include contextual grounding checks.
- The specification contains no statement about validation, sanitization, provenance verification, or approval of document content entering the corpus.

**Reasonable Inferences**
- None required. The absence is the finding.

**Unknowns / Missing Evidence**
- The ingestion path: who writes to the data-source bucket, under what review, and with what content controls.
- Whether contextual grounding is configured to detect instruction-bearing retrieved content, as distinct from factual ungroundedness.

**Assessment Status**
- Partially answerable — the storage boundary is evidenced, the content boundary is not.

**Attack Vector**
- A document containing embedded instructions enters the corpus through whatever path populates the data-source bucket. It is chunked, embedded, and indexed by the managed pipeline. On retrieval it arrives in the model's context with the same standing as legitimate grounding material. The specification's own §18.1 acknowledges that input-side guardrail evaluation can be evaded by tagging; retrieved context is precisely the content most likely to be assembled outside the tagged region.
- The adapter holds `dynamodb:PutItem`, `dynamodb:TransactWriteItems`, and `s3:PutObject`. Injected instructions that shape adapter behaviour reach write actions, not merely response text.

**Cross-Layer Impact**
- L2-T03 (prompt injection realised through retrieval), L6-T06 (write actions and exfiltration through the response channel), L8-T01 (guardrail evasion), L9 (hash-only telemetry cannot show what was retrieved).

**Likelihood / Impact / Risk**
- Likelihood: **Unassessable from current evidence** — depends entirely on who can write to the data source, which is unstated.
- Impact: **High** — the adapter's write permissions convert a content-injection into a state-changing action.
- Risk: **Unassessable**, pending the ingestion path.

**Recommended Mitigations**
- Define and document the ingestion path as a trust boundary: approved writers, content validation before indexing, provenance metadata on every chunk.
- Treat retrieved context as untrusted input in the adapter's prompt assembly — structurally delimited, never concatenated into instruction position.
- Ensure retrieved content falls inside the guardrail-evaluated region of the prompt, given §18.1.
- Extend contextual grounding configuration to flag imperative or instruction-shaped retrieved content, not only ungrounded assertions.
- Add poisoned-document canaries to §14.3 alongside the PII canaries.

**SSRM Ownership**
- Primary: AIC (Agent Owner).
- Shared: OSP (ingestion pipeline), MP (embedding model), CSP (storage).
- Agent Owner accountable: yes.

**Required Evidence to Fully Answer**
- Ingestion architecture and writer inventory for the data-source bucket.
- Guardrail configuration export showing contextual grounding thresholds.
- Prompt assembly code showing how retrieved chunks are delimited.

---

### L3-T07 / CE-T6 — Context Overflow

**MAESTRO Layer**
- L3: Data, Memory, and Knowledge (Domain 1).

**Current Evidence**
- §3: WAF custom rules for oversized bodies and prompt-payload ceilings.
- §11.3: token budget per caller identity, checked before invocation; CloudWatch alarms on `InputTokenCount`.
- No limit on retrieved-context volume is evidenced.

**Assessment Status**
- Partially answerable. Inbound payload is bounded; assembled context is not.

**Attack Vector**
- The evidenced ceilings apply to the request as received. Context assembled after retrieval — user prompt plus *n* retrieved chunks plus system prompt — is not bounded by any evidenced control. A query engineered to retrieve maximally long chunks inflates the assembled context, forcing truncation or lossy compression, which can displace system-prompt or guardrail-relevant content (CE-T5 compression loss).

**Cross-Layer Impact**
- L8 (safety instruction displaced by truncation), L2 (degraded output quality), L1-T03 / §11 (token consumption as a cost-abuse vector).

**Likelihood / Impact / Risk**
- Likelihood: **Medium**.
- Impact: **Medium** — bounded by the guardrail's independent evaluation of the response, which does not depend on the system prompt surviving.
- Risk: **Medium**.

**Recommended Mitigations**
- Cap retrieved-chunk count and total assembled-context tokens explicitly, and reject rather than truncate on breach.
- Assemble context so that safety-relevant content is positionally protected from truncation.
- Alarm on assembled-context size, not only on inbound payload size.

**SSRM Ownership**
- Primary: AIC. Shared: MP (context window behaviour), OSP.
- Agent Owner accountable: yes.

**Required Evidence to Fully Answer**
- Retrieval configuration (`numberOfResults`, chunk size) and the adapter's context assembly logic.

---

### L3-T05 — Embedding Inversion

**MAESTRO Layer**
- L3: Data, Memory, and Knowledge (Domain 1).

**Current Evidence**
- §6.3: S3 Vectors index with per-index CMK.
- §7.1: `KnowledgeBaseServiceRole` holds `s3vectors` query and write permissions; `KBRetrieveRole` holds only `bedrock:Retrieve`.
- §12.4: the specification correctly states that an embedding derived from personal data is personal data.

**Assessment Status**
- Answerable.

**Attack Vector**
- Direct read of the vector index would permit approximate reconstruction of source text. The evidenced controls — CMK, `aws:SourceVpce`, role separation, and the absence of any `s3vectors` read permission on the adapter's role — close the direct path. Residual exposure is through the retrieval interface rather than the store.

**Cross-Layer Impact**
- L7 (the role separation is what holds), L1 (key policy).

**Likelihood / Impact / Risk**
- Likelihood: **Low** — no evidenced principal can read the index directly other than the KB service role.
- Impact: **High** if realised.
- Risk: **Low**. Documented as covered rather than as a gap.

**Recommended Mitigations**
- Maintain the current separation; specifically, never grant `s3vectors` read to the adapter role as a convenience during troubleshooting.
- Include the vector index in the periodic access review.

**SSRM Ownership**
- Primary: AIC. Shared: CSP (encryption), MP (embedding model).
- Agent Owner accountable: yes.

---

### L2-T03 — Prompt Injection / Jailbreak

**MAESTRO Layer**
- L2: Cognitive Core (Domain 1). Cross-references L8-T01.

**Current Evidence**
- §6.2: guardrail attached per invocation; enforcement at identity policy (`bedrock:GuardrailIdentifier` with paired explicit deny), SCP (`Null` check), and endpoint policy.
- §6.2: content filters, denied topics, word filters, contextual grounding, sensitive-information filters, automated reasoning checks.
- §18.1: the specification itself records that input tags let a caller mark which prompt sections are evaluated, and that response-side evaluation is unconditional.
- §16: repeated guardrail interventions from one caller identity trigger a WAF blocked-identity set entry.

**Assessment Status**
- Answerable.

**Attack Vector**
- Direct injection through the user prompt is the strongest-covered path in the architecture: three independent enforcement layers must fail before an unguarded invocation occurs. The residual paths are (a) input-tag evasion by a compromised adapter, which the specification acknowledges, and (b) indirect injection via retrieved context (see L3-T01), which the specification does not address.

**Cross-Layer Impact**
- L3 (indirect injection vector), L6-T06 (adapter write permissions as the payoff), L8-T01.

**Likelihood / Impact / Risk**
- Likelihood: **Medium** — direct injection attempts are near-certain; success against three enforcement layers is not.
- Impact: **High** — the adapter holds write permissions.
- Risk: **Medium**, and would be Low but for the indirect path at L3-T01.

**Recommended Mitigations**
- Close the indirect path first; it is the higher-yield route and is currently unaddressed.
- Treat the adapter's tagging logic as the security-relevant code the specification says it is — specifically, assert in code review that retrieved context and user input both fall inside the evaluated region.
- Add jailbreak-corpus regression testing to the pipeline alongside the PII canaries.

**SSRM Ownership**
- Primary: MP (safety alignment, guardrail service). Shared: AP (prompt construction), AIC (guardrail configuration and integration).
- Agent Owner accountable: yes.

---

### L2-T04 — Model Supply Chain (unattested third-party inference provider)

**MAESTRO Layer**
- L2: Cognitive Core (Domain 1).

**Current Evidence**
- §6.1: residual external/on-prem inference retained "only where no in-boundary equivalent exists"; payload passes `ApplyGuardrail` and deterministic redaction before egress; a hash of the transmitted payload is ledgered.
- §18.3: the specification states that the external provider's logging and retention govern the payload once received, and that only contractual control exists.
- No provider attestation, model integrity verification, or AI-CAIQ position is evidenced.

**Assessment Status**
- Partially answerable.

**Attack Vector**
- The specification addresses the *confidentiality* of what is sent and is candid about its limits. It does not address the *integrity* of what comes back. A compromised or manipulated external model returns content that the architecture treats as an inference result. Where that result is displayed to a user or written to the ledger, model-supply-chain compromise becomes an application-integrity problem with no evidenced detection.

**Cross-Layer Impact**
- L6 (third-party dependency), L8 (returned content is not evidenced as guardrail-evaluated on the inbound leg), L10 (supply-chain governance, STA domain).

**Likelihood / Impact / Risk**
- Likelihood: **Low**.
- Impact: **Medium to High** depending on what consumes the response — unstated.
- Risk: **Medium**.

**Recommended Mitigations**
- Apply `ApplyGuardrail` to the **response** from the external provider, not only to the outbound payload. The specification currently describes egress-side guarding only.
- Obtain AI-CAIQ responses from the external provider and attach them as a contractual annex (3SRM §6.2).
- Maintain a Service BOM (STA-16) covering the external model, its version, and its retention terms — AIC-owned and currently absent.
- Record model identity and version alongside the payload hash in the ledger, so a provider-side model change is detectable after the fact.

**SSRM Ownership**
- Primary: MP — and note that the external provider is a **second MP** with no evidenced attestation, while AWS Bedrock as MP is covered by CSP-adjacent attestation.
- Shared: AIC (selection and due diligence), AP.
- Agent Owner accountable: yes — the Agent Owner answers for the external component's behaviour regardless of proximate cause.

**Required Evidence to Fully Answer**
- Provider security attestation, model versioning commitments, retention terms.
- Whether inbound responses are guardrail-evaluated.

---

### L2-T01 — Model Extraction

**MAESTRO Layer**
- L2: Cognitive Core (Domain 1).

**Current Evidence**
- §11.3: tier-1 per-identity token budget; tier-2 CloudWatch alarms on invocation and token counts; tier-3 Budget Actions.
- §4.1: WAF rate-based rule with a custom aggregation key on caller identity.
- Model weights are hosted by the model provider; no self-hosted weights are evidenced.

**Assessment Status**
- Answerable.

**Attack Vector**
- Systematic querying to reconstruct decision boundaries or distil behaviour. The three-tier consumption control is a meaningful constraint on query volume — an unusual position, since these controls were specified for cost reasons and happen to constrain extraction as a side effect. Weight extraction proper is out of reach given managed hosting.

**Cross-Layer Impact**
- L1-T03 (resource exhaustion shares the same controls), L11 n/a.

**Likelihood / Impact / Risk**
- Likelihood: **Low**.
- Impact: **Low** for base model weights (MP-owned); **Medium** for system-prompt and guardrail-configuration inference, which repeated probing can reveal.
- Risk: **Low**.

**Recommended Mitigations**
- Alarm on high-volume low-diversity query patterns from a single identity, distinct from the volume-only alarms already specified.
- Treat system-prompt disclosure as an explicit denied topic in the guardrail configuration.

**SSRM Ownership**
- Primary: MP. Shared: AIC (rate limiting), AP.
- Agent Owner accountable: yes.

---

### L8-T03 — Cascading Safety Failure (guardrail failure semantics unspecified)

**MAESTRO Layer**
- L8: Safety and Security (Domain 3, horizontal).

**Current Evidence**
- §6.1: the egress proxy path passes payloads through `bedrock:ApplyGuardrail` before external transmission.
- §7.1: `EgressProxyRole` holds `bedrock:ApplyGuardrail`, `secretsmanager:GetSecretValue`, and `dynamodb:PutItem` — and explicitly no inference permissions.
- Nothing states what happens when `ApplyGuardrail` errors, throttles, or times out.

**Assessment Status**
- Partially answerable. The control is evidenced; its failure mode is not.

**Attack Vector**
- The three-layer enforcement at §6.2 makes the *Bedrock* path fail closed by construction — an IAM condition denies the call outright. The egress path has no equivalent structure: `ApplyGuardrail` is an in-code call, and an in-code call has a failure branch. If that branch proceeds on error, an attacker who can induce throttling — trivially, by driving concurrent volume — obtains unredacted egress to a third party. The asymmetry is that the strong path is enforced by policy and the weak path by code.

**Cross-Layer Impact**
- L6 (external transmission), L2 (redaction bypass), L9 (a fail-open event may be indistinguishable from a successful guarded call in the ledger, which records a payload hash, not a guardrail verdict).

**Likelihood / Impact / Risk**
- Likelihood: **Medium** — induced throttling is a low-skill trigger.
- Impact: **High** — unredacted content crosses the trust boundary, and §18.3 establishes that recovery is contractual only.
- Risk: **High**.

**Recommended Mitigations**
- State fail-closed explicitly and implement it: no `ApplyGuardrail` verdict, no egress.
- Record the guardrail verdict alongside the payload hash in the ledger, so post-hoc distinction between guarded and unguarded egress is possible.
- Alarm on `ApplyGuardrail` error and throttle rates as a safety signal, not an availability one.
- Consider reserved concurrency on the egress proxy sized below the guardrail throughput limit, converting a safety failure into a queuing failure.

**SSRM Ownership**
- Primary: AIC (integrating authority for L8). Shared: MP (guardrail service), AP (adapter and proxy code).
- Agent Owner accountable: yes.

**Required Evidence to Fully Answer**
- Egress proxy source, specifically the exception path around the guardrail call.

---

### L8-T05 — Adversarial Robustness Failure (no red-team programme)

**MAESTRO Layer**
- L8: Safety and Security (Domain 3, horizontal).

**Current Evidence**
- §14.3: synthetic PII markers injected on a schedule, with absence asserted in the ledger, vector store, and telemetry spans.
- §16: guardrail interventions raised as Security Hub findings; repeated interventions trigger identity blocking.
- §19: guardrail intervention is monitored as a trend.
- No red-teaming framework, jailbreak corpus, or adversarial evaluation appears in the specification.

**Assessment Status**
- Answerable — the absence is unambiguous.

**Attack Vector**
- The canary programme tests one control (PII redaction) against one failure mode (leakage). It does not test whether the guardrail resists adversarial input. Guardrail effectiveness is therefore inferred from intervention *rate* rather than measured against known attacks — a metric that moves when attack volume changes, not when guardrail quality changes. A guardrail silently degraded by a configuration change would show as a lower intervention rate, which §19 correctly flags as a signal to watch but cannot distinguish from a quieter attack environment.

**Cross-Layer Impact**
- L2-T03, L8-T01, L9-T03 (drift), L10 (no evaluation evidence for regulatory purposes).

**Likelihood / Impact / Risk**
- Likelihood: **High** — this is an omission, not a contingency.
- Impact: **Medium** — bounded by the three-layer enforcement, which ensures *a* guardrail is applied even if its quality is unmeasured.
- Risk: **Medium**.

**Recommended Mitigations**
- Add a versioned adversarial corpus to the pipeline, run as a blocking gate on guardrail configuration changes. This extends the existing §14.3 canary pattern rather than introducing a new mechanism.
- Track intervention rate *per attack class* rather than in aggregate, which distinguishes guardrail degradation from environmental change.
- Schedule external red-teaming on a cadence, with results retained as evaluation evidence — this is what L10 regulatory positions will require and what the architecture currently cannot produce.

**SSRM Ownership**
- Primary: AIC (integrating). Shared: MP (MDS-06 adversarial attack analysis, MDS-07 model hardening — note both have no ISO 42001 equivalent), AP.
- Agent Owner accountable: yes.

---

### L9-T01 — Monitoring Blind Spot (content-blind detection surface)

**MAESTRO Layer**
- L9: Monitoring and Observability (Domain 3, horizontal).

**Current Evidence**
- §10: ADOT telemetry carries **prompt hashes only, never content**; spans include correlation ID, inference profile ARN, guardrail verdict, latency, token counts.
- §10: Bedrock model invocation logging captures prompt and completion bodies, encrypted under `cmk/audit` in the Log Archive account, "access restricted to a named investigation role."
- §10: CloudTrail records that a call occurred, never its content.

**Reasonable Inferences**
- Detection engineering operates on metadata; content analysis requires an access request against a restricted role in a different account. Bounded: the specification does not describe the investigation workflow.

**Assessment Status**
- Answerable. This is a deliberate design trade, assessed as such rather than as a defect.

**Attack Vector**
- Content-based detection — semantic anomaly, coordinated prompt patterns across identities, slow-burn extraction — has no near-real-time surface. The signals available in the fast path are volume, latency, token count, and guardrail verdict. An attack that stays within volume norms and does not trigger a guardrail is invisible until someone opens the invocation logs, which requires assuming a restricted role in a segregated account.

**Cross-Layer Impact**
- L2-T01 (slow extraction), L3-T02 (a successful cross-tenant retrieval looks like a normal retrieval), L8-T04 (incident response blind spot).

**Likelihood / Impact / Risk**
- Likelihood: **High** — the constraint is structural and permanent.
- Impact: **Medium** — detection is delayed, not absent; the invocation logs are complete and immutable.
- Risk: **Medium**.

**Recommended Mitigations**
- Accept the trade, but close the gap between it and incident response: define and rehearse the investigation-role access path, and measure time-to-content as an IR metric.
- Emit non-content derived signals into the fast path that support semantic detection — guardrail sub-verdicts by category, retrieval chunk IDs, embedding-distance outliers — none of which disclose content.
- Run scheduled detection queries against the invocation logs in Log Archive, so content analysis happens on a cadence rather than only on suspicion.

**SSRM Ownership**
- Primary: AIC (integrating). Shared: all roles — CSP (infrastructure telemetry), MP (MDS-10 model monitoring), OSP, AP.
- Agent Owner accountable: yes.

**Note.** Per skill rule 4, this assessment distinguishes evaluation and observability from audit-grade logging. This architecture genuinely satisfies the audit-grade criterion — tamper-evident via Object Lock compliance mode, retained, segregated from the execution environment, and queryable. That is uncommon and is recorded as a strength. The finding above concerns detection latency, not audit sufficiency.

---

### L9-T03 — Drift Detection Bypass

**MAESTRO Layer**
- L9: Monitoring and Observability (Domain 3, horizontal).

**Current Evidence**
- §11.3: CloudWatch alarms with anomaly-detection bands on `InputTokenCount`, `OutputTokenCount`, `Invocations`, `InvocationThrottles`.
- §11.4: Cost Anomaly Detection on the Bedrock service and on the tag dimension.
- §19: guardrail intervention monitored as a trend.
- No behavioural baseline, output-quality monitoring, or model-drift detection is evidenced.

**Assessment Status**
- Answerable.

**Attack Vector**
- The evidenced anomaly detection is entirely on consumption metrics. Behavioural drift — a model version change altering output characteristics, a guardrail configuration change reducing sensitivity, an embedding model update shifting retrieval relevance (OWASP T17 / CE-T7 semantic drift) — produces no consumption signal and would pass undetected.

**Cross-Layer Impact**
- L2 (model behaviour), L3 (retrieval relevance), L8-T05 (guardrail quality degradation).

**Likelihood / Impact / Risk**
- Likelihood: **Medium** — cross-region inference profiles and managed model updates make version movement a normal operational event.
- Impact: **Medium**.
- Risk: **Medium**.

**Recommended Mitigations**
- Baseline output characteristics per inference profile and alarm on distributional shift.
- Pin and log model version per invocation; treat a version change as a change event requiring the adversarial regression gate from L8-T05.
- Monitor retrieval relevance scores over time to detect embedding drift, which §12.1's source-binding does not address.

**SSRM Ownership**
- Primary: AIC (integrating). Shared: MP (MDS-10), OSP.
- Agent Owner accountable: yes.

---

### L10-T01 — Shadow AI / Rogue Agents (SCP scope boundary)

**MAESTRO Layer**
- L10: Governance, Authority, and Compliance (Domain 3, horizontal).

**Current Evidence**
- §15: SCPs are "attached at the workload OU." SCP 3 enforces guardrail presence; SCP 4 enforces inference-profile presence; SCP 5 restricts regions.
- §2 and §7.1: the ML / Data Science account holds `DataScienceRole` with SageMaker Studio, Bedrock dev models, and MWAA, under a permissions boundary "capping to the ML account."
- §2: the ML account is a distinct account; no statement places it in the workload OU.

**Reasonable Inferences**
- Guardrail and inference-profile enforcement do not reach the ML account. Bounded: OU membership is not stated either way, but the SCPs are described as workload-OU-scoped and the ML account is described separately throughout.

**Unknowns / Missing Evidence**
- The organizational unit structure and which SCPs attach where.

**Assessment Status**
- Partially answerable.

**Attack Vector**
- Human principals in the ML account invoke Bedrock without a guardrail and without an inference profile. This is not an attack so much as a governance boundary: the specification's strongest AI-specific control — mandatory guardrails — is scoped to the account least likely to encounter adversarial input, and absent from the account where humans experiment interactively with models and production-derived data. Cost attribution is likewise absent there, so the ML account's inference spend is invisible to the §11.2 mechanism.

**Cross-Layer Impact**
- L2 (unguarded inference), L8 (enforcement gap), L11 n/a, §11 (unattributed spend).

**Likelihood / Impact / Risk**
- Likelihood: **High** if the OU boundary is as inferred.
- Impact: **Medium** — the ML account is stated to be isolated from production resources by permissions boundary and SCP.
- Risk: **Medium**.

**Recommended Mitigations**
- Attach guardrail-enforcement and inference-profile SCPs at the organization root or a shared parent OU, with documented exceptions rather than silent non-coverage.
- If experimentation genuinely requires unguarded invocation, make that an explicit, time-bound, logged exception rather than an artefact of OU placement.
- Extend cost attribution to the ML account; experimentation is where unbounded spend originates.

**SSRM Ownership**
- Primary: AIC — **non-delegable**. Per 3SRM §8.2: in all three deployment models, Layer 10 (Governance) remains with the Agent Owner. Governance cannot be outsourced.
- Shared: none. All providers support governance via attestation only.
- Agent Owner accountable: yes.

---

### L10-T06 — Regulatory Non-Compliance (AI-specific governance absent)

**MAESTRO Layer**
- L10: Governance, Authority, and Compliance (Domain 3, horizontal).

**Current Evidence**
- §12.4: subject-erasure position, including the honest statement that backup retention caps erasure.
- §15: twelve SCPs, all addressing infrastructure and inference-mechanics governance.
- §10, §13: audit and retention controls.
- The specification contains no AI impact assessment, no acceptable-use policy, no bias or fairness position, no human-oversight definition, and no reference to the EU AI Act, ISO/IEC 42001, or NIST AI RMF.

**Assessment Status**
- Answerable — the absence is unambiguous and complete.

**Attack Vector**
- Not an attack path. This is a compliance exposure: the AICM controls that are AIC-owned regardless of deployment model — GRC-09 (acceptable use), GRC-10 (AI impact assessment), GRC-11 (bias and fairness), GRC-12 (ethics committee), GRC-15 (human supervision) — have no counterpart in the specification. The document governs the *infrastructure* of an AI system thoroughly and the *AI* of it not at all.
- GRC-15 in particular cannot be assessed because §5 gap 7 stands: what consumes the model output, and whether any consequential decision follows from it, is unstated. If the output informs a decision about a person, human-oversight obligations attach and nothing in the specification satisfies them.

**Cross-Layer Impact**
- L8 (evaluation evidence for safety claims), L9 (records required for regulatory reporting exist and are well-formed, which is the strong half of the position), L2 (model selection and documentation obligations).

**Likelihood / Impact / Risk**
- Likelihood: **High** — this is a present-state gap, not a contingency.
- Impact: **Unassessable from current evidence** — depends on use case and jurisdiction, both unstated.
- Risk: **Unassessable**, but the gap itself is certain.

**Recommended Mitigations**
- Produce an AI impact assessment (GRC-10) covering purpose, affected persons, and consequential-decision analysis. This is the artefact that determines whether the remaining obligations attach.
- Define acceptable use (GRC-09) and human supervision (GRC-15) once the downstream consumer of the output is known.
- Maintain a Service BOM (STA-16) covering the foundation models, the embedding model, the external inference provider, and the guardrail configuration version.
- Note for framework alignment work: per the AICM↔ISO 42001 crosswalk, the layers this system depends on most heavily are the least ISO-anchored. All of MDS-01–13 (L2) and all of LOG-01–15 (L9) have no ISO 42001 equivalent, and the IAM family (L7) maps only to a generic alignment clause. ISO 42001 certification would not attest the controls this architecture is actually built on; ISO 27001 and SOC 2 are the correct citations for those.

**SSRM Ownership**
- Primary: AIC — non-delegable. GRC-09, GRC-10, GRC-11, GRC-12 are AIC-owned regardless of deployment model.
- Shared: none for accountability; all providers support via compliance attestation.
- Agent Owner accountable: yes.

---

### L6-T04 / L6 (Tool Provider role) — MCP Consumer Boundary Undefined

**MAESTRO Layer**
- L6: Tools, Application, Environment, and Ecosystem (Domain 2).

**Current Evidence**
- §1 and §4.2: "machine callers such as MCP tool invocations" are a first-class caller class with a dedicated Cognito app client, `client_credentials` flow, and scopes `llm/invoke` and `llm/retrieve`.
- §4.6: the machine caller may be multi-tenant, requiring a delegated tenant identity.
- Nothing else about the MCP caller appears: not its operator, its transport, its credential storage, its tool definition, or the trust relationship with its end users.

**Reasonable Inferences**
- The organization is a Tool Provider (TaaS) in the Agent 3SRM sense relative to these consumers. Bounded: this follows from the caller class being an MCP tool invocation, which by definition means an agent elsewhere invokes this API as a tool.

**Unknowns / Missing Evidence**
- Whether the MCP server is first-party or third-party.
- How the MCP server stores and scopes the credentials it holds for this API.
- Whether the MCP server holds per-end-user tokens (which would raise L7-T10, MCP-service token isolation failure) or a single service credential.
- What tool definition is published to the consuming agent.

**Assessment Status**
- **Largely unanswerable from current evidence.** Per skill rule 5, MCP-specific threats are not inferred from the presence of a caller class. What is answerable is that the boundary exists and is undefined.

**Attack Vector**
- Two directions, both currently unaddressed:
  - *Inbound.* The architecture authenticates the MCP client and says nothing about its integrity. Everything the consuming agent sends — including the tenant assertion at L7-T06 — is accepted on the strength of a machine credential. A compromised MCP server is an authenticated caller.
  - *Outbound.* As Tool Provider, the organization supplies model output that an autonomous agent elsewhere acts upon. L6-T07 (interface manipulation) and L6-T03 (business-logic abuse) attach to the *consumer's* system through this interface. The specification defines no tool contract, no output constraints, and no communication of limitations to consumers.

**Cross-Layer Impact**
- L7-T06 and L7-T08 (identity assertions crossing the boundary), L10 (AICM structural gap category 4 — cross-organizational agent collaboration, where responsibility boundaries need explicit definition and the current AICM catalog lacks a clean control), L8 (safety of output consumed autonomously).

**Likelihood / Impact / Risk**
- Likelihood: **Unassessable from current evidence.**
- Impact: **Unassessable from current evidence.**
- Risk: **Unassessable.** The finding is the undefined boundary, not a quantified exposure.

**Recommended Mitigations**
- Document the MCP consumer boundary as a first-class trust boundary in the specification, with the same rigour applied to the CloudFront origin boundary.
- Publish a tool contract: what the API returns, what it does not guarantee, what the consuming agent must not do with the output.
- Maintain a Service BOM (STA-16) of consuming systems — AIC-owned.
- Establish per-consumer credentials, scopes, and rate limits, so a single compromised consumer is containable.
- Where the consumer holds per-end-user tokens, assess L7-T10 explicitly; it is not assessable here.

**SSRM Ownership**
- Primary: OSP + AP + **Tool Provider**. The organization occupies the Tool Provider role for its MCP consumers — a 3SRM extension not yet recognized in AICM v1.1, and one where STA-16 (Service BOM) is AIC-owned.
- Shared: AIC.
- Agent Owner accountable: yes. Note that for the *consuming* organization, their Agent Owner is accountable for their agent's use of this tool — accountability does not transfer across the boundary in either direction, which is precisely why the boundary needs defining.
- **AICM structural gap flagged:** category 4 (cross-organizational agent collaboration). The current AICM catalog lacks a clean control for this pattern; naming the gap is more accurate than citing a tangential STA control as if it covered it.

---

### L6-T06 — API Abuse and Exfiltration

**MAESTRO Layer**
- L6: Tools, Application, Environment, and Ecosystem (Domain 2).

**Current Evidence**
- §7.1: `SafeguardExecRole` holds `s3:PutObject`, `dynamodb:PutItem`, `dynamodb:TransactWriteItems`, conditioned on enumerated resource ARNs, `aws:SourceVpce`, `dynamodb:LeadingKeys`, and a pinned SSE key.
- §5.1: the compute tier has no default route; only the egress proxy can reach the internet.
- §5.2: endpoint policies restrict principal, action, and inference profile ARN.
- §8: three-condition data perimeter including `aws:ResourceOrgID`.

**Assessment Status**
- Answerable.

**Attack Vector**
- Injected instructions inducing the adapter to write attacker-chosen data, or to write legitimate data to an attacker-chosen destination. The evidenced controls close the destination path comprehensively: `aws:ResourceOrgID` prevents writes outside the organization, enumerated ARNs prevent writes to unintended in-org resources, and the absence of a route prevents direct exfiltration. What remains open is writing *attacker-chosen content* to *legitimate destinations* — a data-integrity exposure rather than a confidentiality one, and one the specification does not address.

**Cross-Layer Impact**
- L3-T01 (injection source), L2-T03, L9 (a poisoned ledger write is indistinguishable from a legitimate one in hash-only telemetry).

**Likelihood / Impact / Risk**
- Likelihood: **Low to Medium** — requires successful injection first.
- Impact: **Medium** — bounded to integrity of the ledger and app bucket; the exfiltration path is genuinely closed.
- Risk: **Low to Medium**. Recorded substantially as covered.

**Recommended Mitigations**
- Validate adapter writes structurally — schema-constrained, with model-derived content confined to designated fields — so injection cannot alter record semantics.
- Include ledger integrity in the canary programme.

**SSRM Ownership**
- Primary: OSP + AP. Shared: AIC.
- Agent Owner accountable: yes.

---

### L7-T08 — Confused-Deputy Token Abuse

**MAESTRO Layer**
- L7: Identity and Autonomy (Domain 3, horizontal).

**Current Evidence**
- §4.3: explicit distinction between ID-token `aud` and access-token `client_id`, with the statement that `client_credentials` access tokens carry no `aud` claim.
- §4.4: validation matrix requiring `iss`, `token_use`, client binding, scope, and expiry per path.
- §4.5: JWKS pinned to the issuer URL rather than resolved from the token's own `iss`; RS256 only; `alg: none` and HMAC rejected.
- §4.5: REQUEST authorizer with per-method cache key; explicit prohibition on wildcard resource in the returned policy.
- §7.1: `sts:ExternalId` and session tags on the `SafeguardExecRole` → `KBRetrieveRole` hop; trust policies name source role ARNs, never account root.

**Assessment Status**
- Answerable.

**Attack Vector**
- The canonical form — a valid token accepted at the wrong audience or scope — is directly addressed. The specification's treatment of the caching hazard is notable: an authorizer returning a wildcard resource caches an over-broad policy against a scope-limited token, which reproduces exactly this threat inside the authorization layer itself. That is identified and closed.
- The residual is at L7-T06: the *tenant* assertion is a second identity dimension that this validation chain does not root.

**Cross-Layer Impact**
- L4 (delegation via role chaining), L6 (the MCP hop), L3 (what the misdirected authority reaches).

**Likelihood / Impact / Risk**
- Likelihood: **Low** for the token-audience form.
- Impact: **High** if realised.
- Risk: **Low**. Documented as covered — this is the strongest-specified area of the architecture.

**Recommended Mitigations**
- Maintain the per-method cache key; regression-test it, since a later change to a wildcard resource would silently reintroduce the flaw with no visible symptom.
- Apply the same rooting discipline to the tenant claim as is applied to the client binding (see L7-T06).
- Where the machine caller acts for end users, adopt token exchange (RFC 8693) with narrowed scope per delegation rather than a claim carried in a client-credentials token.

**SSRM Ownership**
- Primary: AIC (AP). Shared: CSP (Cognito), OSP.
- Agent Owner accountable: yes.

---

### L5-T02 — CI/CD Pipeline Compromise (guardrail weakening via legitimate deployment)

**MAESTRO Layer**
- L5: Deployment and Execution (Domain 2). Cross-references L8.

**Current Evidence**
- §7.2: three-role deployment chain with `iam:PassRole` conditioned on `iam:PassedToService`; GitHub OIDC with `sub` pinned to repository and environment; `DeploymentBoundary` denying self-detachment, privileged role creation, and action on audit and backup resources.
- §7.2: `DeploymentBoundary` denies **deletion of the Bedrock guardrail**.
- §17: guardrail configuration is version-controlled and reviewed as security-relevant code; `cfn-guard` encodes the SCP set; two-person approval on production.

**Reasonable Inferences**
- The pipeline can deploy guardrail *configuration changes*, since guardrail configuration is stated to be IaC under pipeline control. Bounded: the boundary explicitly denies deletion, which implies modification is permitted.

**Assessment Status**
- Answerable.

**Attack Vector**
- The deployment controls are strong against the conventional threat — malicious code injection, credential theft, privilege escalation. The specific gap is narrower: **weakening a guardrail is not deleting it.** An attacker with pipeline access, or an insider with commit and approval capability, can lower filter thresholds, remove denied topics, or narrow the sensitive-information filter through a legitimate, boundary-compliant, `cfn-guard`-passing deployment. The `bedrock:GuardrailIdentifier` condition continues to be satisfied because the guardrail still exists at the same ARN and version-pinning is at the deployment layer, not the enforcement layer.
- The two-person approval is the operative control here, and it is a process control rather than a technical one.

**Cross-Layer Impact**
- L8-T01 and L8-T02 (safety degradation without fine-tuning — a configuration-layer analogue), L2-T03, L10-T02 (policy bypass through a compliant channel).

**Likelihood / Impact / Risk**
- Likelihood: **Low** — requires pipeline compromise or insider access plus approval collusion.
- Impact: **High** — the architecture's primary AI-specific control is degraded while all enforcement layers continue to report success.
- Risk: **Medium**.

**Recommended Mitigations**
- Gate guardrail configuration changes on the adversarial regression corpus from L8-T05, as a blocking pipeline stage. A weakened guardrail then fails a test rather than passing a policy check.
- Pin the guardrail **version** in the IAM condition and require a separate, differently-approved change to advance it — so a configuration change does not take effect on the enforced version implicitly.
- Alarm on guardrail configuration change events as a security finding, independent of deployment tooling.
- Track intervention rate across the change boundary; a step change coinciding with a deployment is the signal.

**SSRM Ownership**
- Primary: CSP + OSP for L5 generally; **AP and AIC** for this specific finding, since guardrail configuration is application-layer and integration is AIC-owned.
- Shared: MP (guardrail service behaviour).
- Agent Owner accountable: yes.

**Required Evidence to Fully Answer**
- `DeploymentBoundary` policy document.
- Whether `bedrock:GuardrailIdentifier` conditions pin a numeric version or a bare identifier.

---

### L5-T06 — Deployment Rollback Exploitation

**MAESTRO Layer**
- L5: Deployment and Execution (Domain 2).

**Current Evidence**
- §17: stack policies protect the audit bucket, backup vault, KMS keys, and endpoint resources from replacement; drift detection is scheduled.
- §13: restore runbooks for data.
- No control on rollback to a prior application or guardrail version is evidenced.

**Assessment Status**
- Partially answerable.

**Attack Vector**
- Rollback to a version predating a security fix, or predating a guardrail tightening. The evidenced stack policies protect specific *resources* from replacement; they do not constrain which *version* of the application or guardrail configuration may be deployed.

**Cross-Layer Impact**
- L8 (guardrail version regression), L2.

**Likelihood / Impact / Risk**
- Likelihood: **Low**.
- Impact: **Medium**.
- Risk: **Low**.

**Recommended Mitigations**
- Maintain a minimum-acceptable-version floor enforced in the pipeline, so rollback below a security baseline fails.
- Subject rollbacks to the same adversarial regression gate as forward deployments.

**SSRM Ownership**
- Primary: CSP + OSP. Shared: AP, AIC (rollback policy and approval).
- Agent Owner accountable: yes.

---

### L1-T03 — Resource Exhaustion

**MAESTRO Layer**
- L1: Infrastructure (Domain 1).

**Current Evidence**
- §3: Shield Advanced; WAF rate-based rules at edge and regional scope.
- §11.3: three-tier consumption control with stated detection latencies at each tier and explicit acknowledgement that the billing tier is too slow to act alone.
- §11.4: cost anomalies routed to the security event bus.
- §6.1: on-demand inference with no provisioned throughput, so spend scales with volume.

**Assessment Status**
- Answerable.

**Attack Vector**
- Consumption as the attack. The specification identifies this correctly: for a metered inference endpoint, the abuse case succeeds while every access control functions as designed. The tiering — immediate application-layer budget, minutes-scale CloudWatch, day-scale Budget Actions — is the appropriate structure.

**Cross-Layer Impact**
- L2-T01 (shared controls), L9 (cost anomaly as a security signal), §11.

**Likelihood / Impact / Risk**
- Likelihood: **High** — trivially attempted.
- Impact: **Low to Medium** — bounded by the tier-1 control, provided the caller identity it keys on is sound. Note the dependency on L7-T06: if tenant identity can be asserted freely, per-identity budgets can be evaded by rotating the asserted tenant.
- Risk: **Medium**, and reducible to Low by resolving L7-T06.

**Recommended Mitigations**
- Resolve L7-T06; the tier-1 budget is only as sound as the identity it counts against.
- Apply a per-`client_id` ceiling in addition to the per-tenant one, so tenant rotation does not multiply the budget.

**SSRM Ownership**
- Primary: CSP. Shared: AIC (rate limiting and budgets), AP.
- Agent Owner accountable: yes.

---

### L1-T01 — Infrastructure Compromise via Supply Chain

**MAESTRO Layer**
- L1: Infrastructure (Domain 1).

**Current Evidence**
- §17: Inspector scans code and dependencies before artifact promotion; `cfn-guard` and `checkov` block on high severity.
- §5.3: Network Firewall carries package-registry access during build.
- Lambda managed runtime; no container images or self-managed base images are evidenced.

**Assessment Status**
- Answerable.

**Attack Vector**
- Compromised third-party package in the Express adapter's dependency tree. Inspector coverage is evidenced; what is not evidenced is dependency pinning, lockfile integrity verification, or provenance attestation, and the build-time registry path through the firewall is an allow-listed egress that carries executable content.

**Cross-Layer Impact**
- L5-T02, L6 (dependency ecosystem), L8 (a compromised dependency in the adapter reaches the tagging logic §18.1 identifies as security-relevant).

**Likelihood / Impact / Risk**
- Likelihood: **Medium** — the ecosystem-level base rate.
- Impact: **High** — adapter code compromise reaches guardrail tagging and write permissions.
- Risk: **Medium**.

**Recommended Mitigations**
- Pin dependencies with integrity hashes; verify lockfiles in the pipeline.
- Maintain an SBOM alongside the Service BOM recommended at L10-T06.
- Restrict the build-time registry allow-list to a private mirror rather than public registries.

**SSRM Ownership**
- Primary: CSP for infrastructure; **AP** for application dependencies. Shared: OSP.
- Agent Owner accountable: yes.

---

## 9. Cross-Layer Path Analysis

Four paths are supported by the evidence. Path 1 is the most consequential.

**Path 1 — Tenant assertion to cross-tenant disclosure.**
`L6` (an external MCP caller asserts a tenant) → `L7-T06` (the assertion is validated for membership, not entitlement) → `L3-T02` (retrieval is not tenant-filtered) → `L2` (the model reproduces the retrieved content) → `L6-T06` (the response leaves through the API).
Every step uses a valid credential and triggers no guardrail, because disclosed content is not unsafe content. The `dynamodb:LeadingKeys` condition — the architecture's most precise tenant control — is enforced correctly against a compromised input, and the audit trail records the attacker's asserted tenant, so the event is invisible in review. This path is entirely composed of controls working as designed.

**Path 2 — Corpus poisoning to state change.**
`L3-T01` (no evidenced ingestion validation) → `L2-T03` (injected instruction arrives as grounding context) → `L8-T01` (§18.1's tagging residual means retrieved content may sit outside the evaluated region) → `L6-T06` (adapter write permissions execute).
The architecture's write-path controls are strong on *destination* and silent on *content*, so the terminal impact is integrity rather than exfiltration.

**Path 3 — Pipeline access to safety degradation.**
`L5-T02` (pipeline compromise or insider commit) → guardrail configuration weakened through a boundary-compliant, `cfn-guard`-passing deployment → `L8-T01` / `L8-T02` → `L2-T03`.
All three guardrail enforcement layers continue to report success throughout, because the guardrail still exists at the pinned identifier. Detection depends on the intervention-rate trend at §19 and on two-person approval — one lagging signal and one process control.

**Path 4 — Governance boundary to unguarded inference.**
`L10-T01` (SCPs scoped to the workload OU) → the ML account invokes Bedrock outside guardrail and inference-profile enforcement → `L2` unguarded inference on production-derived data → `L9` (no cost attribution, so the activity is also financially invisible).

**Not supported by the evidence.** No path involving sub-agent delegation, agent-to-agent propagation, orchestration hijack, or tool-definition poisoning is supported — those require an orchestration or tool-invocation surface this system does not have.

---

## 10. SSRM Ownership Summary

**Deployment model.** This is not an agent deployment, so the AaI / AaP / AaaS taxonomy applies only by analogy. The closest fit is **Agent-as-Infrastructure (AaI)**: the organization builds and operates the application on rented infrastructure, consuming foundation models from a provider and controlling everything above them. Role mapping is therefore **AIC + AP + OSP** for the organization, with a material second-MP relationship for the external inference provider.

| Layer | CSP | MP | OSP | AP | Tool Prov | AIC / Agent Owner | Assessment note |
|---|---|---|---|---|---|---|---|
| L1 | **P** | — | — | — | — | C/A | AWS as CSP; org configures. Strong coverage |
| L2 | S | **P** | S | — | — | C/A | Two MPs: AWS Bedrock (attested) and the external provider (**unattested** — L2-T04) |
| L3 | S | S | S | S | — | **P**/A | AIC-primary and the layer with the two largest gaps (L3-T01, L3-T02) |
| L4 | — | S | **P** | S | S | S/A | Minimal surface; no orchestration platform in play |
| L5 | **P** | — | **P** | S | — | C/A | Org occupies OSP here; strongest-specified layer |
| L6 | — | S | **P** | **P** | **P** | S/A | **Org is Tool Provider to its MCP consumers** — role unacknowledged in the specification |
| L7 | S | — | S | S | S | **P**/A | AIC-primary; AWS-principal identity excellent, caller-tenant identity unrooted |
| L8 | S | S | S | S | S | **P**/A | AIC is integrating authority; enforcement strong, failure semantics and testing absent |
| L9 | S | S | S | S | S | **P**/A | Genuinely audit-grade — uncommon and worth recording as a strength |
| L10 | C | C | C | C | C | **P**/A | Infrastructure governance strong; AI-specific governance absent |

**Non-delegable accountability.** Quoted directly per the 3SRM: *"In all three deployment models, Layer 10 (Governance) remains with the Agent Owner. Governance cannot be outsourced."* The Agent Owner bears ultimate accountability for all system behaviour regardless of which provider's component was the proximate cause — including the external inference provider at L2-T04 and any MCP consumer's misuse of the interface at L6.

**AICM structural gaps flagged.** Category 4 (cross-organizational agent collaboration) applies at the MCP consumer boundary. AICM v1.1 lacks a clean control for defining responsibility across that boundary; the gap is named here rather than papered over with a tangential STA citation.

---

## 11. Framework Crosswalk

Omitted. STRIDE, MITRE ATLAS, OWASP LLM/Agentic Top 10, NIST AI RMF, and ISO/IEC 42001 alignment were not requested. MAESTRO is the primary and only spine used.

Two crosswalk observations surfaced during analysis and are recorded because they bear on findings above rather than as a substitute for a crosswalk: OWASP T17 (semantic drift in embeddings) maps to the L9-T03 finding, and OWASP T18 (RAG input manipulation) maps to L3-T01. The ISO 42001 coverage note at L10-T06 is included because it materially changes what certification would and would not attest for this architecture.

---

## 12. Required Validation Steps

Ordered by how much each would change the assessment.

1. **Pre-token-generation trigger source and authorizer tenant validation path.** Resolves L7-T06 from High to Low, or confirms High. Highest-value single artifact.
2. **Knowledge base configuration export** showing metadata filter definitions, plus a corpus tenancy statement. Resolves L3-T02.
3. **Ingestion architecture for the KB data-source bucket** — writer inventory, content validation, approval workflow. Resolves L3-T01 from Unassessable.
4. **Egress proxy source**, specifically the exception path around `ApplyGuardrail`. Resolves L8-T03.
5. **Organizational unit structure and SCP attachment points.** Resolves L10-T01.
6. **`DeploymentBoundary` policy document** and the guardrail IAM conditions, showing whether a numeric guardrail version is pinned. Resolves L5-T02's residual.
7. **Adapter prompt-assembly code** showing how retrieved chunks are delimited and whether they fall inside the guardrail-evaluated region. Bears on L3-T01, L2-T03, L8-T01.
8. **Statement of downstream consumption** — what acts on the model output. Blocks GRC-15 assessment at L10-T06.
9. **External inference provider attestation** and whether inbound responses are guardrail-evaluated. Resolves L2-T04.
10. **Contractual artifacts** (3SRM §6.2): AI-CAIQ responses from the external inference provider as a contractual annex; shared-responsibility addenda mapping provider obligations to 3SRM layers; audit-rights clauses; safety SLAs covering escalation response time and behavioural drift thresholds.
11. **Restore exercise results.** The specification itself notes that measured RTO is discoverable only by execution; until then §13.3 is design intent.

---

## 13. Conclusion: What Can and Cannot Be Concluded

**What can be concluded.**

This architecture is unusually strong at the layers most security reviews cover and has a consistent, characteristic weakness at the layer that distinguishes AI systems from conventional ones. The infrastructure, deployment, and AWS-principal identity work (L1, L5, L7) is among the more completely specified this framework is applied to: the data perimeter is enforced by condition key rather than convention, the deployment chain separates the ability to start a stack operation from the permissions to mutate resources, and the audit layer genuinely meets the audit-grade criterion — tamper-evident, retained, segregated, queryable — which is uncommon enough to record explicitly.

The weakness is that *identity of the caller* and *identity of the data* are treated with less rigour than identity of the AWS principal. The tenant claim is validated for membership rather than entitlement (L7-T06). Retrieval is not tenant-scoped while both other datastores are (L3-T02). The corpus has a storage boundary and no content boundary (L3-T01). These three compose into Path 1, which is the finding that matters most: a cross-tenant disclosure achieved entirely through controls operating as designed, invisible in the audit trail because the audit trail faithfully records the attacker's assertion.

Two further conclusions hold independently. The guardrail enforcement architecture is correct and its residual is honestly documented, but guardrail *quality* is unmeasured — inferred from intervention rate rather than tested against adversarial input (L8-T05) — and a guardrail can be weakened rather than deleted through a compliant deployment (L5-T02, Path 3). And the specification governs the infrastructure of an AI system thoroughly while containing no AI-specific governance at all: no impact assessment, no acceptable-use position, no human-oversight definition, no regulatory mapping (L10-T06).

**What cannot be concluded.**

Nothing about implementation. This is a design document, and design intent is not control. No finding above should be read as a statement that a control is or is not present in a deployed environment.

Nothing about the MCP consumer boundary beyond its existence. Per skill rule 5, MCP-specific threats are not inferred from a caller class label. Whether L7-T10 (MCP-service token isolation failure) applies is unanswerable, and it is the threat most likely to compound L7-T06 if the consumer holds per-end-user tokens.

Nothing about regulatory exposure, because the use case is unstated. The gap at L10-T06 is certain; its consequence is not calculable without knowing what the system is for and who it affects.

Nothing about multi-agent risk, orchestration compromise, or tool-invocation abuse — those surfaces do not exist in this system, and their absence from this assessment is a property of the architecture rather than a limitation of the analysis. Should tool use, Bedrock Agents, or sub-agent delegation be introduced later, L4, L6, and the multi-agent threat categories become live and this assessment requires re-scoping rather than extension.

---

## 14. Single Clarifying Question

Does the pre-token-generation Lambda trigger derive the tenant claim from an authoritative server-side mapping keyed on `client_id`, or does it accept a tenant value supplied by the client in the token-endpoint metadata?

This single answer determines whether L7-T06 is a High-risk authorization flaw and Path 1 is live, or whether both collapse to Low — and it also governs whether the tier-1 cost budget at L1-T03 can be evaded by tenant rotation.
