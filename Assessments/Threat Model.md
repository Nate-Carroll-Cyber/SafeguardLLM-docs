# MAESTRO v2.0 Threat Model — Safeguard LLM v2.5

*Adversary-Aware Prompt Firewall & Forwarding Gateway (`counter-spy`)*
*Framework: MAESTRO v2.0 (CSA, Apr 2026). Assessment date: 2026-08-03 (rev. — controls dimension added). Evidence: `github.com/Nate-Carroll-Cyber/SafeguardLLM-docs` (`main`).*

**What changed in this revision.** The threat set and findings are unchanged in
substance. Each Section 8 block now carries a **Controls** field drawing from
three sources: the AI Threat Technique Taxonomy (`AITech-*` / `AISubtech-*`), the
FAIR-CAM GenAI Control Library (function-classed as Prevention / Detection /
Response / Variance / Decision), and the Trust & Identity-Lifecycle taxonomy with
its CSA AICM v1.1 controls and ISO/IEC 42001:2023 clauses. One threat block is
new (**L9-T03**), surfaced by applying the trust-decay lens. Section 14 is new: a
consolidated control register.

**Secondary-lens discipline.** MAESTRO remains the spine. `AITech-*` IDs,
FAIR-CAM control names, AICM control IDs, and ISO clauses **enrich** a finding
whose MAESTRO layer threat is established first; they are never substituted for
`L<n>-T<nn>`. Control IDs should be reconciled against the authoritative AICM
v1.1 catalog and the live ATLAS matrix before audit-grade citation.

---

## 1. Understanding Confirmed

The target is a **security control-plane / LLM firewall**, not a general
autonomous agent. It mediates every prompt before inference using a two-stage
"Shield-and-Sword" pattern: a client-side TypeScript **Shield** (heuristic
detection, redaction, obfuscation decoding) and a backend **Sword** path
(`/v1/intercept`) that runs deterministic prechecks, an optional pgvector
instruction-similarity monitor, an OpenAI-compatible **safeguard judge**, and —
only for `CLEAN` verdicts — forwards to a pluggable **downstream responder**
(OpenAI or Gemini). It also hosts a governed "Sam Spade" CTF elicitation
scenario. This assessment maps that evidenced surface across the ten MAESTRO
layers and, in this revision, to a named control set per finding.

## 2. Scope and Assumptions

- **In scope:** the documented architecture, models, data stores, dependencies, auth model, detectors, and data flows in the analyzed docs.
- **Deployment model:** Evidenced as transitional **Agent-as-Infrastructure (AaI)** today (self-built on local/Firebase + Docker Compose; Owner = AIC + AP + OSP) moving toward **Agent-as-Platform (AaP)** (AWS ECS Fargate / API Gateway / Bedrock — *target-state, not implemented*). Where ownership depends on this, it is flagged.
- **Assumption (bounded):** frontier providers (OpenAI, Google) act as **MP**; LM Studio/Ollama hosts act as self-operated MP/CSP in the demo.
- MAESTRO is built for agentic systems and is **partially over-scoped** here: Safeguard LLM has tool-use (forwarding, translate, embeddings) and memory (pgvector), but limited autonomy and no documented multi-agent delegation chain. L4/L6 are assessed narrowly against what is evidenced.
- **Controls scope:** the FAIR-CAM library is used as a mitigation *source*, not as a maturity assessment — a control named in a recommendation is not asserted to exist. Where a control is evidenced as present, it is stated so explicitly.
- This is a defensive assessment. No exploit code is produced.

## 3. System Summary

Safeguard LLM is a policy-enforcing GenAI gateway. Its own product function *is*
an L8 safety control (prompt-injection/jailbreak/obfuscation detection), which
makes the assessment partly recursive: many L8 threats concern the **failure or
bypass of the very detectors that are the product**. The system is strongly
fail-secure (judge failure → 202 + `FAIL_SECURE` + Global Pause; ReDoS >1000ms →
block + Global Pause; frontend 45s hang → abort, no local fallback inference). It
keeps provider secrets out of the browser bundle and only sends **redacted**
prompts to any model.

The two load-bearing weaknesses evidenced are (a) **coarse identity** — a shared
static bearer token on all execution routes, with JWT/OIDC "not implemented" —
and (b) several **target-state controls** (production auth, CSP, rate limiting,
Z-score incidenting, Secrets Manager) that are documented but not yet built. It
is **not** a purely passive chatbot (it has memory, tools, and orchestration), so
the full L1–L10 spine is retained, with empty layers stated explicitly.

**Controls-lens observation.** Applying the FAIR-CAM function classes to the
evidenced control set produces an asymmetry worth naming up front: Safeguard LLM
is dense in **Loss Event Controls — Prevention · Resistance** (detectors,
redaction, egress restriction, fail-secure) and **Response · Event Termination**
(Global Pause), and thin in **Variance Management Controls** — the controls that
keep other controls working. There is no evidenced access review, no credential
rotation, no periodic policy review, and no inventory of components. A system
whose product *is* a control, with no variance management over that control, is
the specific shape that degrades silently.

## 4. Evidence Available

Architecture (Shield-and-Sword, `/v1/intercept` flow, fail-secure matrix); models
(`gpt-oss-safeguard-20b` / `gpt-5.4-mini` judge; OpenAI/`gemini-2.5-flash`
responder; `nomic-embed-text` 768-dim embeddings); data stores (Firestore
US-West2; pgvector `pgvector:pg16`; SQLite Sam Spade; in-memory); `core` seed
corpus (319 records/611 chunks, SHA-256 verified); instruction-similarity
thresholds; detector/flag glossary; SBOM with pinned CVE-mitigating versions;
Firestore rules; auth model (Firebase Google OAuth for UI, shared bearer token
for API, `x-counter-spy-user-id` for Sam Spade); egress policy (embeddings
private-network only; Lara backend-only); telemetry event schema; MITRE ATLAS
16-node organizer.

## 5. Immediate Gaps / Missing Information

- **Production identity/authz:** JWT/OIDC validation, IAM SigV4, and an API-layer RBAC matrix are **planned, not implemented**. Current API auth = shared static bearer token.
- **Inference parameters** (temperature/top_p) for judge and responder — undocumented.
- **Audit-log tamper-evidence:** Firestore audit logs are rich but no WORM/immutability or tamper-evidence is evidenced. Retention is "intended permanent" with optional TTL.
- **Rate limiting / DoS controls** at the gateway beyond the ReDoS breaker — none documented.
- **Content Security Policy** — explicitly a "Known Gap"; `react-markdown` raw-HTML relies on library default.
- **AWS target architecture** (Bedrock wiring, VPC topology, CloudWatch collector) — target-state, undocumented in detail.
- **Third-party model provenance / training data** (OpenAI, Google, Nomic) — opaque.
- **`Technical/File_Structure.md`** referenced but served empty — full file tree not captured.
- **Control ownership records** — no evidenced registry assigning an owner, intent, or review cadence to any component. This blocks every Variance Management Control in Section 14.
- **Contradiction flagged:** earlier docs claimed PII redaction occurs "before data leaves the client"; SESSION_HANDOFF corrects this — backend routes own redaction on protected paths. Treat the client-side-redaction claim as superseded.

## 6. MAESTRO Layer Mapping

| Layer | Evidenced components in Safeguard LLM | Status |
|---|---|---|
| **L1 Infrastructure** | Docker multi-stage builds; `pgvector/pgvector:pg16`; non-root `node`/`su-exec`; localhost-bound Postgres (`127.0.0.1:15432`, SCRAM, tmpfs); demo hosts `192.168.0.183`; AWS ECS/Fargate (target) | Partially evidenced |
| **L2 Cognitive Core** | Safeguard judge (`gpt-oss-safeguard-20b` / `gpt-5.4-mini`); downstream responder (OpenAI / `gemini-2.5-flash`); `nomic-embed-text`; Safeguard Effective Prompt (drift hash `590a286e…`) | Evidenced |
| **L3 Data, Memory, Knowledge** | pgvector instruction-similarity store; `core` seed corpus (319/611); Firestore KB/Golden Set; SQLite Sam Spade sessions; browser in-memory state; MITRE ATLAS corpus (569 prompts) | Evidenced |
| **L4 Orchestration & Coordination** | Backend intercept orchestration (precheck → monitor → judge → responder); HITL/HOTL; Global Pause; Sam Spade NPC scenario engine | Evidenced (single-agent) |
| **L5 Deployment & Execution** | Docker Compose demo stack; validation gates (lint/test/build); planned ECS Fargate | Partially evidenced |
| **L6 Tools, Application, Ecosystem** | Downstream LLM forwarding; Lara Translate (`/v1/translate`); Ollama embeddings; MCP/A2A **detection** policy (not an MCP client) | Evidenced (tool-use, no multi-agent) |
| **L7 Identity & Autonomy** | Firebase Google OAuth (UI); shared static bearer token (API); `x-counter-spy-user-id`; owner-scoped Sam Spade; Firestore role rules | Evidenced (with gaps) |
| **L8 Safety & Security** | The product itself: Shield detectors, obfuscation strict-mode, instruction-similarity monitor, safeguard judge, output sanitization, fail-secure, canary token, Global Pause | Evidenced (core surface) |
| **L9 Monitoring & Observability** | Structured JSON events; Metrics dashboard (Defense Funnel, Feature Pressure, threat velocity); Firestore audit trail; planned CloudWatch/Z-score | Evidenced (with gaps) |
| **L10 Governance & Compliance** | MITRE ATLAS mapping; Operations Guide/SOPs; Golden Set governance; firestore.rules; documented EU AI Act/PII posture | Evidenced |

*No layer is empty. Multi-agent threat categories (cascading leaks, collusion, delegation escalation) are **not applicable** — no autonomous multi-agent delegation is evidenced.*

## 7. Assessment Status by Layer

- **L1** — Partially Answerable (demo infra evidenced; production infra target-state).
- **L2** — Partially Answerable (judge/responder/embeddings evidenced; weights & inference params opaque).
- **L3** — Answerable (data stores, memory, and context surfaces well evidenced).
- **L4** — Answerable for single-agent orchestration; multi-agent categories N/A.
- **L5** — Partially Answerable (demo deploy evidenced; CI/CD & prod runtime undocumented).
- **L6** — Answerable for tool-use; MCP client threats N/A (MCP is detection-only, not consumed).
- **L7** — Answerable — this is the primary finding area.
- **L8** — Answerable — the core product surface.
- **L9** — Partially Answerable (rich telemetry; audit-grade tamper-evidence unproven; incidenting not implemented).
- **L10** — Answerable.

---

## 8. Detailed Threat Analysis

Each block ends with a **Controls** field. Format: technique ID (OWASP / ATLAS) ·
FAIR-CAM control and function class · AICM v1.1 control · ISO/IEC 42001 clause ·
matching Trust-taxonomy threat name where one applies. **Present** marks a
control evidenced in the repository; **Recommended** marks one that is not.

### L2-T03 — Prompt Injection / Jailbreak (against the judge and responder)

**MAESTRO Layer** — L2 Cognitive Core (Domain 1).

**Current Evidence** — The safeguard judge receives a **redacted** candidate prompt plus neutral preprocessing evidence (flags, entropy, syntactic score) — *not* the local Shield's verdict/reasoning. Judge returns strict JSON `{verdict, analystReasoning}`. Downstream responder only sees `CLEAN` prompts. Obfuscation strict-mode treats any recognized encoding as Adversarial (Pig Latin excepted).

**Reasonable Inferences** — A jailbreak that survives Shield heuristics and does not match the pgvector corpus depends entirely on the judge's own alignment; a judge false-negative forwards adversarial content to the responder.

**Unknowns / Missing Evidence** — Judge model alignment/eval coverage; temperature (non-determinism could yield inconsistent verdicts — cf. OWASP T16); whether the responder has independent guardrails.

**Assessment Status** — Partially Answerable.

**Attack Vector** — Novel jailbreak phrasing with low entropy, no recognized obfuscation family, no SimHash/embedding match to the 319-record corpus → passes Shield + monitor → judge misclassifies `CLEAN` → forwarded to responder.

**Cross-Layer Impact** — L8 (guardrail bypass), L3 (corpus only covers reviewed-ADVERSARIAL history), L6 (responder invocation).

**Likelihood / Impact / Risk** — Likelihood Medium (defense-in-depth reduces it, but judge is the single semantic gate); Impact Medium–High (adversarial content reaches responder + user); **Risk Medium-High**.

**Recommended Mitigations** — Continuous judge red-teaming (MDS-06); pin/track judge model + Safeguard Effective Prompt drift hash (already present — `590a286e…`); add responder-side guardrails as defense-in-depth; log judge non-determinism via existing `safeguard.divergence` metric and alert on verdict flips for identical hashes.

**Controls**

| Lens | Reference |
|---|---|
| Technique | `AISubtech-2.1.1` Context Manipulation (LLM01 / `AML.T0054`); `AISubtech-2.1.3` Semantic Manipulation |
| FAIR-CAM | *Detection · Visibility* — Intrusion detection for GenAI applications — **Present** (`safeguard.divergence` metric, Defense Funnel) · *VMC Identification · Monitoring* — Application vulnerability testing, periodic — **Recommended** (this is the red-teaming cadence) |
| AICM v1.1 | `TVM-11` Guardrails — **Present** · `MDS-06` Adversarial Attack Analysis — **Recommended** · `AIS-15` Prompt Differentiation — **Present** (judge receives evidence, not Shield's verdict, which is exactly this control) |
| ISO 42001 | A.6.1 Responsible Design Process; A.6.2.6 Operation & Monitoring |
| Trust taxonomy | *Policy Enforcement Bypass* (T-G, ASI10) |

**Note on AIS-15.** Withholding the Shield's verdict from the judge is a
deliberate prompt-differentiation control and an unusually clean implementation
of it — the judge cannot be anchored by an upstream decision. Preserve it; a
future "efficiency" change that passes the Shield verdict forward would collapse
two independent gates into one.

**SSRM Ownership** — Primary: MP (judge/responder alignment). Shared: OSP, AP (integration), CSP (hosting). Agent Owner accountable: yes (always).

**Required Evidence to Fully Answer** — Judge eval/red-team results; inference params; responder guardrail config.

---

### L2-T04 — Model Supply-Chain Attack (judge/responder/embedding provenance)

**MAESTRO Layer** — L2 Cognitive Core (Domain 1).

**Current Evidence** — Judge presets point to a local LM Studio model and OpenAI; responder is OpenAI/Gemini; embeddings are `nomic-embed-text` via Ollama, restricted to private network. No model-weight checksums are recorded in the repo (contrast with the seed-corpus SHA-256, which *is* verified).

**Reasonable Inferences** — A compromised local `gpt-oss-safeguard-20b` or `nomic-embed-text` artifact (open-weight, pulled from a registry) could silently degrade detection.

**Unknowns / Missing Evidence** — Weight integrity verification; Ollama/LM Studio image provenance.

**Assessment Status** — Partially Answerable.

**Attack Vector** — Backdoored open-weight judge/embedding model returns attacker-favorable verdicts or embeddings that never match the adversarial corpus.

**Cross-Layer Impact** — L1 (image/registry), L8 (detection integrity), L3 (embedding-space poisoning).

**Likelihood / Impact / Risk** — Likelihood Low–Medium; Impact High (defeats the control silently); **Risk Medium**.

**Recommended Mitigations** — Record and verify SHA-256/signatures for judge and embedding weights (extend the existing seed-hash discipline to models); pin Ollama/LM Studio versions (already `0.23.2`); image signing/scanning (L1).

**Controls**

| Lens | Reference |
|---|---|
| Technique | Supply-chain family (LLM03 / `AML.T0010` ML Supply Chain Compromise) |
| FAIR-CAM | *VMC Identification · Monitoring* — Hardening review for GenAI usages — **Recommended** · *VMC Identification · Monitoring* — Inventory of permitted GenAI applications — **Recommended** (no model inventory evidenced) |
| AICM v1.1 | `STA-08` Supply Chain Inventory — **Recommended** · `STA-16` Service Bill of Material — **Recommended** · `STA-12` Supply Chain Compliance — **Recommended** |
| ISO 42001 | A.10.3 Suppliers; A.7 Data & Model Resources |
| Trust taxonomy | *Trust Assertion Forgery* (T-H, ASI04) |

**Note on the SBOM asymmetry.** A dependency SBOM with pinned CVE-mitigating
versions is evidenced. No equivalent exists for **model weights** — the artifact
whose compromise is silent rather than noisy. `STA-16` covers both; extending the
existing SBOM discipline to the model layer is a smaller change than it appears,
because the integrity practice already exists for the seed corpus.

**SSRM Ownership** — Primary: MP. Shared: CSP (registry/hosting). Agent Owner accountable: yes.

**Required Evidence to Fully Answer** — Model weight hashes; registry provenance.

---

### L3-T01 / CE-T1 — Instruction-Similarity Corpus Poisoning

**MAESTRO Layer** — L3 Data, Memory, Knowledge (Domain 1).

**Current Evidence** — pgvector stores **reviewed-`ADVERSARIAL`-only** fingerprints; `observe()` refuses to persist clean/suspicious/unreviewed entries. Promotion to reviewed-ADVERSARIAL is via authenticated `/v1/instruction-monitor/reviewed-adversarial`. `core` seed is SHA-256-verified and immutable rows fail closed unless `--allow-seed-update`.

**Reasonable Inferences** — Poisoning requires abusing the review/promotion path (an authz problem, see L7), since arbitrary prompts cannot self-persist. Conversely, an attacker who can mark **benign** patterns as ADVERSARIAL could induce false-positive blocking (availability/DoS-by-policy).

**Unknowns / Missing Evidence** — Who (which role) may call the reviewed-adversarial endpoint; approval workflow for promotion.

**Assessment Status** — Partially Answerable.

**Attack Vector** — Holder of the shared bearer token promotes crafted fingerprints (either to whitelist an attack family by omission, or to poison with benign look-alikes causing over-blocking).

**Cross-Layer Impact** — L7 (authz on promotion), L8 (detector integrity), L10 (policy).

**Likelihood / Impact / Risk** — Likelihood Medium (gated only by shared token); Impact Medium; **Risk Medium**.

**Recommended Mitigations** — Restrict the reviewed-adversarial endpoint to Administrator role under per-user OIDC identity (see L7); dual-control/approval for corpus writes; the seed immutability + fail-closed behavior is a strong existing control to extend to runtime writes.

**Controls**

| Lens | Reference |
|---|---|
| Technique | `AISubtech-5.1.1` Long-term Memory Injection (ASI06 / `AML.TA0007`); `AISubtech-6.1.2` Reinforcement Biasing (LLM04 / `AML.T0020`) |
| FAIR-CAM | *LEC Prevention · Avoidance* — Access privileges restrict access to sensitive info — **Partial** (Firestore rules yes; API layer no) · *DSC Prevention · Expectations* — Data classification policy documented — **Recommended** |
| AICM v1.1 | `DSP-21` Data Poisoning Prevention — **Partial** (write-path restriction present, approval workflow absent) · `DSP-23` Data Integrity Check — **Present** for the seed, **Recommended** for runtime writes · `IAM-18` Special Authorization — **Recommended** |
| ISO 42001 | A.6.2.6 Operation & Monitoring; 6.3 Planning of Changes; A.7.4 Quality of Data for AI Systems |
| Trust taxonomy | *Historical Context Poisoning* (T-B, ASI06); *Preference Persistence Attacks* (T-B) |

**Note on the two-sided threat.** `DSP-21` is usually read as preventing
*malicious* content entering a corpus. Here the inverse is equally available:
promoting benign patterns as ADVERSARIAL turns the detector into a
denial-of-service against legitimate users, and no control in the evidenced set
addresses it. `DSP-23` (integrity check) applied to runtime writes — a review
that the promoted fingerprint actually corresponds to observed adversarial
traffic — is the control that covers both directions.

**SSRM Ownership** — Primary: AIC (data governance). Shared: OSP (pipeline), MP (embedding integrity). Agent Owner accountable: yes.

**Required Evidence to Fully Answer** — Promotion RBAC and approval workflow.

---

### L3-T02 — Vector Database Access-Control Bypass

**MAESTRO Layer** — L3 (Domain 1).

**Current Evidence** — Postgres is **localhost-bound** (`127.0.0.1:15432`), SCRAM auth, tmpfs in demo, connection/DDL/slow-query logging, statement timeout, connection caps. Production is directed to replace tmpfs with managed persistent storage.

**Reasonable Inferences** — Demo posture is hardened for local use; production managed store introduces new network-exposure surface not yet documented.

**Unknowns / Missing Evidence** — Production DB network policy, encryption at rest, IAM.

**Assessment Status** — Partially Answerable.

**Attack Vector** — In production, a misconfigured managed pgvector instance exposes adversarial-prompt embeddings/fingerprints.

**Cross-Layer Impact** — L1 (network), L7 (DB credentials).

**Likelihood / Impact / Risk** — Likelihood Low (demo); Unassessable for production (undocumented); **Risk Low-Medium**.

**Recommended Mitigations** — VPC isolation, encryption at rest, IAM-auth DB access, no public exposure; carry the localhost-bound discipline into production network policy.

**Controls**

| Lens | Reference |
|---|---|
| Technique | `AISubtech-14.1.2` Insufficient Access Controls (ASI03 / `AML.TA0006`) |
| FAIR-CAM | *LEC Prevention · Resistance* — AES-256 encryption for data at rest — **Recommended** (unevidenced) · *LEC Detection · Monitoring* — No unauthenticated public data repository — **Present** in demo (localhost-bound), **Recommended** as a production assertion |
| AICM v1.1 | `I&S-06` Segmentation and Segregation — **Recommended** · `IAM-15` Secrets Management — **Recommended** (DB credential currently in `.env`) |
| ISO 42001 | A.4.3 Data Resources; 10.2 Nonconformity & Corrective Action |
| Trust taxonomy | *Cross-Tenant Trust Violations* (T-C, ASI03/ASI06) — applies only if the production deployment becomes multi-tenant |

**SSRM Ownership** — Primary: CSP (storage). Shared: AIC (config). Agent Owner accountable: yes.

**Required Evidence to Fully Answer** — Production DB architecture.

---

### L3-T07 / CE-T6 — Context Overflow / Compression Loss

**MAESTRO Layer** — L3 (Domain 1).

**Current Evidence** — `INSTRUCTION_MONITOR_EMBEDDINGS_MAX_CHUNKS=4`; chunked overlapping embeddings; entropy analysis on sliding windows; Bulk Ingest supports large runs (Screen Wake Lock).

**Reasonable Inferences** — Very long prompts split into chunks could dilute an injected instruction below per-chunk similarity thresholds (chunk `>0.72`), or push content past the judge's context window.

**Unknowns / Missing Evidence** — Judge context length; behavior when prompt exceeds max chunks.

**Assessment Status** — Partially Answerable.

**Attack Vector** — Oversized prompt with an injected instruction spread thin across chunks to evade both similarity thresholds and judge attention.

**Cross-Layer Impact** — L8 (detection evasion), L2 (judge context limits).

**Likelihood / Impact / Risk** — Likelihood Medium; Impact Medium; **Risk Medium**.

**Recommended Mitigations** — Enforce max input length before judge; treat over-length/over-chunk inputs as Suspicious → review (consistent with fail-secure posture); the "Sandwich Delta >0.20" heuristic already targets dilution — validate its coverage under chunk-splitting.

**Controls**

| Lens | Reference |
|---|---|
| Technique | `AISubtech-4.2.1` Context Window Exploitation (ASI06 / `AML.T0051.002`) |
| FAIR-CAM | *LEC Prevention · Resistance* — Rate limiting for Internet-exposed apps — **Recommended** (input-size limiting is the same control class applied to payload rather than frequency) |
| AICM v1.1 | `AIS-08` Input Validation — **Partial** (chunking and entropy present; no evidenced length ceiling) · `DSP-24` Data Differentiation — **Present** (chunk boundaries) |
| ISO 42001 | A.6.2.4 AI System Verification; A.7.2 Development Data Requirements |
| Trust taxonomy | *Context Inheritance* (T-B, ASI06) |

**SSRM Ownership** — Primary: AIC. Shared: OSP, MP. Agent Owner accountable: yes.

**Required Evidence to Fully Answer** — Length-handling logic; judge context size.

---

### L4-T07 — Human-in-the-Loop Bypass

**MAESTRO Layer** — L4 Orchestration & Coordination (Domain 2).

**Current Evidence** — HITL routes borderline traffic to `PENDING_REVIEW`; HOTL Global System Pause is the DEFCON-1 kill switch; expected mapping `SUSPICIOUS → QUEUED (202)`. Unreviewed Suspicious rolls into operational Review.

**Reasonable Inferences** — The review queue is a **display/operational** state; if a state-changing action (e.g., KB/Golden-Set promotion, verdict override) does not hard-gate on human approval, it could proceed without it.

**Unknowns / Missing Evidence** — Whether any high-consequence action can execute without completing review; per-action approval enforcement.

**Assessment Status** — Partially Answerable.

**Attack Vector** — Operator or token-holder performs a state-changing operation that should require review, exploiting a soft (advisory) gate.

**Cross-Layer Impact** — L7 (authz), L10 (governance), L8 (safety-state changes).

**Likelihood / Impact / Risk** — Likelihood Low–Medium; Impact Medium; **Risk Medium**.

**Recommended Mitigations** — Hard-gate high-consequence actions behind CIBA/RAR out-of-band approval (see governance assessment); make Global Pause states enforce, not advise.

**Controls**

| Lens | Reference |
|---|---|
| Technique | `AISubtech-5.2.1` Agent Profile Tampering (ASI01 / `AML.TA0007`) — the configuration-persistence analogue of a soft gate |
| FAIR-CAM | *LEC Response · Event Termination* — Documented incident response process — **Present** (Global Pause + SOPs) · *DSC Prevention · Expectations* — Acceptable Use Policy exists for GenAI — **Recommended** |
| AICM v1.1 | `GRC-15` Human Supervision — **Partial** (advisory queue, not an enforced gate) · `IAM-18` Special Authorization — **Recommended** |
| ISO 42001 | B.5.3 Impact Assessment Documentation; B.3.2 AI Roles Guidance; B.2.4 AI Policy Review Guidance |
| Trust taxonomy | *Approval Workflow Bypass* (T-G, ASI09); *Approval Reuse* (T-A, ASI09) |

**Note on the distinction the controls make visible.** `GRC-15` and `IAM-18` are
different controls and only the first is partially present. A review *queue*
supervises; a *special authorization* gate authorizes. The evidenced system has
supervision without authorization — an operator can see that something needs
review and still act. The Trust-taxonomy pair makes the second failure mode
explicit: *Approval Reuse* means an approval granted once persists past the point
where it should be re-verified, which is what a display-state queue permits by
construction.

**SSRM Ownership** — Primary: OSP. Shared: AP, AIC. Agent Owner accountable: yes.

**Required Evidence to Fully Answer** — Approval-enforcement code paths.

---

### L6-T06 — API Abuse / Exfiltration via Tool Egress (responder, Lara, embeddings)

**MAESTRO Layer** — L6 Tools, Application, Ecosystem (Domain 2).

**Current Evidence** — Backend owns all egress: responder (OpenAI/Gemini), Lara Translate (backend-only, fails closed without creds), embeddings (**private-network only; public embedding endpoints blocked** so adversarial prompt material isn't sent to third-party embedding APIs). Only redacted prompts reach any model. Output is re-sanitized (keyword/PII) before display. Canary token `COUNTERSPY_CANARY_TOKEN_…` triggers `CANARY_EXFIL` → HOTL Global Pause.

**Reasonable Inferences** — Egress is deliberately constrained; the residual exfil surface is (a) data sent to the frontier responder for `CLEAN` prompts and (b) any judge false-negative that lets sensitive/adversarial content forward.

**Unknowns / Missing Evidence** — Whether responder base URL can be changed at runtime by any authenticated caller (docs say browser cannot override provider base URLs — good; server-side change control not detailed).

**Assessment Status** — Answerable (egress model well evidenced).

**Attack Vector** — Attacker aims to exfiltrate via the sanctioned responder channel by getting content judged `CLEAN`; or redirect egress by tampering with server-side provider config.

**Cross-Layer Impact** — L2 (judge gate), L7 (config-change authz), L9 (canary detection).

**Likelihood / Impact / Risk** — Likelihood Low–Medium; Impact Medium; **Risk Medium** (strong egress controls reduce it).

**Recommended Mitigations** — Egress allowlist for responder base URLs enforced server-side; change-control + audit on provider config; retain canary + output sanitization (strong existing controls).

**Controls**

| Lens | Reference |
|---|---|
| Technique | `AISubtech-18.2.1` Abuse of APIs for Mass Automation (LLM10 / `AML.T0029`); `AITech-16.1` Eavesdropping (LLM02 / `AML.TA0009`) |
| FAIR-CAM | *LEC Prevention · Resistance* — Network-level protection vs sensitive-data publishing — **Present** (embeddings private-network only) · *LEC Prevention · Resistance* — DLP enforces data classification policy — **Partial** (redaction present; no classification policy evidenced) · *LEC Prevention · Resistance* — Access to plugins and extensions restricted — **Present** (browser cannot override provider base URLs) |
| AICM v1.1 | `AIS-10` API Security — **Partial** · `STA-10` Primary Service Contract — **Recommended** (no evidenced provider SLA or DPA) · `CCC-04` Change Authorization — **Recommended** (server-side provider config) |
| ISO 42001 | 6.1 Actions to Address Risks; A.10.4 Customers |
| Trust taxonomy | *Agent-to-SaaS Trust Abuse* (T-C, ASI02) |

**Note on the canary.** The canary token is a *Detection · Visibility* control
that also triggers a *Response · Event Termination* control (Global Pause). That
coupling is efficient and is also the weakness examined at L8-T05: a detection
control wired directly to a system-wide termination control converts a detection
event into an availability event. Decoupling the two — canary detects, pause is a
separate decision — is the control-level statement of that recommendation.

**SSRM Ownership** — Primary: OSP + AP + **Tool Provider** (L6 has three primaries). Shared: MP. Agent Owner accountable: yes.

**Required Evidence to Fully Answer** — Server-side provider-config change controls.

---

### L6-T04 — MCP Server Compromise — **Not Applicable (documented)**

MCP/A2A appears **only as a detection reference** (hard-block indicator phrases)
and as a transitive **dev** dependency (`@modelcontextprotocol/sdk` via
`shadcn`). Per skill rule #5, MCP-specific threats are **not inferred**: Safeguard
LLM is not an MCP client and consumes no MCP tool servers. Flagged here
explicitly rather than assessed.

*Controls note:* the Trust-taxonomy row *Agent-to-MCP Trust Abuse* (T-C) and its
controls `AIS-11` / `AIS-10` are **not** cited as gaps, because the surface does
not exist. Should the system later consume MCP servers, that row and `AIS-13` (AI
Sandboxing) become live and this block requires re-scoping rather than extension.

---

### L7-T02 / L7-T03 — Shared Static Credential; Coarse Authorization *(Primary Finding)*

**MAESTRO Layer** — L7 Identity & Autonomy (Domain 3, horizontal).

**Current Evidence** — Protected execution routes (`/v1/intercept`, `/v1/translate`, `/v1/instruction-monitor/*`, `/v1/ctf/sam-spade/*`) require a **shared static bearer token** (`INTERCEPT_BEARER_TOKEN` vs. browser `VITE_BACKEND_BEARER_TOKEN`), compared as a static string. **JWT/OIDC validation is explicitly not implemented.** Sam Spade additionally requires the **client-asserted** `x-counter-spy-user-id`. UI login is Firebase Google OAuth. Secrets live in `.env` via `dotenv` (Secrets Manager planned). No documented API-layer RBAC matrix; Firestore rules do enforce no-role-self-elevation and admin-only reads.

**Reasonable Inferences** — Any holder of the single token can call any protected route with any asserted user id; per-user accountability at the API layer rests on a self-asserted header. Token rotation logs out everyone (no per-user revocation).

**Unknowns / Missing Evidence** — Token storage/rotation cadence; production OIDC timeline.

**Assessment Status** — Answerable.

**Attack Vector** — Leaked/stolen bearer token (from `.env`, logs, or the browser env var) grants full API access and identity spoofing via `x-counter-spy-user-id`.

**Cross-Layer Impact** — L3 (corpus promotion, L3-T01), L4 (HITL bypass), L6 (egress), L10 (audit attribution integrity).

**Likelihood / Impact / Risk** — Likelihood Medium (static long-lived secret, browser-exposed env var); Impact High (full control-plane access + spoofed attribution); **Risk High**.

**Recommended Mitigations** — Replace shared token with per-request OIDC/OAuth2 validation (`sub`/`aud`/`exp`, JWKS, no local cache → immediate revocation — the docs' own target); derive identity from verified `sub`, not the client header; move secrets to AWS Secrets Manager with rotation; add universal logout.

**Controls**

| Lens | Reference |
|---|---|
| Technique | `AISubtech-14.1.1` Credential Theft (ASI03 / `AML.TA0006`); `AISubtech-3.1.1` Identity Obfuscation (LLM01 / `AML.T0031`) — the `x-counter-spy-user-id` spoof; `AISubtech-4.3.4` Replay Exploitation (ASI06 / `AML.TA0007`) |
| FAIR-CAM | *VMC Correction · Implementation* — Ensure credential rotation is performed regularly — **Absent** · *VMC Correction · Implementation* — Revoke access to compromised credentials — **Absent** (rotation logs out everyone) · *VMC Correction · Implementation* — Revoke overly permissive user access — **Absent** · *VMC Identification · Monitoring* — User access review performed periodically — **Absent** · *LEC Prevention · Avoidance* — Restrict groups with access to sensitive info — **Partial** (Firestore only) |
| AICM v1.1 | `IAM-14` Strong Authentication — **Absent** at the API layer · `IAM-16` Authorization — **Partial** · `IAM-07` Access Revocation — **Absent** · `IAM-15` Secrets Management — **Absent** (`.env`) · `IAM-09` Segregation of Privileged Roles — **Partial** (Firestore rules only) |
| ISO 42001 | A.2.3 Alignment with Organizational Policies; A.6.2 AI System Control Environment |
| Trust taxonomy | *Authentication Bypass* (T-G, ASI03); *Token Persistence* (T-A, ASI03); *Session Reuse* (T-A); *Stale Trust Decisions* (T-A) |

**Note — this is the densest control gap in the assessment.** Four of the five
Variance Management Controls in the FAIR-CAM library that apply to identity are
**absent**, not partial. That is the concrete form of the asymmetry named in
Section 3: the system has strong Loss Event Controls and almost no controls that
keep those controls current. A single static credential with no rotation, no
revocation, no access review, and no per-user attribution is a control
environment in which every other L7 control is theoretical.

`IAM-07` (Access Revocation) is the specific control whose absence unlocks
Chain A. It cannot be implemented against a shared static token — which makes the
OIDC migration a prerequisite for a control, not merely an improvement to one.

**SSRM Ownership** — Primary: AIC (IAM domain). Shared: CSP (identity infra), OSP (federation). Agent Owner accountable: yes.

**Required Evidence to Fully Answer** — Production auth design; token lifecycle.

---

### L8-T01 — Guardrail Bypass (the product's core threat)

**MAESTRO Layer** — L8 Safety & Security (Domain 3, horizontal).

**Current Evidence** — Layered detection: Shannon entropy (adversarial `>4.0`, suspicious floor `3.8`), syntactic complexity (`≥65`/`≥90`), English-likeness/obfuscation strict-mode (any recognized family = Adversarial; Pig Latin → Suspicious), structural-jailbreak flags, instruction-similarity thresholds (SimHash Hamming `≤12`; cosine `≥0.78`; chunk `>0.72`; attention pool `>0.70`; sandwich delta `>0.20`), safeguard judge, output sanitization, ReDoS breaker.

**Reasonable Inferences** — The strict obfuscation policy trades false-positives for coverage; the residual bypass path is **plaintext, low-entropy, novel-phrasing** attacks with no corpus match, relying solely on the judge (see L2-T03). Thresholds are published in docs — an attacker with doc access can tune inputs to sit just under each band.

**Unknowns / Missing Evidence** — Judge robustness; false-negative rate; adaptive-attacker evaluation.

**Assessment Status** — Answerable (control surface) / Partially (efficacy).

**Attack Vector** — Craft input with entropy ≤3.8, syntactic score <65, English-like, no obfuscation family, no SimHash/embedding match → all heuristics pass → judge is the sole gate.

**Cross-Layer Impact** — L2 (judge), L3 (corpus coverage), L9 (must be observable).

**Likelihood / Impact / Risk** — Likelihood Medium; Impact High (control failure = the product failing); **Risk Medium-High**.

**Recommended Mitigations** — Adaptive/adversarial red-teaming against published thresholds (MDS-06); consider not publishing exact numeric thresholds in public docs (they aid evasion); continuous corpus expansion from reviewed escapes (Golden Set already supports this); track Post-Model Escape Rate (already a metric) as the KPI.

**Controls**

| Lens | Reference |
|---|---|
| Technique | `AISubtech-2.1.2` Obfuscation (LLM01 / `AML.T0031` Evade ML Model) |
| FAIR-CAM | *LEC Prevention · Resistance* — the detector stack itself — **Present** and dense · *VMC Identification · Monitoring* — Application vulnerability testing, periodic — **Absent** (this is adversarial evaluation of the detectors) · *DSC Misaligned Decisions · Analysis* — Root cause analysis reviewed — **Partial** (Golden Set promotion from reviewed escapes) |
| AICM v1.1 | `TVM-11` Guardrails — **Present** · `MDS-06` Adversarial Attack Analysis — **Absent** · `MDS-07` Model Hardening — **Absent** · `AIS-09` Output Validation — **Present** (output re-sanitization) |
| ISO 42001 | A.6.1 Responsible Design Process; A.6.2.6 Operation & Monitoring. *Note:* `MDS-06` and `MDS-07` have **no ISO 42001 equivalent* — see Section 14 |
| Trust taxonomy | *Policy Enforcement Bypass* (T-G, ASI10) |

**Note on the ISO gap.** The two controls that would measure this system's core
competency — adversarial attack analysis and model hardening — are the two with
no ISO/IEC 42001 counterpart. An ISO 42001 certification would not attest the
control this product exists to provide. That is worth stating in any compliance
narrative rather than discovering during an audit.

**SSRM Ownership** — Shared across all roles within delivery layers (TVM-11 guardrails); AIC is integrating authority. Agent Owner accountable: yes.

**Required Evidence to Fully Answer** — Red-team results; false-negative telemetry.

---

### L8-T05 — Adversarial Robustness / ReDoS & Availability

**MAESTRO Layer** — L8 (Domain 3).

**Current Evidence** — ReDoS circuit breaker (>1000ms → block + `GLOBAL_PAUSE`, flag `ReDoS_ATTEMPT_DETECTED` Critical); fail-secure on judge/sanitizer/frontend timeouts; **no documented gateway rate limiting** beyond this and client-side Bulk Ingest backoff.

**Reasonable Inferences** — The absence of backend request rate limiting means an attacker can drive volume; the Global Pause itself is a **self-DoS** vector — repeatedly tripping pause conditions (canary strings, ReDoS-like inputs, forced judge 503) halts the whole system.

**Unknowns / Missing Evidence** — Backend rate limits; pause-trip abuse protections; cost controls on judge/responder calls.

**Assessment Status** — Partially Answerable.

**Attack Vector** — Flood with inputs engineered to trip Global Pause (fail-secure weaponized into availability denial), or high-volume prompts to exhaust judge/responder quota/cost.

**Cross-Layer Impact** — L1 (resource exhaustion), L4 (orchestration DoS), L9 (alert fatigue, L9-T06).

**Likelihood / Impact / Risk** — Likelihood Medium; Impact Medium–High (fail-secure = availability trade-off); **Risk Medium**.

**Recommended Mitigations** — Backend per-identity rate limiting and quotas; distinguish global vs. per-session pause to limit blast radius; cost circuit-breakers on provider calls; alert-fatigue tuning (Z-score incidenting once implemented).

**Controls**

| Lens | Reference |
|---|---|
| Technique | `AISubtech-13.1.4` Application Denial of Service (LLM10 / `AML.T0029`); `AISubtech-13.2.1` Service Misuse for Cost Inflation |
| FAIR-CAM | *LEC Prevention · Resistance* — Rate limiting for Internet-exposed apps — **Absent** · *LEC Prevention · Resistance* — DDoS protection implemented — **Absent** · *LEC Response · Event Termination* — Global Pause — **Present**, and is itself the attack target |
| AICM v1.1 | `TVM-13` Threat Response — **Partial** (pause exists; graduated response does not) · `LOG-13` Anomalies Reporting — **Recommended** (Z-score, planned) |
| ISO 42001 | A.6.2.6 Operation & Monitoring |
| Trust taxonomy | *Verification Suppression* (T-E, ASI10) — the inverse framing: an attacker who can force the verification layer into a halted state has suppressed it |

**Note on rate limiting as the missing prerequisite.** Per-identity rate limiting
cannot be implemented against a shared static token — there is no identity to
limit per. This is the second control (after `IAM-07`) whose implementation is
**blocked by** the L7 finding rather than merely related to it. Two independent
control gaps resolve to the same root cause, which is the argument for
prioritizing L7 above its own severity rating.

**SSRM Ownership** — Shared (TVM-11, SEF). Primary integrating: AIC. Shared: CSP, OSP. Agent Owner accountable: yes.

**Required Evidence to Fully Answer** — Rate-limit and pause-abuse controls.

---

### L9-T02 / OWASP T23 — Audit Trail Tamper-Evidence

**MAESTRO Layer** — L9 Monitoring & Observability (Domain 3).

**Current Evidence** — Rich structured events (`safeguard_decision`, `metric_increment`, `instruction_embedding_generated`); Firestore audit log with per-decision attribution and SHA-256 prompt hashes; `firestore.rules` reject client forgery of backend-owned security fields. CloudWatch delivery and Z-score incidenting are **not implemented**.

**Reasonable Inferences** — Firestore rules prevent *client* tampering, but no **WORM/immutable** logging or tamper-evidence is evidenced; anyone with backend/Firestore admin could alter records. Per skill rule #4, this observability is **not audit-grade** until tamper-evidence is shown.

**Unknowns / Missing Evidence** — Immutability/retention enforcement; separation of logging store from execution environment.

**Assessment Status** — Partially Answerable.

**Attack Vector** — Privileged insider or compromised backend/Firestore credential selectively deletes/edits audit entries to conceal an escape (T23).

**Cross-Layer Impact** — L10 (audit gaps, L10-T05), L7 (privileged credential), L8 (IR blind spot).

**Likelihood / Impact / Risk** — Likelihood Low–Medium; Impact High (forensic integrity); **Risk Medium**.

**Recommended Mitigations** — WORM/immutable audit sink separate from Firestore and the execution env (e.g., append-only log, object-lock); ship events to SIEM (CloudWatch → SIEM as planned); integrity-hash chaining of audit records.

**Controls**

| Lens | Reference |
|---|---|
| Technique | `AISubtech-16.1.1` Logging Sensitive Conversations (LLM02 / `AML.TA0009`) — the inverse concern, applicable to the prompt-hash discipline |
| FAIR-CAM | *LEC Prevention · Deterrence* — Audit logs retained for a defined period — **Partial** ("intended permanent," no enforcement) · *LEC Detection · Visibility* — Intrusion detection for GenAI applications — **Present** |
| AICM v1.1 | `LOG-02` Audit Logs Protection — **Absent** · `LOG-09` Log Protection — **Absent** · `LOG-03` Security Monitoring & Alerting — **Partial** (dashboard yes, alerting planned) · `LOG-07` Logging Scope — **Present** |
| ISO 42001 | A.6.2.6 Operation & Monitoring. *Note:* the entire `LOG-*` family has **no ISO 42001 equivalent** — see Section 14 |
| Trust taxonomy | *Risk Signal Suppression* (T-E, ASI10); *Monitoring Blind Spots* (T-E) |

**Note on what the prompt-hash discipline already achieves.** Recording SHA-256
prompt hashes rather than prompt bodies is a strong `LOG-07` scoping decision — it
makes the audit trail useful without making it a secondary disclosure surface.
The gap is `LOG-02`/`LOG-09`, which protect the trail rather than scope it. These
are separable: the scoping is right and should survive any change made to add
immutability.

**SSRM Ownership** — Shared (LOG domain). Integrating: AIC. Shared: CSP (log infra). Agent Owner accountable: yes.

**Required Evidence to Fully Answer** — Log immutability and retention design.

---

### L9-T03 — Detector Drift & Policy Drift *(new in this revision)*

**MAESTRO Layer** — L9 Monitoring & Observability (Domain 3, horizontal).

**Why this is new.** Applying the trust-decay lens (Family T-E) to a system whose
product is a detector surfaces a threat the original assessment did not separate
from L8-T01: not that the guardrail is *bypassed*, but that it **silently stops
working as well as it did**, with no signal distinguishing that from a quieter
threat environment.

**Current Evidence** — The Safeguard Effective Prompt has a tracked drift hash
(`590a286e…`) — a genuine and uncommon control. The `safeguard.divergence` metric
exists. Post-Model Escape Rate is a named metric. Detection thresholds are static
constants published in the documentation. Judge model presets point to versioned
endpoints. No baseline-deviation detection, no scheduled detector re-validation,
and no evidenced periodic policy review are documented.

**Reasonable Inferences** — Four independent drift sources exist, and none has an
evidenced monitor: (a) a judge model updated behind a provider endpoint without
notice; (b) an embedding model change shifting the vector space so historical
fingerprints no longer match at the tuned thresholds; (c) threshold constants
tuned to reduce false positives, cumulatively widening the pass band; (d) corpus
growth changing the base rate at which the similarity monitor fires.

**Unknowns / Missing Evidence** — Whether detector efficacy is measured over
time; whether threshold changes are reviewed; whether judge model version is
recorded per decision.

**Assessment Status** — Partially Answerable.

**Attack Vector** — Not a single action. An attacker benefits passively from
drift, and an attacker with documentation access can *observe* which threshold
bands have loosened by probing at the edges and reading the flag glossary.

**Cross-Layer Impact** — L8-T01 (efficacy), L2-T03 (judge behaviour), L3-T01
(corpus base rate), L10 (compliance drift, L10-T03).

**Likelihood / Impact / Risk** — Likelihood **High** — this is a passive process,
not an attack that must succeed; Impact Medium–High (silent degradation of the
core control); **Risk Medium-High**.

**Recommended Mitigations** — Record judge and embedding model identity and
version **per decision**, not per configuration, so a provider-side change is
detectable retrospectively. Establish a fixed adversarial evaluation set and run
it on a schedule and on every threshold change, tracking absolute detection rate
rather than intervention volume. Treat threshold constants as security-relevant
code under review. Alert on an unexplained *drop* in detection rate — a decline
and a quieter environment are indistinguishable in aggregate, which is precisely
why a fixed evaluation set is required to separate them.

**Controls**

| Lens | Reference |
|---|---|
| Technique | `AISubtech-11.2`-class Model-Selective Evasion (LLM01 / `AML.T0031`) applied over time |
| FAIR-CAM | *VMC Identification · Monitoring* — Validate effectiveness of training/controls — **Absent** · *VMC Identification · Monitoring* — Periodic policy review for GenAI usage — **Absent** · *VMC Prevention · Reduce Variance* — the whole class, thinly represented |
| AICM v1.1 | `MDS-10` Model Continuous Monitoring — **Absent** · `CCC-07` Detection of Baseline Deviation — **Absent** · `LOG-16` (Proposed) Behavioral Drift Detection — **structural AICM gap**, see below |
| ISO 42001 | A.6.2.6 Operation & Monitoring; 9.1 Monitoring, Measurement, Evaluation; 9.3 Management Review |
| Trust taxonomy | *Policy Drift* (T-E, ASI10); *Verification Frequency Reduction* (T-E); *Trust Decay Exploitation* (T-E); *Continuous Assessment Failure* (T-E) |

**AICM structural gap flagged.** Behavioral drift detection is one of the
documented structural gaps in AICM v1.1 — `LOG-16` is a *proposed*, not canonical,
control. Rather than citing a tangentially related existing control as coverage,
this finding names the gap: the catalog does not yet have a clean control for
"the detector still runs and is worse than it was." `MDS-10` and `CCC-07` are the
nearest canonical entries and both are absent here regardless.

**SSRM Ownership** — Primary: AIC (integrating). Shared: MP (model versioning),
OSP. Agent Owner accountable: yes.

**Required Evidence to Fully Answer** — Detector efficacy over time; threshold
change history; per-decision model version records.

---

### L10-T06 / L10-T01 — Regulatory Compliance & Shadow-AI Governance

**MAESTRO Layer** — L10 Governance & Compliance (Domain 3).

**Current Evidence** — MITRE ATLAS 16-node organizer, Operations Guide/SOPs, Golden Set governance, firestore.rules, documented EU AI Act/PII posture (redaction-before-inference; SESSION_HANDOFF correction on client-side-redaction wording). No documented bias/disparate-impact testing for language-based over-blocking (`FOREIGN_LANGUAGE`/`MIXED_LANGUAGE`). No agent/component registry or Shadow-AI discovery over the operator's own egress.

**Reasonable Inferences** — Over-blocking of legitimate non-English/dialectal input is an algorithmic-discrimination candidate (CO SB 24-205); third-party model training-data disclosure (CA AB 2013) is not captured.

**Unknowns / Missing Evidence** — Bias testing; DPA/subprocessor list; data residency beyond Firestore US-West2.

**Assessment Status** — Answerable (governance surface) / Partially (specific obligations).

**Attack Vector** — Not an attack per se — compliance drift (L10-T03) as the system evolves, and undocumented egress endpoints (rogue LM Studio/Ollama/responder hosts) constituting Shadow-AI.

**Cross-Layer Impact** — L2/L3 (data provenance), L6 (egress inventory), L7 (identity for accountability).

**Likelihood / Impact / Risk** — Likelihood Medium; Impact Medium–High (regulatory); **Risk Medium**.

**Recommended Mitigations** — Bias/impact testing for language heuristics; capture third-party model disclosures; central component registry + egress reconciliation for Shadow-AI; the AI-BOM produced alongside this assessment supports Annex IV documentation.

**Controls**

| Lens | Reference |
|---|---|
| Technique | `AISubtech-4.1.1` Rogue Agent Introduction (ASI07 / `AML.T0051.002`) — the Shadow-AI half |
| FAIR-CAM | *DSC Prevention · Expectations* — Acceptable Use Policy exists for GenAI — **Absent** · *DSC Prevention · Expectations* — Data classification policy documented — **Absent** · *DSC Prevention · Awareness* — Risk analysis — **Partial** (this assessment) · *VMC Identification · Monitoring* — Inventory of permitted GenAI applications — **Absent** · *VMC Identification · Monitoring* — Periodic policy review — **Absent** |
| AICM v1.1 | `GRC-09` Acceptable Use of AI — **Absent** · `GRC-10` AI Impact Assessment — **Absent** · `GRC-11` Bias and Fairness — **Absent** · `GRC-12` Ethics Committee — **Absent** · `STA-08` Supply Chain Inventory — **Absent** · `STA-16` Service Bill of Material — **Absent** |
| ISO 42001 | A.9.4 Intended Use of AI System; A.10.3 Suppliers; B.5.4 Assessing Impact on Individuals |
| Trust taxonomy | *Agent Onboarding Abuse* (T-H, ASI04) |

**Note on non-delegability.** Every AICM control listed above is **AIC-owned
regardless of deployment model** — none of them shift to a platform provider
under the AaP target. Moving to AWS changes the ownership of `I&S-06`, `LOG-02`,
and `IAM-14`; it changes nothing about `GRC-09` through `GRC-12`. Those six
absences are the ones that persist through the migration.

**SSRM Ownership** — Primary: **AIC — non-delegable** (governance cannot be outsourced; holds in AaI/AaP/AaaS alike). Agent Owner accountable: yes.

**Required Evidence to Fully Answer** — Bias-test results; DPA/subprocessor docs; production egress inventory.

---

## 9. Cross-Layer Path Analysis

**Chain A — Credential → Corpus/Policy → Detection failure.** Theft of the shared
bearer token (L7-T02) grants access to
`/v1/instruction-monitor/reviewed-adversarial` (L3-T01), letting an attacker shape
the similarity corpus (whitelist-by-omission or benign poisoning) and thereby
degrade the L8 detector — with spoofed `x-counter-spy-user-id` corrupting L10
audit attribution. This is the highest-value chain because a single static secret
unlocks it end-to-end.
*Controls view:* `IAM-07` (Access Revocation) absent → `IAM-18` (Special
Authorization) absent → `DSP-21` (Data Poisoning Prevention) partial. Three
sequential absent-or-partial controls, none of which independently prevents the
chain.

**Chain B — Novel jailbreak → sole-judge gate → sanctioned egress.** A plaintext,
low-entropy, non-obfuscated, corpus-unmatched prompt (L8-T01) passes every
heuristic, leaving the safeguard judge as the only gate (L2-T03); a judge
false-negative forwards adversarial content to the downstream responder over the
sanctioned egress channel (L6-T06). Output sanitization and the canary token are
the last-line mitigations.
*Controls view:* `TVM-11` present but `MDS-06` absent — the guardrail exists and
its efficacy is unmeasured. `AIS-09` (Output Validation) present is what makes
this chain Medium rather than High.

**Chain C — Fail-secure weaponized → availability denial.** Inputs engineered to
trip Global Pause conditions exploit the fail-secure design (L8-T05) to halt the
entire gateway (L4 orchestration DoS), amplified by absent backend rate limiting
and alert fatigue (L9-T06).
*Controls view:* a *Response · Event Termination* control (Global Pause) wired
directly to *Detection · Visibility* triggers, with the *Prevention · Resistance*
control that would bound the trigger rate (rate limiting) absent. The control
topology is the vulnerability.

**Chain D — Privileged insider → selective audit edit.** With no evidenced WORM
logging, a backend/Firestore admin credential (L7) enables selective audit-record
deletion (L9-T02 / T23) to conceal a prior escape (L10-T05 audit gap).
*Controls view:* `LOG-07` (scope) present, `LOG-02`/`LOG-09` (protection) absent
— the trail is well-designed and unprotected.

**Chain E — Drift → widened pass band → undetected escape** *(new)*. No
per-decision model version recording and no fixed evaluation set (L9-T03) mean a
judge model change, an embedding space shift, or cumulative threshold tuning
widens the pass band (L8-T01) with no signal. Unlike Chains A–D this requires no
attacker action to begin; an attacker only benefits from it.
*Controls view:* the entire *VMC Identification · Monitoring* class is absent.
`MDS-10` and `CCC-07` absent; `LOG-16` is a structural AICM gap.

No multi-agent cascade/collusion chains are constructed — no autonomous
multi-agent delegation is evidenced.

---

## 10. SSRM Ownership Summary

Deployment model in play: **AaI today → AaP (AWS) target.** Under AaI the Agent
Owner = **AIC + AP + OSP**; several rows shift toward the platform under the AaP
target (noted where relevant).

| Threat | Layer | Primary Owner | Shared | Shifts under AaP? | Agent Owner Accountable |
|---|---|---|---|---|---|
| L2-T03 Jailbreak vs judge | L2 | MP | OSP, AP, CSP | No | Yes |
| L2-T04 Model supply chain | L2 | MP | CSP | Partially (registry → CSP) | Yes |
| L3-T01 Corpus poisoning | L3 | AIC | OSP, MP | No | Yes |
| L3-T02 Vector DB access | L3 | CSP | AIC | **Yes** — managed DB | Yes |
| L3-T07 Context overflow | L3 | AIC | OSP, MP | No | Yes |
| L4-T07 HITL bypass | L4 | OSP | AP, AIC | No | Yes |
| L6-T06 Tool egress exfil | L6 | OSP + AP + **Tool Provider** | MP | Partially | Yes |
| L7-T02/03 Shared credential | L7 | AIC | CSP, OSP | Partially — infra only | Yes |
| L8-T01 Guardrail bypass | L8 | Shared (all, TVM-11) | CSP/MP/OSP/AP | No | Yes — AIC integrating |
| L8-T05 ReDoS / availability | L8 | Shared | CSP, OSP | **Yes** — WAF/API GW | Yes |
| L9-T02 Audit tamper-evidence | L9 | Shared (LOG) | CSP | **Yes** — Object Lock | Yes — AIC integrating |
| L9-T03 Detector drift *(new)* | L9 | AIC | MP, OSP | No | Yes |
| L10-T06/01 Compliance/Shadow-AI | L10 | **AIC (non-delegable)** | — | **No** | Yes |

> Per MAESTRO §9.3 / 3SRM §3.1: **"In all three deployment models, Layer 10
> (Governance) remains with the Agent Owner. Governance cannot be outsourced."**

**The "shifts under AaP" column is the useful new read.** Three rows move
meaningfully to the platform; the highest-severity findings (L7, L8-T01, L9-T03,
L10) do not. Migrating to AWS resolves infrastructure controls and leaves the
identity, efficacy, drift, and governance gaps exactly where they are.

**Relevant AICM structural gaps (3SRM §2.6):** *Dynamic Tool Discovery* is **not**
triggered (no runtime MCP binding). *Autonomous Decision-Making* applies weakly —
the judge makes an autonomous verdict, a behavioral-responsibility surface not
cleanly owned by any AICM control. *Behavioral drift* now applies explicitly via
L9-T03. No sub-agent-delegation or cross-org-collaboration gaps apply
(single-service, no A2A).

---

## 11. Framework Crosswalk

Not requested as a full crosswalk. The MITRE ATLAS 16-node organizer the system
already uses aligns naturally with the technique IDs now cited per finding:
`AML.T0051`/`T0054` (L2-T03, L8-T01), `AML.T0058`-class (L6-T06), `AML.T0020`
(L3-T01), `AML.TA0006` (L7-T02/03), `AML.T0029` (L8-T05), `AML.T0031` (L9-T03).
A full STRIDE/OWASP/NIST/ISO-42001 crosswalk can be produced on request.

---

## 12. Required Validation Steps

1. Provide judge/responder inference parameters and any red-team/eval results (resolves L2-T03, L8-T01 efficacy; evidences `MDS-06`).
2. Confirm the production identity design and timeline for OIDC/JWT + universal logout (resolves L7 primary finding; unblocks `IAM-07` and per-identity rate limiting).
3. Document the RBAC/approval workflow for `/v1/instruction-monitor/reviewed-adversarial` and KB/Golden-Set promotion (resolves L3-T01, L4-T07; evidences `IAM-18`, `GRC-15`).
4. Evidence audit-log immutability/WORM and retention, and log-store separation (resolves L9-T02; evidences `LOG-02`, `LOG-09`).
5. Provide production infra design for pgvector, network policy, and rate limiting (resolves L3-T02, L8-T05).
6. Supply model-weight integrity hashes/signatures for judge and embedding models (resolves L2-T04; evidences `STA-16`).
7. Provide bias/disparate-impact testing for language heuristics and third-party model training-data disclosures (resolves L10; evidences `GRC-11`).
8. **Contractual (3SRM §6.2):** obtain AI-CAIQ responses from OpenAI/Google/Lara; add shared-responsibility addenda and safety SLAs (escalation time, drift thresholds) (evidences `STA-10`, `STA-12`).
9. **New —** provide detector efficacy measurements over time, threshold change history, and per-decision model version records (resolves L9-T03; evidences `MDS-10`, `CCC-07`).
10. Retrieve the empty `Technical/File_Structure.md` to close the file-tree evidence gap.

---

## 13. Conclusion: What Can and Cannot Be Concluded

**Can be concluded.** Safeguard LLM has a well-considered, defense-in-depth L8
control surface that is the product's core competency, backed by genuine
strengths: strict control/inference-plane separation, pervasive fail-secure
behavior, provider secrets excluded from the client bundle,
redaction-before-inference, egress restriction of embeddings to a private
network, prompt-differentiation to the judge (`AIS-15`), output validation
(`AIS-09`), and Firestore rules that block client-side forgery of security fields
and role self-elevation. Integrity discipline on the seed corpus and the Safeguard
Effective Prompt (verified SHA-256 hashes) is exemplary and should be extended to
model weights.

The controls lens sharpens the central finding rather than changing it. The
system is dense in **Loss Event Controls** and nearly empty of **Variance
Management Controls** — the ones that keep controls working. Every VMC in the
FAIR-CAM library that applies to identity is absent; every VMC that applies to
detector efficacy is absent. That pattern, in a product whose function *is* a
control, is what makes L9-T03 (drift) a High-likelihood finding despite requiring
no attacker.

The dominant residual risk remains **identity**: a single shared static bearer
token gates all execution routes, with per-user accountability resting on a
client-asserted header and no per-user revocation. Two other control gaps —
`IAM-07` access revocation and per-identity rate limiting — are **blocked by**
this one rather than merely adjacent to it, which is the argument for
prioritizing it above its own severity rating.

**Cannot be concluded.** Detector *efficacy* (false-negative rate under adaptive
attack), detector *drift* over time, judge robustness, model-weight integrity,
production infrastructure/auth posture, audit immutability, and
bias/discrimination behavior are all **Unanswerable from current evidence** —
they require the artifacts in Section 12. No finding here asserts the system is
either compromised or proven safe on those axes; they are documented gaps, not
verdicts.

**A caution on the control register.** Section 14 marks controls Present /
Partial / Absent against *documentation*, not against a deployed system or a
tested one. A control marked Present is evidenced as designed; it is not
evidenced as effective. `MDS-06` (adversarial attack analysis) is the control
that would convert those Present marks into measured ones, and it is absent.

---

## 14. Consolidated Control Register

Every control cited in Section 8, with status against the evidence. **Present** =
evidenced in the repository. **Partial** = evidenced in one layer or context but
not where the finding needs it. **Absent** = not evidenced.

### CSA AICM v1.1

| Control | Domain | Status | Findings | ISO 42001 |
|---|---|---|---|---|
| `AIS-08` Input Validation | AI Security | Partial | L3-T07 | A.6.2.4 |
| `AIS-09` Output Validation | AI Security | **Present** | L8-T01 | B.8.2 |
| `AIS-10` API Security | AI Security | Partial | L6-T06 | 6.1 |
| `AIS-15` Prompt Differentiation | AI Security | **Present** | L2-T03 | A.7.4 |
| `CCC-04` Change Authorization | Change Control | Absent | L6-T06 | A.10.2 |
| `CCC-07` Detection of Baseline Deviation | Change Control | Absent | L9-T03 | A.6.2.6 |
| `DSP-21` Data Poisoning Prevention | Data Security | Partial | L3-T01 | A.6.2.6 |
| `DSP-23` Data Integrity Check | Data Security | Partial | L3-T01 | 6.3 |
| `DSP-24` Data Differentiation | Data Security | **Present** | L3-T07 | A.4.3 |
| `GRC-09` Acceptable Use of AI | Governance | Absent | L10-T06 | A.9.4 |
| `GRC-10` AI Impact Assessment | Governance | Absent | L10-T06 | B.5.4 |
| `GRC-11` Bias and Fairness | Governance | Absent | L10-T06 | B.5.4 |
| `GRC-12` Ethics Committee | Governance | Absent | L10-T06 | — |
| `GRC-15` Human Supervision | Governance | Partial | L4-T07 | B.5.3 |
| `I&S-06` Segmentation and Segregation | Infra & Sec | Absent (prod) | L3-T02 | 10.2 |
| `IAM-07` Access Revocation | IAM | **Absent** | L7-T02 | A.2.3 |
| `IAM-09` Segregation of Privileged Roles | IAM | Partial | L7-T03 | A.2.3 |
| `IAM-14` Strong Authentication | IAM | **Absent** (API layer) | L7-T02 | A.2.3 |
| `IAM-15` Secrets Management | IAM | **Absent** | L7-T02, L3-T02 | A.2.3 |
| `IAM-16` Authorization | IAM | Partial | L7-T03 | A.6.2.2 |
| `IAM-18` Special Authorization | IAM | Absent | L4-T07, L3-T01 | B.3.2 |
| `LOG-02` Audit Logs Protection | Logging | **Absent** | L9-T02 | *no ISO equivalent* |
| `LOG-03` Security Monitoring & Alerting | Logging | Partial | L9-T02 | *no ISO equivalent* |
| `LOG-07` Logging Scope | Logging | **Present** | L9-T02 | *no ISO equivalent* |
| `LOG-09` Log Protection | Logging | **Absent** | L9-T02 | *no ISO equivalent* |
| `LOG-13` Anomalies Reporting | Logging | Absent (planned) | L8-T05 | *no ISO equivalent* |
| `LOG-16` Behavioral Drift Detection | Logging | **structural gap** | L9-T03 | *proposed* |
| `MDS-06` Adversarial Attack Analysis | Model Dev | **Absent** | L2-T03, L8-T01 | *no ISO equivalent* |
| `MDS-07` Model Hardening | Model Dev | Absent | L8-T01 | *no ISO equivalent* |
| `MDS-10` Model Continuous Monitoring | Model Dev | **Absent** | L9-T03 | *no ISO equivalent* |
| `STA-08` Supply Chain Inventory | Supply Chain | Absent | L2-T04, L10-T01 | A.10.3 |
| `STA-10` Primary Service Contract | Supply Chain | Absent | L6-T06 | A.10.4 |
| `STA-12` Supply Chain Compliance | Supply Chain | Absent | L2-T04 | A.10.3 |
| `STA-16` Service Bill of Material | Supply Chain | Absent | L2-T04 | B.10.3 |
| `TVM-11` Guardrails | Threat & Vuln | **Present** | L8-T01, L2-T03 | A.6.1 |
| `TVM-13` Threat Response | Threat & Vuln | Partial | L8-T05 | A.6.2.6 |

**Nine controls marked Present or Partial-favourable.** Thirteen absent. The
absences cluster in three domains: **IAM** (five of six), **LOG** (four of six),
and **GRC** (four of five).

### FAIR-CAM function-class coverage

| Function class | Coverage | Note |
|---|---|---|
| LEC · Prevention · Avoidance | Partial | Firestore only; API layer open |
| LEC · Prevention · Deterrence | Partial | Retention intended, not enforced |
| **LEC · Prevention · Resistance** | **Strong** | The detector stack, redaction, egress restriction |
| LEC · Detection · Visibility | Present | Metrics dashboard, canary |
| LEC · Detection · Monitoring | Partial | No bot monitoring, no alerting |
| **LEC · Response · Event Termination** | **Present** | Global Pause, documented IR |
| LEC · Response · Loss Reduction | Absent | — |
| **VMC · Prevention · Reduce Variance** | **Absent** | No training, no acceptable-use |
| **VMC · Identification · Monitoring** | **Absent** | No access review, no inventory, no periodic testing, no policy review |
| **VMC · Correction · Implementation** | **Absent** | No rotation, no revocation, no access pruning |
| DSC · Prevention · Expectations | Absent | No AUP, no data classification policy |
| DSC · Prevention · Awareness | Partial | This assessment |
| DSC · Misaligned Decisions · Analysis | Partial | Golden Set promotion |

**The shape of the finding in one table.** Three of the four Loss Event Control
classes are Strong or Present. All three Variance Management Control classes are
Absent. A control that is never rotated, reviewed, inventoried, or re-tested
degrades on its own — which is what L9-T03 formalizes and what the ordering in
Section 12 is designed to correct.

### ISO/IEC 42001 coverage note

Eleven of the controls above carry **no ISO/IEC 42001 equivalent** — the entire
`LOG-*` family and the entire `MDS-*` family. Those are precisely the layers this
system depends on most: model development discipline (its core competency) and
logging (its forensic basis). **ISO 42001 certification would not attest the
controls Safeguard LLM is actually built on.** ISO 27001 and SOC 2 are the
correct citations for the logging and access-control controls; the model-security
controls have no certification counterpart in any of the three and must be
evidenced directly.

---

*Produced with the AI Threat Model Analyst skill (MAESTRO v2.0) with the threat-technique and control library loaded. Facts, inferences, and unknowns are kept separate per skill rule #2; MCP-specific and multi-agent threats were withheld as not-evidenced per rules #3 and #5. `AITech-*` IDs, FAIR-CAM control names, AICM control IDs, and ISO clauses are secondary lenses enriching MAESTRO layer threats, never substituted for them. Control IDs should be reconciled against the authoritative AICM v1.1 catalog and the live MITRE ATLAS matrix before audit-grade citation. This is a defensive threat model and does not constitute an offensive playbook.*
