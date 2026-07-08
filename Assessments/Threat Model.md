# MAESTRO v2.0 Threat Model — Safeguard LLM v2.5

*Adversary-Aware Prompt Firewall & Forwarding Gateway (`counter-spy`)*
*Framework: MAESTRO v2.0 (CSA, Apr 2026). Assessment date: 2026-07-08. Evidence: `github.com/Nate-Carroll-Cyber/SafeguardLLM-docs` (`main`).*

---

## 1. Understanding Confirmed

The target is a **security control-plane / LLM firewall**, not a general autonomous agent. It mediates every prompt before inference using a two-stage "Shield-and-Sword" pattern: a client-side TypeScript **Shield** (heuristic detection, redaction, obfuscation decoding) and a backend **Sword** path (`/v1/intercept`) that runs deterministic prechecks, an optional pgvector instruction-similarity monitor, an OpenAI-compatible **safeguard judge**, and — only for `CLEAN` verdicts — forwards to a pluggable **downstream responder** (OpenAI or Gemini). It also hosts a governed "Sam Spade" CTF elicitation scenario. This assessment maps that evidenced surface across the ten MAESTRO layers.

## 2. Scope and Assumptions

- **In scope:** the documented architecture, models, data stores, dependencies, auth model, detectors, and data flows in the analyzed docs.
- **Deployment model:** Evidenced as transitional **Agent-as-Infrastructure (AaI)** today (self-built on local/Firebase + Docker Compose; Owner = AIC + AP + OSP) moving toward **Agent-as-Platform (AaP)** (AWS ECS Fargate / API Gateway / Bedrock — *target-state, not implemented*). Where ownership depends on this, it is flagged.
- **Assumption (bounded):** frontier providers (OpenAI, Google) act as **MP**; LM Studio/Ollama hosts act as self-operated MP/CSP in the demo.
- MAESTRO is built for agentic systems and is **partially over-scoped** here: Safeguard LLM has tool-use (forwarding, translate, embeddings) and memory (pgvector), but limited autonomy and no documented multi-agent delegation chain. L4/L6 are assessed narrowly against what is evidenced.
- This is a defensive assessment. No exploit code is produced.

## 3. System Summary

Safeguard LLM is a policy-enforcing GenAI gateway. Its own product function *is* an L8 safety control (prompt-injection/jailbreak/obfuscation detection), which makes the assessment partly recursive: many L8 threats concern the **failure or bypass of the very detectors that are the product**. The system is strongly fail-secure (judge failure → 202 + `FAIL_SECURE` + Global Pause; ReDoS >1000ms → block + Global Pause; frontend 45s hang → abort, no local fallback inference). It keeps provider secrets out of the browser bundle and only sends **redacted** prompts to any model. The two load-bearing weaknesses evidenced are (a) **coarse identity** — a shared static bearer token on all execution routes, with JWT/OIDC "not implemented," and (b) several **target-state controls** (production auth, CSP, rate limiting, Z-score incidenting, Secrets Manager) that are documented but not yet built. It is **not** a purely passive chatbot (it has memory, tools, and orchestration), so the full L1–L10 spine is retained, with empty layers stated explicitly.

## 4. Evidence Available

Architecture (Shield-and-Sword, `/v1/intercept` flow, fail-secure matrix); models (`gpt-oss-safeguard-20b` / `gpt-5.4-mini` judge; OpenAI/`gemini-2.5-flash` responder; `nomic-embed-text` 768-dim embeddings); data stores (Firestore US-West2; pgvector `pgvector:pg16`; SQLite Sam Spade; in-memory); `core` seed corpus (319 records/611 chunks, SHA-256 verified); instruction-similarity thresholds; detector/flag glossary; SBOM with pinned CVE-mitigating versions; Firestore rules; auth model (Firebase Google OAuth for UI, shared bearer token for API, `x-counter-spy-user-id` for Sam Spade); egress policy (embeddings private-network only; Lara backend-only); telemetry event schema; MITRE ATLAS 16-node organizer.

## 5. Immediate Gaps / Missing Information

- **Production identity/authz:** JWT/OIDC validation, IAM SigV4, and an API-layer RBAC matrix are **planned, not implemented**. Current API auth = shared static bearer token.
- **Inference parameters** (temperature/top_p) for judge and responder — undocumented.
- **Audit-log tamper-evidence:** Firestore audit logs are rich but no WORM/immutability or tamper-evidence is evidenced. Retention is "intended permanent" with optional TTL.
- **Rate limiting / DoS controls** at the gateway beyond the ReDoS breaker — none documented.
- **Content Security Policy** — explicitly a "Known Gap"; `react-markdown` raw-HTML relies on library default.
- **AWS target architecture** (Bedrock wiring, VPC topology, CloudWatch collector) — target-state, undocumented in detail.
- **Third-party model provenance / training data** (OpenAI, Google, Nomic) — opaque.
- **`Technical/File_Structure.md`** referenced but served empty — full file tree not captured.
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

## 8. Detailed Threat Analysis

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

**SSRM Ownership** — Primary: OSP + AP + **Tool Provider** (L6 has three primaries). Shared: MP. Agent Owner accountable: yes.

**Required Evidence to Fully Answer** — Server-side provider-config change controls.

---

### L6-T04 — MCP Server Compromise — **Not Applicable (documented)**

MCP/A2A appears **only as a detection reference** (hard-block indicator phrases) and as a transitive **dev** dependency (`@modelcontextprotocol/sdk` via `shadcn`). Per skill rule #5, MCP-specific threats are **not inferred**: Safeguard LLM is not an MCP client and consumes no MCP tool servers. Flagged here explicitly rather than assessed.

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

**Recommended Mitigations** — Replace shared token with per-request OIDC/OAuth2 validation (`sub`/`aud`/`exp`, JWKS, no local cache → immediate revocation — the docs' own target); derive identity from verified `sub`, not the client header; move secrets to AWS Secrets Manager with rotation; add universal logout. (Confused-deputy / L7-T08 and token-isolation / L7-T10 become relevant once token exchange to downstream is introduced — enforce audience/scope at each hop.)

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

**SSRM Ownership** — Shared (TVM-11, SEF). Primary integrating: AIC. Shared: CSP, OSP. Agent Owner accountable: yes.

**Required Evidence to Fully Answer** — Rate-limit and pause-abuse controls.

---

### L9-T02 / OWASP T23 — Audit Trail Tamper-Evidence

**MAESTRO Layer** — L9 Monitoring & Observability (Domain 3).

**Current Evidence** — Rich structured events (`safeguard_decision`, `metric_increment`, `instruction_embedding_generated`); Firestore audit log with per-decision attribution and SHA-256 prompt hashes; `firestore.rules` reject client forgery of backend-owned security fields. CloudWatch delivery and Z-score incidenting are **not implemented**.

**Reasonable Inferences** — Firestore rules prevent *client* tampering, but no **WORM/immutable** logging or tamper-evidence is evidenced; anyone with backend/Firestore admin could alter records. Per skill rule #4, this observability is **not** audit-grade until tamper-evidence is shown.

**Unknowns / Missing Evidence** — Immutability/retention enforcement; separation of logging store from execution environment.

**Assessment Status** — Partially Answerable.

**Attack Vector** — Privileged insider or compromised backend/Firestore credential selectively deletes/edits audit entries to conceal an escape (T23).

**Cross-Layer Impact** — L10 (audit gaps, L10-T05), L7 (privileged credential), L8 (IR blind spot).

**Likelihood / Impact / Risk** — Likelihood Low–Medium; Impact High (forensic integrity); **Risk Medium**.

**Recommended Mitigations** — WORM/immutable audit sink separate from Firestore and the execution env (e.g., append-only log, object-lock); ship events to SIEM (CloudWatch → SIEM as planned); integrity-hash chaining of audit records.

**SSRM Ownership** — Shared (LOG domain). Integrating: AIC. Shared: CSP (log infra). Agent Owner accountable: yes.

**Required Evidence to Fully Answer** — Log immutability and retention design.

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

**Recommended Mitigations** — Bias/impact testing for language heuristics; capture third-party model disclosures; central component registry + egress reconciliation for Shadow-AI (GRC-09–12); the AI-BOM produced alongside this assessment supports Annex IV documentation.

**SSRM Ownership** — Primary: **AIC — non-delegable** (governance cannot be outsourced; holds in AaI/AaP/AaaS alike). Agent Owner accountable: yes.

**Required Evidence to Fully Answer** — Bias-test results; DPA/subprocessor docs; production egress inventory.

## 9. Cross-Layer Path Analysis

The evidence supports the following plausible attack chains:

**Chain A — Credential → Corpus/Policy → Detection failure.** Theft of the shared bearer token (L7-T02) grants access to `/v1/instruction-monitor/reviewed-adversarial` (L3-T01), letting an attacker shape the similarity corpus (whitelist-by-omission or benign poisoning) and thereby degrade the L8 detector — with spoofed `x-counter-spy-user-id` corrupting L10 audit attribution. This is the highest-value chain because a single static secret unlocks it end-to-end.

**Chain B — Novel jailbreak → sole-judge gate → sanctioned egress.** A plaintext, low-entropy, non-obfuscated, corpus-unmatched prompt (L8-T01) passes every heuristic, leaving the safeguard judge as the only gate (L2-T03); a judge false-negative forwards adversarial content to the downstream responder over the sanctioned egress channel (L6-T06). Output sanitization and the canary token are the last-line mitigations.

**Chain C — Fail-secure weaponized → availability denial.** Inputs engineered to trip Global Pause conditions (ReDoS-like timing, canary strings, forced judge 503) exploit the fail-secure design (L8-T05) to halt the entire gateway (L4 orchestration DoS), amplified by absent backend rate limiting and alert fatigue (L9-T06).

**Chain D — Privileged insider → selective audit edit.** With no evidenced WORM logging, a backend/Firestore admin credential (L7) enables selective audit-record deletion (L9-T02 / T23) to conceal a prior escape (L10-T05 audit gap).

No multi-agent cascade/collusion chains are constructed — no autonomous multi-agent delegation is evidenced.

## 10. SSRM Ownership Summary

Deployment model in play: **AaI today → AaP (AWS) target.** Under AaI the Agent Owner = **AIC + AP + OSP**; several rows shift toward the platform under the AaP target (noted where relevant).

| Threat | Layer | Primary Owner | Shared | Agent Owner Accountable |
|---|---|---|---|---|
| L2-T03 Jailbreak vs judge | L2 | MP | OSP, AP, CSP | Yes |
| L2-T04 Model supply chain | L2 | MP | CSP | Yes |
| L3-T01 Corpus poisoning | L3 | AIC | OSP, MP | Yes |
| L3-T02 Vector DB access | L3 | CSP | AIC | Yes |
| L3-T07 Context overflow | L3 | AIC | OSP, MP | Yes |
| L4-T07 HITL bypass | L4 | OSP | AP, AIC | Yes |
| L6-T06 Tool egress exfil | L6 | OSP + AP + **Tool Provider** | MP | Yes |
| L7-T02/03 Shared credential | L7 | AIC | CSP, OSP | Yes |
| L8-T01 Guardrail bypass | L8 | Shared (all, TVM-11) | CSP/MP/OSP/AP | Yes — AIC integrating |
| L8-T05 ReDoS / availability | L8 | Shared | CSP, OSP | Yes |
| L9-T02 Audit tamper-evidence | L9 | Shared (LOG) | CSP | Yes — AIC integrating |
| L10-T06/01 Compliance/Shadow-AI | L10 | **AIC (non-delegable)** | — | Yes |

> Per MAESTRO §9.3 / 3SRM §3.1: **"In all three deployment models, Layer 10 (Governance) remains with the Agent Owner. Governance cannot be outsourced."** The Agent Owner (AIC) is accountable for every threat above regardless of which provider's component is the proximate cause.

**Relevant AICM structural gaps (3SRM §2.6):** *Dynamic Tool Discovery* is **not** triggered (no runtime MCP binding). *Autonomous Decision-Making* applies weakly — the judge makes an autonomous verdict, a behavioral-responsibility surface not cleanly owned by any AICM control. No sub-agent-delegation or cross-org-collaboration gaps apply (single-service, no A2A).

## 11. Framework Crosswalk

Not requested. The MITRE ATLAS 16-node organizer the system already uses (e.g., `T0051` Prompt Injection, `T0054` LLM Jailbreak, `T0031` Evade ML Model, `T0058` Exfiltration via Tool) aligns naturally with L2-T03/L8-T01 (ATLAS `AML.T0051`/`T0054`), L6-T06 (`AML.T0058`-class), and L3-T01 (`AML.T0020` Poison Training Data-class). A full STRIDE/OWASP/ATLAS/NIST/ISO-42001 crosswalk can be produced on request.

## 12. Required Validation Steps

1. Provide judge/responder inference parameters and any red-team/eval results (resolves L2-T03, L8-T01 efficacy).
2. Confirm the production identity design and timeline for OIDC/JWT + universal logout (resolves L7 primary finding).
3. Document the RBAC/approval workflow for `/v1/instruction-monitor/reviewed-adversarial` and KB/Golden-Set promotion (resolves L3-T01, L4-T07).
4. Evidence audit-log immutability/WORM and retention, and log-store separation (resolves L9-T02).
5. Provide production infra design for pgvector, network policy, and rate limiting (resolves L3-T02, L8-T05).
6. Supply model-weight integrity hashes/signatures for judge and embedding models (resolves L2-T04).
7. Provide bias/disparate-impact testing for language heuristics and third-party model training-data disclosures (resolves L10).
8. **Contractual (3SRM §6.2):** obtain AI-CAIQ responses from OpenAI/Google/Lara; add shared-responsibility addenda and safety SLAs (escalation time, drift thresholds) for the frontier providers.
9. Retrieve the empty `Technical/File_Structure.md` to close the file-tree evidence gap.

## 13. Conclusion: What Can and Cannot Be Concluded

**Can be concluded.** Safeguard LLM has a well-considered, defense-in-depth L8 control surface that is the product's core competency, backed by genuine strengths: strict control/inference-plane separation, pervasive fail-secure behavior, provider secrets excluded from the client bundle, redaction-before-inference, egress restriction of embeddings to a private network, and Firestore rules that block client-side forgery of security fields and role self-elevation. Integrity discipline on the seed corpus and the Safeguard Effective Prompt (verified SHA-256 hashes) is exemplary and should be extended to model weights.

The dominant residual risk is **identity**: a single shared static bearer token gates all execution routes, with per-user accountability resting on a client-asserted header and no per-user revocation — this is the linchpin of the highest-value attack chain (Chain A) and the top remediation priority. Secondary, well-defined risks are the **sole-judge semantic gate** for novel plaintext jailbreaks (Chain B), **fail-secure-as-availability-denial** absent rate limiting (Chain C), and **non-audit-grade logging** (Chain D). Each has a concrete, evidenced mitigation path, most of which the project's own documentation already names as target-state.

**Cannot be concluded.** Detector *efficacy* (false-negative rate under adaptive attack), judge robustness, model-weight integrity, production infrastructure/auth posture, audit immutability, and bias/discrimination behavior are all **Unanswerable from current evidence** — they require the artifacts listed in Section 12. No finding in this assessment should be read as asserting the system is either compromised or proven safe on those axes; they are documented gaps, not verdicts.

---

*Produced with the AI Threat Model Analyst skill (MAESTRO v2.0). Facts, inferences, and unknowns are kept separate per skill rule #2; MCP-specific and multi-agent threats were withheld as not-evidenced per rules #3 and #5. This is a defensive threat model and does not constitute an offensive playbook.*
