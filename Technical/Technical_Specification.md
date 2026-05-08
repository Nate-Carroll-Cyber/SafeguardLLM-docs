# Technical Reference & Architecture Specification: Counter-Spy.ai

**Version:** v2.2
**Status:** Beta / Promotion to Beta  
**Classification:** Proprietary / AppSec Engineering  

---

## 1. Architecture Deep Dive: The 'Shield-and-Sword' Pattern

Counter-Spy.ai employs a **Shield-and-Sword** architectural pattern to secure Large Language Model (LLM) interactions. This multi-stage defense-in-depth strategy ensures that adversarial payloads are neutralized at the edge before reaching high-compute inference engines.

### 1.1 Logical Flow
The system bifurcates the request lifecycle into two distinct phases:
1.  **The Shield (Local Sanitization & Governance):** A low-latency engine that performs heuristic analysis, PII redaction, and policy enforcement.
2.  **The Sword (Backend-Mediated Inference):** The backend gateway runs deterministic prechecks, compares clean candidates against the pgvector-backed instruction similarity monitor when enabled, calls an OpenAI-compatible safeguard judge, then forwards only `CLEAN` payloads to the downstream responder when responder routing is enabled. Safeguard runtime configuration is separate from responder runtime configuration, and both paths use backend-managed credentials, endpoints, and backend-owned system prompts. Browser callers cannot override provider base URLs, API keys, model base URLs, or backend prompt text on protected execution paths.
    *   **Current prompt-contract note:** The safeguard judge receives a backend-owned instruction for inspection and forwarding decisions, including the single runtime JSON verdict contract, neutral evidence contract, forbidden-category guidance, and promoted few-shot examples. System Configuration previews and hashes recommended/current safeguard prompt artifacts for review, but protected backend execution does not accept caller-supplied safeguard or responder system prompts. The safeguard judge receives a candidate prompt after deterministic normalization/redaction plus neutral preprocessing evidence; it does not receive the local sanitizer's final verdict or reasoning. Clean traffic is forwarded to the responder only after it clears the safeguard judge and responder routing remains enabled. When responder routing is disabled, clean safeguard verdicts return local responder passthrough instead. Legacy decision-shaped, malformed, or non-JSON safeguard outputs are treated as `SUSPICIOUS` and queued for review. Safeguard upstream calls are bounded by `SAFEGUARDS_TIMEOUT_MS` (default 30s), with browser-side `/v1/intercept` abort as a secondary 45s guard.
    *   **Current forbidden-category note:** Configured forbidden phrases are enforced locally and included in the Safeguard Effective Prompt, which remains the reviewable source for baseline category and gibberish guidance.

### 1.2 System Resilience & Fallback Policies
The Beta implementation adheres to a **Fail-Secure** philosophy across all critical components:

| Component | Failure Scenario | Policy | Outcome |
| :--- | :--- | :--- | :--- |
| **Shield Engine** | Timeout / 5xx Error | **Fail-Secure** | Request is blocked; user receives a 503 Service Unavailable. |
| **Safeguard Judge** | Timeout / provider failure | **Fail-Secure** | Backend returns structured `SHIELD_ERROR` with `SAFEGUARD_TIMEOUT` or `SAFEGUARD_ERROR` plus `FAIL_SECURE`; the frontend marks the audit record `PENDING_REVIEW` and activates Global System Pause. |
| **Instruction Similarity Monitor** | Database unavailable or embedding provider failure | **Best-Effort / Hash Fallback** | Gateway logs the monitor failure and continues with deterministic prechecks plus safeguard evaluation. If embeddings fail but the database is reachable, exact/loose hash and SimHash comparison still run. |
| **Frontend Intercept Call** | Backend route hangs beyond 45s | **Fail-Secure** | Browser aborts `/v1/intercept`, records timeout fail-secure telemetry, activates Global System Pause, and does not run local fallback inference. |
| **Governance Sync** | Database Connection Loss | **Best-Effort Sync** | The app keeps its current in-memory/default governance state. It does not automatically force `isGlobalPause: true` on startup or sync failure. |
| **Sanitization** | ReDoS / Logic Error | **Fail-Secure** | If sanitization latency exceeds 1,000ms, the triggering request is blocked before inference, logged as `Adversarial` with `ReDoS_ATTEMPT_DETECTED`, and the backend returns `governanceAction: "GLOBAL_PAUSE"` so the frontend activates Global System Pause for subsequent traffic. |

---

## 2. Heuristic Logic & Mathematical Intent

### 2.1 Shannon Entropy Sliding Window
To defeat **Token Dilution**, the system utilizes a **Sliding Window Shannon Entropy** calculation.
*   **Formula:** $H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$
*   **Intent:** By isolating high-entropy spikes (e.g., Base64 shellcode) in 35-character windows, the system identifies obfuscated payloads that would otherwise be averaged out in a global entropy check.

### 2.1.1 English-Likeness Heuristic
To catch alphabetic substitution gibberish that still resembles plain prose, the frontend sanitizer also applies a bounded English-likeness check.
*   **Signals:** low English trigram support after normalization, bounded Caesar-shift recovery improvement, high token uniqueness, and prose-like spacing.
*   **Intent:** Surface cipher-style concealment that entropy and syntactic heuristics alone may under-rate.
*   **Current Policy:** A hit is treated as an obfuscation-family signal and therefore classified as `Adversarial`.

### 2.1.2 Entropy Policy Bands
The current Beta uses one shared entropy policy across the submit-time firewall, Audit Logs, and Metrics.
*   **Allowed:** prompt entropy `<= 3.6`
*   **Suspicious:** prompt entropy `> 3.6` and `<= configured Entropy Threshold`
*   **Adversarial:** prompt entropy `> configured Entropy Threshold`
*   **Operator Meaning:** the governance slider now sets the maximum approved entropy before a prompt becomes adversarial; it no longer acts as the suspicious floor.

### 2.2 Syntactic Complexity Scoring
The analyzer uses a weighted heuristic to detect "Instruction Stacking":
*   **Constraint Density (High Weight):** Frequency of imperative keywords.
*   **Special Char Ratio (Medium Weight):** Inverse-match regex `/[a-zA-Z0-9\s]/g` to detect code-like syntax.
*   **Thresholds:** Scores > 50 contribute to `Suspicious` classification; scores > 90 independently trigger `Adversarial` classification.
*   **Pre-Inference Feature Vector:** The Playground now exposes the raw syntactic components behind the score, including weighted constraint pressure, density contribution, wrapper count, verbosity bonus, and obfuscation bonus. These fields feed the analysis-only Feature Pressure score and do not change runtime verdict thresholds. The Metrics dashboard averages all six normalized component pressures across submitted prompts: instruction, constraint density, syntax/wrapper, obfuscation, entropy, and n-gram.
*   **N-Gram Obfuscation Telemetry:** The Playground feature vector includes English trigram hit rate, best Caesar-shift trigram recovery, and the low n-gram likelihood boolean used to explain alphabetic gibberish detections. This is separate from the runtime Foreign / Mixed Language detection signal.

### 2.3 Obfuscation Severity Policy
Counter-Spy.ai now treats prompt concealment itself as a hostile act in the governed path.
*   **Policy:** Any recognized decode/structural obfuscation signal is classified as `Adversarial`, even if the concealed content would otherwise decode into something benign. Pig Latin is detected without lossy decoding and routes to `Suspicious` / review unless another stronger signal fires.
*   **Covered families:** Base64, continuous and byte-delimited Hex (`0x..`, `\x..`, and spaced/comma-separated bytes), 8-bit binary, ASCII decimal byte lists, A1Z26/alphabet-position encoding, URL encoding, HTML entities, unicode escapes, compatibility glyphs, symbol substitution, leetspeak, Pig Latin, ROT13, reverse text, NATO phonetic, Morse code, braille, regional indicators, recursive decode chains, coordinate ciphers, structural wrappers, vertical text, and low-English-likeness alphabetic gibberish.
*   **Vertical reflow:** Alphabetic single-character columns and playground-style `x - position N` rows are reflowed into an additional detector candidate before keyword, regex, and jailbreak-structure checks run. `VERTICAL_TEXT` is emitted independently as an obfuscation signal, while digit-only enumerated lists are not reflowed.
*   **Credit-card false-positive boundary:** Credit-card redaction requires card-shaped tokens with non-alphanumeric boundaries, valid major-network lengths, issuer prefix checks, and Luhn validation. Long hex hashes, content IDs, and transaction IDs are preserved for decoder analysis rather than being redacted as card data.
*   **Routing rule:** Once the frontend sanitizer classifies a prompt as obfuscation-family `Adversarial` or otherwise locally `Suspicious`/`Adversarial`, that prompt should terminate before backend inference. Backend error messaging is reserved for prompts that were actually allowed to attempt `/v1/intercept`.

### 2.4 Structural Jailbreak Signals
The deterministic sanitizer now flags structural jailbreak patterns before the safeguard layer:
*   `FORCED_PREFIX_INJECTION`: opening instructions that force the responder to start, begin, answer only with, or use a required first word/line/character.
*   `ANTI_SANITIZATION_CLAUSE`: explicit requests to avoid sanitization, moderation, filtering, warnings, disclaimers, or safety policies.
*   `PERSONA_INJECTION`: persona assignment combined with unrestricted capability language such as no rules, unrestricted, uncensored, developer mode, or do-anything claims.
*   `ALLCAPS_PERSONA`: signal-only telemetry for all-caps hyphenated persona handles; this flag alone does not gate traffic.

---

## 3. State Management & Persistence

### 3.1 Global Pause (HOTL) Persistence
The governance state is persisted in Firestore (`config/governance`). 
*   **Current runtime behavior:** The frontend initializes `isGlobalPause` to `false` and then overlays Firestore state when the governance document arrives. In local review mode the same state remains in memory only. Startup should not be treated as implicitly paused.

### 3.2 Audit Log Retention
*   **Policy:** By default, logs are intended to be permanent for forensic auditability.
*   **Cost Management:** The Beta supports **Firestore TTL (Time-to-Live)**. Administrators can designate a TTL policy field in the Google Cloud Console, enabling automatic purging of logs older than a defined retention period (e.g., 90 days).

> [!NOTE]
> **Forensic Gap Awareness**: Firestore audit logs are retained independently of any downstream provider-side abuse monitoring window. For incidents requiring cross-referencing provider-side request logs, forensic analysis must occur within that provider's retention window.

---

## 4. Security Mitigations

### 4.1 Anti-ReDoS Circuit Breaker
*   **Logic:** Every `sanitizeInput` execution is wrapped in a high-resolution timing block (`performance.now()`).
*   **Threshold:** 1,000ms.
*   **Policy:** Any sanitization pass completing above 1,000ms is treated as a potential ReDoS event. The triggering request is blocked before inference, logged as `Adversarial` with the `ReDoS_ATTEMPT_DETECTED` flag, returns `governanceAction: "GLOBAL_PAUSE"` from `/v1/intercept`, and contributes to both the `ReDoS Trips` resilience metric and the Defense Funnel's pre-inference blocked count.

---

## 5. API Reference: `/v1/intercept`

### 5.1 Authentication
Current Beta protected execution routes require a shared backend bearer credential before work begins.

*   **Header:** `Authorization: Bearer <INTERCEPT_BEARER_TOKEN>`
*   **Current Beta Implementation:** `INTERCEPT_BEARER_TOKEN` configures the backend-side credential, and browser gateway clients send the matching `VITE_BACKEND_BEARER_TOKEN` value with `/v1/intercept`, `/v1/translate`, `/v1/instruction-monitor/reviewed-adversarial`, and `/v1/ctf/sam-spade/*` requests. The backend performs a static bearer-token comparison for these routes.
*   **Planned Production Control:** JWT/OIDC validation is not implemented in the current backend. A production deployment should replace or front this shared-token check with provider-backed JWT validation, including per-request validation of `sub`, `aud`, and `exp`, plus the identity provider's token lifetime and revocation policy.
*   **Future Support:** Integration with **AWS IAM SigV4** is planned for service-to-service communication within VPC environments.

### 5.2 Endpoint Specification
`POST /v1/intercept`

**Request Body (JSON):**
| Field | Type | Description |
| :--- | :--- | :--- |
| `prompt` | `string` | The raw input string to be sanitized. |
| `userId` | `string` | The unique identifier for the requesting user. |
| `sessionId` | `string` | The identifier for the current interaction session. |
| `metadata` | `object` | Strict allowlist only: `localReviewMode`, `source`, `providerLlmRoutingEnabled`, `responderLlmRoutingEnabled`, optional browser-memory `safeguardApiKey`, and optional instruction-monitor embedding fields. Browser callers cannot choose backend provider endpoints, model base URLs, or backend-owned system prompts. |

Protected execution routes require the backend bearer credential before work begins: `/v1/intercept`, `/v1/translate`, `/v1/instruction-monitor/reviewed-adversarial`, and all `/v1/ctf/sam-spade/*` routes. Sam Spade routes also require the caller id header used by the frontend gateway client; created sessions are stored with that owner id, and fetch/message/solve operations reject cross-owner access. Translation is routed only through backend-managed Lara environment configuration and fails closed when Lara credentials are absent.

When the instruction monitor is enabled, API callers may provide `metadata.instructionEmbedding` and `metadata.instructionChunks` with precomputed vectors. Normal frontend submissions can omit these values; the backend generates whole-prompt and chunk embeddings only when `INSTRUCTION_MONITOR_EMBEDDINGS_API_BASE_URL` points at a local/private-network OpenAI-compatible embeddings endpoint. It does not infer embeddings from `SAFEGUARDS_API_BASE_URL`, so LM Studio safeguard endpoints are never probed as embedding endpoints. Public hosted embedding endpoints are blocked for this path so malicious prompt material is not sent to third-party embedding APIs. Embeddings do not inherit the generic responder, safeguard, or OpenAI LLM endpoint.

**Safeguard Judge Input Contract:**

The backend sends a candidate prompt after deterministic normalization/redaction and states that the candidate is not guaranteed safe. It then sends neutral preprocessing evidence: detection flags, redaction labels, decode telemetry, suspicious chunk count, max entropy, global entropy, and syntactic score. Local sanitizer verdict and reasoning remain response/audit telemetry only and are not sent to the safeguard judge.

**Safeguard Judge Output Contract:**

The safeguard judge must return only JSON with this runtime shape:

```json
{"verdict":"CLEAN|SUSPICIOUS|ADVERSARIAL","analystReasoning":"brief reason"}
```

Decision-shaped payloads such as `ALLOW_AND_FORWARD`, `BLOCK`, `QUEUE_FOR_REVIEW`, or `FAIL_SECURE` are no longer accepted as runtime output. They are recorded as schema shape `decision` and fail secure to `SUSPICIOUS` / `QUEUED`. Non-JSON, malformed JSON, and schema-mismatched outputs are recorded as `malformed` and also queue for review.

**Response Definitions:**
| Code | Status | Description |
| :--- | :--- | :--- |
| `200` | `CLEAN` | Payload passed local prechecks and the safeguard judge. Responses may include downstream responder output or local responder passthrough with responder status `DISABLED_LOCAL_ONLY`. Direct/API callers that explicitly set `providerLlmRoutingEnabled: false` can still request deterministic local inspection. |
| `202` | `QUEUED` | Suspicious payload queued for HITL/HOTL review, including schema-non-conforming safeguard outputs. |
| `401` | `UNAUTHORIZED` | Missing or invalid Bearer Token. |
| `403` | `INTERCEPTED` | Adversarial local precheck or safeguard judge block. This is a governed result with a structured intercept payload, not a backend transport failure. |
| `202` | `SHIELD_ERROR` | Structured fail-secure safeguard timeout/failure. Includes `SAFEGUARD_TIMEOUT` or `SAFEGUARD_ERROR` plus `FAIL_SECURE`; the frontend pauses governance and routes the audit record to review. |
| `502` | `RESPONDER_ERROR` | Downstream responder failure after safeguard approval. |
| `503` | `SHIELD_ERROR` | Reserved for future Shield Engine transport failures outside the structured safeguard timeout path. |

Downstream responder outputs are output-sanitized before display. Safeguard telemetry and responder telemetry such as provider, model ID, status, latency, prompt hash, retry marker, token usage, prompt profile, context utilization, and output-sanitization flags are normalized back into Counter-Spy.ai audit records or structured gateway logs. Local responder passthrough is recorded with model `local-responder-passthrough` and status `DISABLED_LOCAL_ONLY`.

Instruction similarity hits are reported through `INSTRUCTION_SIMILARITY_MATCH` plus `INSTRUCTION_SIMILARITY_MEDIUM` or `INSTRUCTION_SIMILARITY_HIGH`. Exact SHA-256, loose SHA-256, and SimHash matches against stored `ADVERSARIAL` instructions retain the adversarial rating and are intercepted before responder forwarding with `backendGatewayStatus: INTERCEPTED` and `backendSafeguardVerdict: ADVERSARIAL`. Semantic whole-prompt or chunk-embedding matches are review evidence: they queue before responder forwarding with `backendGatewayStatus: QUEUED`, `backendSafeguardVerdict: SUSPICIOUS`, and backend reasoning that names the strongest match family.

### 5.3 Backend Safeguard Attribution Fields
The frontend carries structured backend outcome data from `/v1/intercept` into Audit Logs, local review state, and browser-local Playground/Bulk metrics:

| Field | Meaning |
| :--- | :--- |
| `backendGatewayStatus` | Gateway outcome: `CLEAN`, `INTERCEPTED`, `QUEUED`, or `SHIELD_ERROR`. |
| `backendSafeguardVerdict` | Safeguard judge verdict: `CLEAN`, `SUSPICIOUS`, or `ADVERSARIAL`. |
| `backendSafeguardReasoning` | Backend safeguard reasoning for review and operator context. |
| `backendReachedSafeguard` | True when local gates allowed the prompt to reach the backend safeguard judge. |
| `localPrecheckLatencyMs` | Backend deterministic precheck latency in milliseconds. |
| `backendSafeguardLatencyMs` | Pure Safeguard LLM call latency in milliseconds. |
| `backendGatewayLatencyMs` | Total `/v1/intercept` gateway latency in milliseconds. |
| `instructionEmbeddingDurationMs` | Instruction-monitor embedding request duration in milliseconds when the backend generated whole-prompt/chunk embeddings. |
| `responderLatencyMs` | Downstream responder latency in milliseconds; local passthrough records `0`. |

These fields prevent model/safeguard interventions from being misclassified as local sanitizer results and keep safeguard latency distinct from local responder passthrough latency. They are especially important for Bulk Ingest prompts that appear in Analyst Chat but are blocked by the backend safeguard judge after local sanitizer redaction. The Metrics latency profile also summarizes embedding average, P95, and sample count from `instructionEmbeddingDurationMs` when pgvector/Ollama timings are available.

Sensitive-value redaction includes bare LLM provider API keys under the `LLM_API_KEY` label. The detector covers `sk_`, `sk-`, `sk-proj-`, and `sk-svcacct-` key forms even when they appear without an `api_key =` assignment prefix. Backend sanitization treats `LLM_API_KEY` as high-risk secret material and fails closed to `ADVERSARIAL`; frontend/local review redacts the same forms before audit display.

When the backend instruction monitor returns a medium- or high-risk result, the frontend also persists an `instructionSimilarity` object on the audit record. That object records `highestRisk`, `matchCount`, and the strongest `topMatch`, including the stored `targetHash`, `targetVerdict`, `matchReasons`, and available similarity details. Semantic details include `cosineSimilarity`, `maxChunkSimilarity`, `attentionPooledChunkSimilarity`, and `sandwichDelta`. Fingerprint-only matches, embedding failures, or runs without available embeddings still preserve hash and SimHash evidence, but semantic score fields remain `null` or absent.

### 5.4 Safeguard Schema and Divergence Observability
Every safeguard decision emits structured JSON logs for metric extraction:
*   `metric_increment` with `metric: "safeguard.schema"` and tag `shape` equal to `verdict`, `decision`, or `malformed`.
*   `metric_increment` with `metric: "safeguard.divergence"` and tags `judgeVerdict`, `gatewayAction`, and `divergent`.
*   `safeguard_decision` with prompt hash, retry marker, response shape, judge verdict, gateway action, divergence boolean, optional raw reasoning trace when exposed by the provider, and safeguard latency.
*   `instruction_embedding_generated` with embedding model, runtime source, input count, vector dimensions, chunk count, and duration for pgvector/Ollama embedding requests.

The expected mapping is `CLEAN -> CLEAN`, `SUSPICIOUS -> QUEUED`, and `ADVERSARIAL -> INTERCEPTED`. Any non-zero divergence on suspicious or adversarial traffic indicates orchestration-vs-judge drift and should be treated as a correctness issue.

### 5.5 Instruction Similarity Monitor
The v2.2 backend instruction monitor stores observed instruction fingerprints in PostgreSQL with pgvector. Each record includes strict SHA-256, loose stopword-stripped SHA-256, 2/3/4-gram SimHash values, optional whole-prompt embedding, and optional overlapping chunk embeddings.

The monitor compares exact/loose hashes, SimHash Hamming distance, whole-prompt ANN similarity, and chunk-level ANN similarity. Chunk ANN queries are concurrency-capped to protect the database pool. Deterministic fingerprint reuse of previously adversarial instructions is treated as adversarial and blocked; semantic overlap is treated as suspicious and routed to analyst review. The Docker demo uses `pgvector/pgvector:pg16` with PostgreSQL extension `vector` version `0.8.2` observed in the rebuilt demo database. Its Postgres data directory is tmpfs-backed, so recreating the Postgres container starts the instruction-memory database clean.

The pgvector corpus is intentionally limited to reviewed `ADVERSARIAL` examples. "Reviewed" means an analyst has clicked through the review workflow and the resulting severity/rating is `Adversarial`; there is no separate approval state. Runtime comparison can evaluate any candidate against the corpus, but new records are not inserted unless they are explicitly marked reviewed with an adversarial verdict. Seed imports enforce the same rule: any `core` seed record that is not reviewed and adversarial fails validation before database writes begin.

The `core` seed pack lives at `seeds/pgvector/core.json` and imports with `npm run instruction-monitor:seed:core`. Seed rows share the normal `instruction_records` and `instruction_chunks` tables, with explicit metadata columns: `seed_pack`, `seed_version`, `seed_record_hash`, `seed_snapshot_hash`, `seed_immutable`, `seed_imported_at`, and `seed_source`. Seed imports are idempotent. Matching hashes are skipped; changed immutable seed rows fail closed unless the operator uses an explicit migration/update flag.

**Match Reason Criteria:**
| UI reason | Criteria | Default threshold |
| :--- | :--- | :--- |
| `Exact Sha256` | Candidate normalized SHA-256 equals stored `sha256`. | Exact equality |
| `Loose Sha256` | Candidate stopword-stripped loose SHA-256 equals stored `sha256_loose`. | Exact equality |
| `Simhash 2gram` | 2-word-window SimHash Hamming distance is within threshold. | `<= 12` |
| `Simhash 3gram` | 3-word-window SimHash Hamming distance is within threshold. | `<= 12` |
| `Simhash 4gram` | 4-word-window SimHash Hamming distance is within threshold. | `<= 12` |
| `Embedding` | Whole-prompt pgvector cosine similarity meets the configured semantic threshold. | `>= 0.78` |
| `Chunk Embedding` | Best overlapping chunk pgvector cosine similarity meets the configured semantic threshold. | `>= 0.78` |
| `Attention Pool` | Instruction-intent-weighted chunk similarity is high enough to classify semantic overlap. | `> 0.70` risk threshold |
| `Sandwich Delta` | Best chunk similarity substantially exceeds whole-prompt similarity, exposing an embedded instruction signal diluted by surrounding text. | `> 0.20` delta and chunk `> 0.72` |

---

## 6. Operational Controls: Telemetry Isolation

### 6.1 The `source` Field
The `source` field preserves provenance without hiding traffic from the primary analyst views.
*   **Metrics Isolation:** Records can distinguish `analyst_chat`, `playground`, `bulk_ingest`, and `ctf_chat` traffic while still remaining visible in the same operational surfaces.
*   **DPO Labeling:** Bulk-ingest records carry `batchId` and `expectedVerdict` metadata, allowing analysts to perform false-negative audits without losing the surrounding production-like context.
*   **Local Review Note:** In local review mode, Metrics now use the full in-memory audit set instead of truncating counts to the newest 50 records.

### 6.2 Metrics Architecture
The platform utilizes a real-time anomaly detection engine to monitor threat velocity.
*   **Current Baseline:** Tracks recent audit activity against a rolling 24-hour hourly baseline for threat-velocity and dashboard context.
*   **Current Beta Spike Metric:** The Metrics surface reports threat velocity and alert severity from the current audit stream. The standalone anomaly helper currently calculates a rolling spike ratio against the 24-hour hourly baseline rather than a production incidenting Z-score service.
*   **Planned Production Control:** A production deployment should add a true Z-score or equivalent statistical detector in the telemetry pipeline if formal Z-score thresholds are used operationally.
*   **Alerting Thresholds:** 
    *   **Elevated spike indicator**: Treat as anomalous activity and increase monitoring cadence.
    *   **Z > 5.0**: Production target for high-priority escalation through PagerDuty/Slack or an equivalent incident-management integration. PagerDuty/Slack delivery is not implemented in the current repo.
*   **Implementation Details**: For detailed dashboard telemetry and SOPs, refer to the [Analyst & Administrator Operations Guide](../OPERATIONS_GUIDE.MD).
*   **Layered Defense Funnel:** The Metrics surface tracks pre-inference blocks, backend safeguard/model interventions, and post-model escapes. It uses `backendReachedSafeguard`, `backendGatewayStatus`, and `backendSafeguardVerdict` as structured layer attribution before falling back to older severity heuristics.
*   **Detection Signal Rollups:** The Metrics **Detection Signals** card is a prompt-count rollup by detection family. It uses shared helper functions for local-review and Firestore-backed log sets, groups `FORBIDDEN_TOPIC` and future `FORBIDDEN_PHRASE` flags as **Forbidden Phrase Hits**, and treats **Obfuscation Hits** as any persisted obfuscation technique rather than only `OBFUSCATED_INSTRUCTION`.
