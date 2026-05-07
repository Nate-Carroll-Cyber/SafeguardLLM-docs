# Technical Reference & Architecture Specification: Counter-Spy.ai

**Version:** v2.1  
**Status:** Beta / Promotion to Beta  
**Classification:** Proprietary / AppSec Engineering  

---

## 1. Architecture Deep Dive: The 'Shield-and-Sword' Pattern

Counter-Spy.ai employs a **Shield-and-Sword** architectural pattern to secure Large Language Model (LLM) interactions. This multi-stage defense-in-depth strategy ensures that adversarial payloads are neutralized at the edge before reaching high-compute inference engines.

### 1.0 Current Beta Implementation
The current Beta is a React/Vite/Firebase application with a TypeScript/Express backend gateway. Governance is still enforced first by local TypeScript sanitization logic in the client, while backend routes now own the secure intercept path, downstream responder handoff, manual Lara translation proxying, and the Sam Spade CTF API. Firebase Authentication still provides user identity and Firestore still stores audit logs, knowledge-base content, and synchronized governance configuration.

### 1.1 Logical Flow
The system bifurcates the request lifecycle into two distinct phases:
1.  **The Shield (Local Sanitization & Governance):** A low-latency engine that performs heuristic analysis, PII redaction, and policy enforcement.
2.  **The Sword (Backend-Mediated Inference):** The backend `/v1/intercept` route calls an OpenAI-compatible safeguard judge before any downstream responder receives a prompt. Analyst Chat safeguard configuration remains separate from responder configuration, allowing Counter-Spy.ai to sit between different frontier model providers. Credentials can remain backend-owned, while the UI can select a safeguard provider preset (`LM_STUDIO` or `OPENAI`), provide browser-local Base URL / Model ID / memory-only API key overrides for the safeguard judge, and manage separate provider settings for clean responder traffic.
    *   **Current prompt-contract note:** The firewall stage is guided by one editable Safeguard Effective Prompt stored in System Configuration. That prompt contains the runtime JSON verdict contract, backend-owned neutral evidence contract, forbidden-category guidance, and promoted few-shot examples. System Configuration displays and hashes that exact prompt so reviewable config and runtime payload stay aligned. The current recommended effective prompt hash is `89ab9212ae0d97bac17e2072ec5851e76a3991b766602c9f5e5bcca127499a9d`. The safeguard judge receives the effective prompt plus a candidate prompt after deterministic normalization/redaction and neutral preprocessing evidence, not the local sanitizer's final verdict or reasoning. Only prompts the safeguard judge returns as `CLEAN` are forwarded to the responder model with the active Downstream Responder Prompt as its instruction when responder routing is enabled; otherwise clean traffic returns local responder passthrough. Legacy decision-shaped safeguard payloads, malformed JSON, and non-JSON outputs are treated as `SUSPICIOUS` and queued for review rather than normalized into an allow path. Safeguard upstream calls are bounded by `SAFEGUARDS_TIMEOUT_MS` (default 30s); timeout or provider failure returns structured `SHIELD_ERROR` fail-secure telemetry instead of an unstructured transport error.
    *   **Current forbidden-category note:** Configured forbidden phrases are enforced locally and included in the Safeguard Effective Prompt, which remains the reviewable source for baseline category and gibberish guidance.
    *   **Current telemetry and gating note:** When the responder provider returns usage metadata, the gateway surfaces prompt/completion/total token counts. When responder routing is disabled for local passthrough review, the gateway also surfaces OpenAI-compatible safeguard judge usage from LM Studio/OpenAI-style payloads so safeguard token consumption is not lost. The browser can apply an operator-supplied max context window as a pre-submit gate in Analyst Chat and the Prompt Playground, then reuse that same value with either responder or safeguard usage to compute post-run context utilization for audit review.
*   **Manual Translation Gateway (`/v1/translate`)**:
    *   Owns Lara Translate access for the Playground.
    *   Runs only when an analyst explicitly triggers the Normalize - Translate pipeline.
    *   Supports two modes:
        *   auto-detect source -> English recovery
        *   English -> selected foreign-language variant generation
    *   Uses backend environment credentials by default, with optional browser-memory Lara Base URL, Access Key ID, and API Key overrides for local demos.
    *   Keeps translation licensing/cost exposure bounded by avoiding automatic calls on prompt edits or standard submissions.
*   **Browser-Local Spell Verification**:
    *   Runs before the optional Lara translation hop inside the Playground Normalize - Translate pipeline.
    *   Uses the local typo-recovery heuristic only; no external LanguageTool/provider request is made from this stage.
    *   Skips obvious encoded or non-plain-text inputs so adversarial encodings are preserved for firewall testing.

### 1.2 System Resilience & Fallback Policies
The Beta implementation adheres to a **Fail-Secure** philosophy across all critical components:

| Component | Failure Scenario | Policy | Outcome |
| :--- | :--- | :--- | :--- |
| **Shield Engine** | Timeout / 5xx Error | **Fail-Secure** | Request is blocked; user receives a 503 Service Unavailable. |
| **Safeguard Judge** | Timeout / provider failure | **Fail-Secure** | Backend returns `202` with `SHIELD_ERROR`, `SAFEGUARD_TIMEOUT` or `SAFEGUARD_ERROR`, and `FAIL_SECURE`; the frontend marks the audit record `PENDING_REVIEW` and activates Global System Pause. |
| **Frontend Intercept Call** | Backend route hangs beyond 45s | **Fail-Secure** | Browser aborts `/v1/intercept`, activates Global System Pause, records `SHIELD_ERROR`/`SAFEGUARD_TIMEOUT`, and does not run local fallback inference. |
| **Governance Sync** | Database Connection Loss | **Best-Effort Sync** | The app keeps its current in-memory/default governance state. It does not automatically force `isGlobalPause: true` on startup or sync failure. |
| **Sanitization** | ReDoS / Logic Error | **Fail-Secure** | If sanitization latency exceeds 1,000ms, the triggering request is blocked before inference, logged as `Adversarial` with `ReDoS_ATTEMPT_DETECTED`, and automatic Global System Pause is activated for subsequent traffic. |

---

## 2. Heuristic Logic & Mathematical Intent

### 2.1 Shannon Entropy Sliding Window
To defeat **Token Dilution**, the system utilizes a **Sliding Window Shannon Entropy** calculation.
*   **Formula:** $H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$
*   **Intent:** By isolating high-entropy spikes (e.g., Base64 shellcode) in 35-character windows, the system identifies obfuscated payloads that would otherwise be averaged out in a global entropy check.

### 2.1.1 English-Likeness Heuristic
To catch substitution-cipher gibberish that still looks like ordinary alphabetic prose, the frontend sanitizer also evaluates a bounded English-likeness heuristic.
*   **Intent:** Detect long alphabetic token sequences with weak English trigram support, high token uniqueness, and prose-like spacing that would evade raw entropy checks.
*   **Current Policy:** This heuristic is treated as an obfuscation-family signal, not a mild language warning. When it fires, the prompt is classified as `Adversarial`.

### 2.1.2 Entropy Policy Bands
Entropy is now evaluated with one shared policy across the live sanitizer, Audit Logs, and Metrics.
*   **Allowed:** `<= 3.6`
*   **Suspicious:** `> 3.6` and `<= configured Entropy Threshold`
*   **Adversarial:** `> configured Entropy Threshold`
*   **Intent:** Keep the governance slider focused on the operator-chosen adversarial ceiling while preserving a stable suspicious floor for concealment review.

### 2.2 Syntactic Complexity Scoring
The analyzer uses a weighted heuristic to detect "Instruction Stacking":
*   **Constraint Density (High Weight):** Frequency of imperative keywords.
*   **Special Char Ratio (Medium Weight):** Inverse-match regex `/[a-zA-Z0-9\s]/g` to detect code-like syntax.
*   **Thresholds:** Scores > 50 contribute to `Suspicious` classification; scores > 90 independently trigger `Adversarial` classification.
*   **Feature Breakdown:** The Prompt Playground renders a research-only feature vector above the Syntactic Score card. It is calculated from the prompt and deterministic sanitizer evidence before any Safeguard LLM forwarding. It shows instruction pressure, constraint density, syntax/wrapper pressure, obfuscation pressure, entropy pressure, and n-gram obfuscation signal with raw values and normalized contributions.
*   **Feature Pressure:** Governed prompt submissions persist an analysis-only feature pressure score, top pressure driver, and feature-vector breakdown directly on the audit event before Safeguard LLM forwarding. The stored schema still uses `researchSignal` for backward compatibility, but the operator-facing label is Feature Pressure because it represents a 0-100 structural pressure score for comparison and calibration. The main Metrics view summarizes these live audit fields in a separate Feature Pressure card with the average 0-100 score plus average instruction, constraint-density, syntax/wrapper, obfuscation, entropy, and n-gram pressures. Browser-local Playground snapshots still exist for export, but the Metrics card is not snapshot-dependent. This score does not independently block or allow traffic.

### 2.3 Obfuscation Severity Policy
The current Beta now enforces a stricter plain-text-English-chatbot posture for concealment attempts.
*   **Policy:** Any recognized decode/structural obfuscation signal is classified as `Adversarial`, regardless of whether later recovery would have revealed otherwise benign content. Pig Latin is the exception: it is detected, not decoded, and routes to `Suspicious` / review unless other stronger signals are present.
*   **Covered families:** Base64, continuous and byte-delimited Hex (`0x..`, `\x..`, and spaced/comma-separated bytes), 8-bit binary, ASCII decimal byte lists, A1Z26/alphabet-position encoding, URL encoding, HTML entities, unicode escapes, compatibility glyphs, symbol substitution, leetspeak, Pig Latin, ROT13, reverse text, NATO phonetic, Morse code, braille, regional indicators, recursive decode chains, chunking, variable expansion, vertical text, coordinate ciphers, and low-English-likeness alphabetic gibberish.
*   **Vertical reflow boundary:** Before detector matching, the sanitizer builds a reflowed candidate for alphabetic single-character columns and playground-style `x - position N` rows. The regular detectors run against both the original text and this reflowed candidate. `VERTICAL_TEXT` is also emitted as a standalone obfuscation signal, while digit-only enumerated lists are excluded from the reflow path.
*   **Payload decode ordering:** The decoder path normalizes and reflows first, then recursively inspects high-frequency payload encodings before PII redaction decisions rely on token context. Credit-card detection is boundary-, issuer-, length-, and Luhn-aware so hashes and long hex-like IDs are not redacted as cards.
*   **Reasoning:** Counter-Spy.ai now treats concealment itself as hostile behavior in the governed prompt path, rather than as a lower-severity curiosity that waits for a second content-based match.
*   **Execution boundary:** Recognized obfuscation-family adversarial verdicts are terminal at the local shield layer. Those prompts should not proceed into the backend `/v1/intercept` path, and backend-availability fallback messages should only appear for prompts that were locally eligible for downstream inference.

### 2.4 Structural Jailbreak Signals
The deterministic sanitizer also flags jailbreak structures that are independent of the user's topical request.
*   **Forced-prefix injection:** `FORCED_PREFIX_INJECTION` catches opening instructions such as "always start with", "respond only with", or "first word must be". These prompts route to review rather than being auto-forwarded on topical benignness.
*   **Anti-sanitization clauses:** `ANTI_SANITIZATION_CLAUSE` catches explicit requests to avoid sanitization, filtering, warnings, disclaimers, or safety policies even when embedded in fictional framing.
*   **Persona injection:** `PERSONA_INJECTION` fires when a persona assignment co-occurs with unrestricted-capability language such as no rules, no restrictions, unrestricted, uncensored, developer mode, or do-anything claims.
*   **Named persona telemetry:** `ALLCAPS_PERSONA` records all-caps hyphenated persona handles such as `SIGMA-ZERO` as signal-only telemetry; it is not sufficient to gate traffic by itself.

---

## 3. State Management & Persistence

### 3.1 Global Pause (HOTL) Persistence
The governance state is persisted in Firestore (`config/governance`). 
*   **Current runtime behavior:** The frontend initializes `isGlobalPause` to `false` and then overlays Firestore state when the governance document arrives. In local review mode the same state remains in memory only. Operators should not assume startup automatically begins in a paused state.

### 3.2 Audit Log Retention
*   **Policy:** By default, logs are intended to be permanent for forensic auditability.
*   **Cost Management:** The Beta supports **Firestore TTL (Time-to-Live)**. Administrators can designate a TTL policy field in the Google Cloud Console, enabling automatic purging of logs older than a defined retention period (e.g., 90 days).

> [!NOTE]
> **Forensic Gap Awareness**: Firestore audit logs are retained independently of any downstream provider-side abuse monitoring window. If provider-side request logs are part of an investigation, forensic correlation must still happen inside that provider's retention window.

---

## 4. Security Mitigations

### 4.1 Anti-ReDoS Circuit Breaker
*   **Logic:** Every `sanitizeInput` execution is wrapped in a high-resolution timing block (`performance.now()`).
*   **Threshold:** 1,000ms.
*   **Policy:** Any sanitization pass completing above 1,000ms is treated as a potential ReDoS event. The triggering request is blocked before inference, logged as `Adversarial` with the `ReDoS_ATTEMPT_DETECTED` flag, and contributes to both the `ReDoS Trips` resilience metric and the Defense Funnel's pre-inference blocked count.

---

## 5. Gateway Architecture: `/v1/intercept`

The `/v1/intercept` endpoint is now part of the current Beta implementation. It serves as the live backend gateway between the frontend control plane and downstream inference services, while still matching the longer-term service-to-service architecture planned for ECS.

### 5.1 Authentication
Future external services would authenticate with the Counter-Spy gateway using **Bearer Tokens (JWT)**. 
*   **Header:** `Authorization: Bearer <JWT_TOKEN>`
*   **Validation:** 
    *   **Provider:** Tokens are validated against the configured Auth Provider (Firebase/OIDC).
    *   **Claims:** Validation requires `sub` (subject), `aud` (audience), and `exp` (expiration).
    *   **Policy:** Tokens are validated per-request; no local caching of validation state is performed in the Beta to ensure immediate revocation propagation.
    *   **TTL:** Token lifespan and refresh cycles are governed by the Identity Provider's policy.
*   **Current Beta Note:** In dev, the backend can run without a bearer token. Outside dev, `INTERCEPT_BEARER_TOKEN` can be required before the gateway serves `/v1/intercept`.
*   **Additional Future Support:** Integration with **AWS IAM SigV4** is planned for service-to-service communication within VPC environments.

### 5.2 Endpoint Specification
`POST /v1/intercept`

**Request Body (JSON):**
| Field | Type | Description |
| :--- | :--- | :--- |
| `prompt` | `string` | The raw input string to be sanitized. |
| `userId` | `string` | The unique identifier for the requesting user. |
| `sessionId` | `string` | The identifier for the current interaction session. |
| `metadata` | `object` | Optional key-value pairs, including browser-local safeguard Base URL, safeguard Model ID, memory-only safeguard API key override, `providerLlmRoutingEnabled` for direct/API local-only callers, `responderLlmRoutingEnabled`, responder provider, responder Base URL, responder Model ID, memory-only responder API key override, the active downstream responder prompt, and Sam Spade responder persona/scenario prompts for `ctf_chat` traffic. |

**Safeguard Judge Input Contract:**

The backend sends a candidate prompt after deterministic normalization/redaction and states that the candidate is not guaranteed safe. It then sends neutral preprocessing evidence: detection flags, redaction labels, decode telemetry, suspicious chunk count, max entropy, global entropy, and syntactic score. Local sanitizer verdict and reasoning remain response/audit telemetry only and are not sent to the safeguard judge.

**Safeguard Judge Output Contract:**

The safeguard judge must return only JSON with this runtime shape:

```json
{"verdict":"CLEAN|SUSPICIOUS|ADVERSARIAL","analystReasoning":"brief reason"}
```

Decision-shaped payloads such as `ALLOW_AND_FORWARD`, `BLOCK`, `QUEUE_FOR_REVIEW`, or `FAIL_SECURE` are no longer accepted as runtime output. The backend records their schema shape as `decision` and fails secure to `SUSPICIOUS` / `QUEUED`. Non-JSON, malformed JSON, and schema-mismatched outputs are recorded as `malformed` and also queue for review.

**Response Definitions:**
| Code | Status | Description |
| :--- | :--- | :--- |
| `200` | `CLEAN` | Payload passed local prechecks and the safeguard judge. Responses may include downstream responder output or local responder passthrough with responder status `DISABLED_LOCAL_ONLY`. Direct/API callers that explicitly set `providerLlmRoutingEnabled: false` can still request deterministic local inspection. |
| `202` | `QUEUED` | Suspicious payload queued for HITL/HOTL review, including schema-non-conforming safeguard outputs. |
| `401` | `UNAUTHORIZED` | Missing or invalid Bearer Token. |
| `403` | `INTERCEPTED` | Adversarial local precheck or safeguard judge block. This is a governed result with a structured intercept payload, not a backend transport failure. |
| `202` | `SHIELD_ERROR` | Fail-secure safeguard timeout/failure. The response is structured and includes `SAFEGUARD_TIMEOUT` or `SAFEGUARD_ERROR` plus `FAIL_SECURE`; the frontend routes the record to review and pauses automated inference. |
| `502` | `RESPONDER_ERROR` | Downstream responder failure after safeguard approval. This is surfaced separately from safeguard failure. |
| `503` | `SHIELD_ERROR` | Reserved for future Shield Engine transport failures outside the structured safeguard timeout path. |

Downstream responder outputs are output-sanitized before display. Safeguard telemetry and responder telemetry such as provider, model ID, status, latency, prompt hash, retry marker, token usage, prompt profile, context utilization, and output-sanitization flags are normalized back into Counter-Spy.ai audit records or structured gateway logs. Local responder passthrough is represented with responder status `DISABLED_LOCAL_ONLY` and model `local-responder-passthrough`; in that mode, OpenAI-compatible safeguard usage is used as the audit token source when present.

### 5.3 Backend Safeguard Attribution Fields
When a prompt reaches `/v1/intercept`, the frontend persists a structured backend outcome alongside the normal audit fields:

| Field | Meaning |
| :--- | :--- |
| `backendGatewayStatus` | Gateway outcome: `CLEAN`, `INTERCEPTED`, `QUEUED`, or `SHIELD_ERROR`. |
| `backendSafeguardVerdict` | Safeguard judge verdict: `CLEAN`, `SUSPICIOUS`, or `ADVERSARIAL`. |
| `backendSafeguardReasoning` | Human-readable judge rationale returned by the backend. |
| `backendReachedSafeguard` | Boolean marker that the prompt reached the backend safeguard layer. |
| `localPrecheckLatencyMs` | Backend deterministic precheck latency in milliseconds. |
| `backendSafeguardLatencyMs` | Pure Safeguard LLM call latency in milliseconds. |
| `backendGatewayLatencyMs` | Total `/v1/intercept` gateway latency in milliseconds. |
| `responderLatencyMs` | Downstream responder latency in milliseconds; local passthrough records `0`. |

These fields are the source of truth for Defense Funnel attribution and runtime latency display. Metrics no longer rely on response-text matching to determine whether a Bulk Ingest or Analyst Chat item was blocked locally, blocked by the safeguard judge, or allowed through to the downstream responder. The UI reports safeguard latency separately from responder latency so local passthrough does not hide safeguard timing.

### 5.4 Safeguard Schema and Divergence Observability
Every safeguard decision emits structured JSON logs for metric extraction:
*   `metric_increment` with `metric: "safeguard.schema"` and tag `shape` equal to `verdict`, `decision`, or `malformed`.
*   `metric_increment` with `metric: "safeguard.divergence"` and tags `judgeVerdict`, `gatewayAction`, and `divergent`.
*   `safeguard_decision` with prompt hash, retry marker, response shape, judge verdict, gateway action, divergence boolean, optional raw reasoning trace when the provider exposes it, and safeguard latency.

The expected mapping is `CLEAN -> CLEAN`, `SUSPICIOUS -> QUEUED`, and `ADVERSARIAL -> INTERCEPTED`. Any non-zero divergence on adversarial or suspicious traffic indicates the orchestration layer is overriding the judge and should be investigated as a correctness issue.

---

## 6. Operational Controls: Telemetry Isolation

### 6.1 The `source` Field
The `source` field preserves traffic provenance without hiding data from the primary analyst views.
*   **Provenance:** Records can distinguish `analyst_chat` traffic from `bulk_ingest` traffic.
*   **DPO Labeling:** Bulk ingest logs carry `batchId` and `expectedVerdict` metadata, allowing analysts to perform "False Negative" audits while still comparing that traffic against analyst-entered activity.

### 6.2 Metrics Architecture
The platform utilizes a real-time anomaly detection engine to monitor threat velocity.
*   **Statistical Baseline:** Calculates a rolling 24-hour mean ($\mu$) and standard deviation ($\sigma$) of threat events.
*   **Z-Score Calculation:** $Z = \frac{x - \mu}{\sigma}$.
*   **Alerting Thresholds:** 
    *   **Z > 2.0**: Triggers "Anomalous Activity" dashboard alerts.
    *   **Z > 5.0**: Triggers high-priority escalation via PagerDuty/Slack integrations.
*   **Layered Defense Funnel:** The Metrics surface now tracks the governed prompt path across both enforcement layers:
    *   **Pre-Inference Block Rate:** Fraction of prompts blocked before the Safeguard LLM is invoked.
    *   **Model Intervention Rate:** Fraction of prompts that reached the Safeguard LLM and were then blocked or queued there.
    *   **Post-Model Escape Rate:** Fraction of likely malicious prompts that bypass both the pre-inference layer and the Safeguard LLM layer and still land clean or informational.
    *   **Structured attribution:** `backendReachedSafeguard`, `backendGatewayStatus`, and `backendSafeguardVerdict` determine whether a record belongs to the local pre-inference bucket or the backend safeguard/model-intervention bucket.
    *   **Ground-Truth Assist:** When available, bulk-ingest `expectedVerdict` labels are used to strengthen post-model escape calculations instead of relying only on final severity heuristics.
*   **Detection Signal Rollups:** The Metrics **Detection Signals** card reports prompt counts by detection family, not raw per-flag totals. The same aggregation helpers are used for local-review overlays and Firestore-backed metrics. `FORBIDDEN_TOPIC` and `FORBIDDEN_PHRASE` are grouped under **Forbidden Phrase Hits**, while **Obfuscation Hits** counts any stored obfuscation technique from `obfuscationSummary.techniques` or legacy detection flags so the rollup matches the prompt-detail badges.
*   **Implementation Details**: For detailed dashboard telemetry and SOPs, refer to the [Analyst & Administrator Operations Guide](../OPERATIONS_GUIDE.MD).
