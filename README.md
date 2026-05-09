# Counter-Spy.ai v2.3: Adversary-Aware Prompt Firewall & Forwarding Gateway

Counter-Spy.ai is a secure GenAI control-plane for adversary-aware LLM governance. It is a policy-enforcing firewall first, with a forwarding path for clean traffic and a review/block path for suspicious traffic.

Counter-Spy.ai decouples adversarial defense from response generation by enforcing a control-plane architecture that mediates all LLM interactions before inference.

<p align="center">
  <img src="./assets/brand/counter-spy-logo.png" alt="Counter-Spy.ai logo" width="420" />
</p>

> Govern Every Prompt. Question Every Answer.

## 📚 Documentation
- [Current Session Handoff](./Technical/SESSION_HANDOFF.md) - Compact current-state summary for the latest safeguard, detector, Feature Pressure, Metrics, and local Docker work.
- [Technical Architecture & Specifications](./Technical/ARCHITECTURE.md) - Deep dive into the Shield-and-Sword pattern and heuristics.
- [Analyst & Administrator Operations Guide](./OPERATIONS_GUIDE.MD) - Standard Operating Procedures for SOC personnel.
- [Adversarial Prompt Analysis Plan](./Technical/ADVERSARIAL_PROMPT_ANALYSIS.md) - Research plan for taxonomy, trend analysis, detection effectiveness, and failure-case reporting.
- [MITRE ATLAS Organizer Mapping](./Technical/MITRE_ATLAS_MAPPING.md) - Active 16-node ATLAS organizer taxonomy used for labeling, heat maps, and research exports.
- [Sam Spade CTF Integration Spec](./Technical/SAM_SPADE_CTF_INTEGRATION.md) - Architecture plan for bringing the noir elicitation scenario into Counter-Spy.ai as a governed input source.
- [Sam Spade API Contract](./Technical/SAM_SPADE_API_CONTRACT.md) - Current backend session/message/solve interface for the Sam Spade CTF surface, shaped for a later service/container split.
- [Local Development](./Technical/LOCAL_DEVELOPMENT.md) - Run the frontend, backend stub, tests, and Docker build before AWS access is available.

> [!IMPORTANT]
> **Sanitized Pass-through Guarantee**: Only the redacted version of a prompt is ever sent to the inference engine. Raw PII and secrets are neutralized at the local sanitization layer before any external API call is initiated.

## 🧠 Design Principles

- Treat every prompt as untrusted input
- Enforce policy before model invocation
- Minimize data exposure via sanitization
- Separate control-plane (defense) from inference-plane (response)
- Maintain full auditability of all decisions

## 🛡️ Core Security Architecture

The application implements a **Defense-in-Depth** strategy for AI interactions:

### 1. Local Sanitization Pipeline (The Filter)
Before any prompt is sent to the AI model, it passes through a local TypeScript-based sanitization layer:
- **PII & Secret Redaction**: Automatically detects and masks emails, AWS keys, IP addresses, context-aware credit-card-shaped tokens, phone numbers, and SSNs. Credit-card detection now requires token boundaries, valid card lengths, known issuer prefixes, and Luhn validation so long hex hashes, content IDs, transaction IDs, and encoded payloads are not mangled before the decoder pipeline can inspect them. It also redacts the actual values of secret keys and passwords.
- **Regex Detection**: Evaluates input against configurable regular expressions to catch sophisticated prompt injection and instruction bypass attempts. Supports `break-all` formatting for complex, lengthy patterns.
- **Normalization**: Flattens input (e.g., leetspeak conversion) to prevent keyword bypasses. The sanitizer also reflows alphabetic vertical text before detector matching, including single-character columns and `x - position N` rows, while leaving digit-only enumerated lists alone.
- **Obfuscation Detection**: Extends decode-and-inspect coverage beyond Base64 and continuous Hex to include byte-delimited Hex (`0x..`, `\x..`, and spaced/comma-separated bytes), 8-bit binary, ASCII decimal byte lists, A1Z26/alphabet-position encoding, URL encoding, HTML entities, reverse text, ROT13-style masking, NATO phonetic and Morse encodings, recursive mixed transforms, structural wrappers such as end-sequence markers, chunked payloads, variable-expansion patterns, and vertical-text formatting, plus an English-likeness heuristic for alphabetic substitution gibberish that still looks like plain text. `VERTICAL_TEXT` is emitted as a detection signal on its own, and detectors also run against the reflowed text. Pig Latin is detected by high `ay`-suffix density and routed to review as `PIG_LATIN` without attempting lossy decoding.
- **Entropy Analysis (Sliding Window)**: Calculates Shannon entropy using a sliding window approach (35-character windows, 5-character steps) to detect localized high-entropy payloads (Base64, Hex, etc.) and prevent **Token Dilution** attacks.
  - **Math**: $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
  - **Global Entropy**: The average randomness across the entire prompt.
  - **Max Window Entropy**: The highest randomness found in any specific 35-character chunk. This defeats token dilution, where an attacker attempts to hide a high-entropy payload within paragraphs of normal, low-entropy text.
  - **Thresholds**: Entropy now follows one explicit governance policy across Analyst Chat, Playground, Audit Logs, and Metrics. Prompt entropy at or below `3.6` is treated as allowed on entropy grounds alone. Entropy above `3.6` and up to the configured `Entropy Threshold` is treated as `Suspicious`. Entropy above the configured threshold is treated as `Adversarial`.
- **Syntactic Complexity Analyzer**: Real-time detection of instruction stacking, probing, and model reverse engineering. 
  - **Logic**: Analyzes constraint density and special character ratios using an inverse match regex `/[a-zA-Z0-9\s]/g`. This captures code-like syntax and URL-encoded strings that attempt to bypass semantic filters.
  - Features analysis of sentence verbosity, wrapper structure, obfuscation bonuses, entropy pressure, and trigram/Caesar n-gram obfuscation telemetry to flag highly complex, obfuscated prompts. Accessible via the Analyst Playground and integrated into the core firewall.
  - The Playground displays a research-only Feature Breakdown and Feature Pressure score for analysis/export. These explanatory metrics are calculated before any Safeguard LLM forwarding, are written into the audit event automatically on submission, and do not independently block or allow traffic.
- **Keyword & Forbidden Phrase Filtering**: Matches input against configured lists of blocked keywords and forbidden phrases. Today, forbidden phrases remain a normalized phrase-matching control rather than a standalone semantic classifier; semantic category steering is reinforced through the Safeguard Effective Prompt. The default blocklist also includes risky transport markers such as `javascript:` and `://`, and redacts policy-triggering script/URL payloads before they are persisted in audit detail views.
- **Anti-ReDoS Circuit Breaker**: Local sanitization execution time (`latencyMs`) is monitored via high-resolution timing. If a sanitization pass completes but exceeds 1,000ms, the triggering request is blocked before inference, logged as `Adversarial` with `ReDoS_ATTEMPT_DETECTED`, and an automatic Global System Pause is activated for subsequent traffic. This is a latency-based fail-secure verdict after sanitization returns, not a mid-execution process kill.
- **Persistent Preview**: Live sanitization results remain visible after execution as "Last Execution Results" until a new prompt is initiated. The preview puts the local `Adversarial` / `Suspicious` alert first, then backend safeguard status and Similarity Monitor evidence, followed by a compact `Detections` badge group for redactions, policy hits, and prompt-structure signals. The rail keeps the most recent run visible for demo flow, while the Audit Log Prompt Details modal persists the same Similarity Monitor match evidence for later review.

### 2. Output Sanitization Layer (The Guard)
A secondary sanitization layer is applied to all LLM responses:
- **Keyword Redaction**: Scans the model's output and masks any blocked keywords or forbidden phrases with `[REDACTED_KEYWORD]`.
- **PII Leak Prevention**: Re-applies PII redaction to the model's response to prevent accidental data leakage.
- **Decision-First Severity**: Output-side keyword redaction is treated as display hygiene, not as an automatic severity escalation. Final audit severity follows the structured firewall decision contract when available.

### 3. Governance Engine
The system evaluates the sanitization results against active guardrails and provides real-time administrative controls:
- **Adversarial Interception**: If entropy rises above the configured `Entropy Threshold`, if syntactic complexity exceeds `90`, or if any recognized decode/structural obfuscation signal is detected, the request is blocked pre-inference as `Adversarial`. Counter-Spy.ai treats non-plain-text concealment as hostile by default, even if the decoded content is not yet a confirmed policy violation. Pig Latin is the current exception: it is detected but not decoded and routes to `Suspicious` / `PENDING_REVIEW` unless other stronger signals fire.
- **Suspicious Interception**: If entropy rises above `3.6` without exceeding the configured adversarial cutoff, or if blocked keywords, forbidden phrases, suspicious external-call attempts, or other supporting structural signals are detected, the request is blocked pre-inference as `Suspicious`.
- **Human-in-the-Loop (HITL) Mode**: When activated, automatically intercepts borderline traffic using the live governance thresholds (default entropy threshold `4.0` as the adversarial cutoff, a fixed suspicious entropy floor at `3.6`, plus the active syntactic threshold) and routes it to a manual review queue (`PENDING_REVIEW`), allowing human analysts to intervene before the payload reaches the inference engine.
- **Forbidden Phrases Enforcement**: Configured forbidden phrases are enforced deterministically through the sanitizer. The Safeguard Effective Prompt carries the recommended forbidden-category and gibberish/obfuscation guidance used by the safeguard judge, and adds phrase context plus the single backend-owned runtime JSON verdict contract.
- **Backend Error Boundary**: Backend-availability errors are reserved for prompts that were actually eligible for backend inference. Prompts already classified locally as `Suspicious` or `Adversarial` — including recognized obfuscation such as chunking, vertical text, leetspeak, ROT13, or similar concealment — should terminate in the local firewall path and not fall through to `/v1/intercept`.

### 4. Operator Controls
- **Governance Status**:
  - **ACTIVE (Green)**: All core guardrails are enabled.
  - **REDUCED (Orange)**: One or more critical guardrails (PII Redaction, Logging, Blocked Keywords, or Forbidden Phrases) are disabled.
  - **DISABLED (Red)**: All guardrails are disabled.
- **Traffic Provenance**: Audit logs preserve a `source` marker such as `analyst_chat` or `bulk_ingest`, so test traffic can be compared against analyst-entered traffic without hiding records from the main dashboards.
- **Global System Pause (DEFCON 1)**: A governance kill switch that prevents further automated inference while active. New Analyst Chat prompts are logged and routed to the manual review queue (`PENDING_REVIEW`) instead of reaching the downstream model. Bulk Ingest honors the same live switch by stopping the active replay loop when pause is initiated; remaining batch prompts are not automatically queued or sent until an operator resumes and starts a new ingest run. The triggering ReDoS request is blocked immediately, and safeguard timeout/failure paths now also activate the pause fail-secure; later analyst prompts are queued until operators resume service.

### 5. Inference Engine (Pluggable LLM Architecture)
- **Backend-Only Inference Path**: Direct browser-side model access is disabled so provider credentials are not exposed in the client bundle.
- **Authenticated Gateway Pattern**: Protected execution routes now require the backend bearer credential before work begins. `/v1/intercept`, `/v1/translate`, `/v1/instruction-monitor/reviewed-adversarial`, `/v1/instruction-monitor/records/:identifier`, and `/v1/ctf/sam-spade/*` all reject unauthenticated requests; Sam Spade sessions are also scoped to the authenticated caller.
- **Vendor-Neutral Posture**: The control-plane is designed to stay decoupled from any single provider so the downstream inference engine can evolve across backend-managed OpenAI-compatible and future multi-model runtimes without exposing provider secrets to the browser.
- **Split Prompt Roles**: System configuration keeps the editable **Safeguard Effective Prompt** distinct from responder prompt configuration for review and drift management. Protected backend execution now uses backend-owned safeguard/responder instructions; browser callers cannot send replacement system prompts or downstream responder prompts with `/v1/intercept` or Sam Spade traffic.
- **Safeguard Effective Prompt Review**: System Configuration displays and hashes the recommended and current effective safeguard prompt text so intentional prompt updates can be reviewed as configuration artifacts. The protected backend gateway does not accept caller-supplied prompt-contract overrides.
- **Safeguard Category Guidance**: The recommended Safeguard Effective Prompt includes the baseline forbidden-category, forbidden-phrase, and gibberish guidance operators review in System Configuration.
- **Safeguard Runtime Verdict Contract**: Current safeguard enforcement uses one runtime JSON contract only: `{"verdict":"CLEAN|SUSPICIOUS|ADVERSARIAL","analystReasoning":"brief reason"}`. Legacy decision-shaped payloads such as `ALLOW_AND_FORWARD`, malformed JSON, or non-JSON safeguard responses fail secure to `SUSPICIOUS` / `QUEUED` and are never treated as allow-by-default. Upstream safeguard calls are bounded by `SAFEGUARDS_TIMEOUT_MS` (default 30s); timeout or provider failure returns structured `SHIELD_ERROR` telemetry with `SAFEGUARD_TIMEOUT`/`SAFEGUARD_ERROR` plus `FAIL_SECURE`.
- **Instruction Similarity Monitor**: The backend can compare clean candidates against a pgvector-backed instruction memory before the safeguard judge runs. It records exact SHA-256, loose stopword-stripped SHA-256, 2/3/4-gram SimHash fingerprints, whole-prompt embeddings, and overlapping chunk embeddings. Exact/loose-hash and SimHash matches preserve the stored policy posture: if the stored match was `ADVERSARIAL`, the candidate remains `ADVERSARIAL` and is blocked. Semantic pgvector matches are treated as `SUSPICIOUS` review evidence, so semantically similar but non-identical prompts are queued for analyst review rather than auto-blocked.
  - **Match Reason Criteria**: `Exact Sha256` means the normalized prompt hash equals a stored record; `Loose Sha256` means the stopword-stripped loose hash equals a stored record; `Simhash 2gram`, `Simhash 3gram`, and `Simhash 4gram` mean the corresponding 64-bit SimHash is within the configured Hamming threshold (`<= 12` by default); `Embedding` means whole-prompt cosine similarity meets the semantic threshold (`>= 0.78` by default); `Chunk Embedding` means an overlapping chunk meets the semantic threshold; `Attention Pool` means instruction-intent-weighted chunk similarity is high (`> 0.70` risk threshold); and `Sandwich Delta` means a chunk is much more similar than the whole prompt (`> 0.20` delta with a strong chunk match), suggesting embedded instruction content inside broader text.
  - **Analyst Lookup**: Similarity Monitor cards expose a `Lookup` action beside the stored hash. The UI calls the protected `/v1/instruction-monitor/records/:identifier` endpoint by `targetId` and opens an `Instruction Match` modal with source, stored verdict, strict/loose hashes, flags, labels, stored prompt preview, and stored chunks for comparison.
- **Effective Prompt Drift Fingerprint**: The System Configuration view exposes SHA-256 hashes for the recommended effective safeguard prompt and the active effective safeguard prompt, making prompt drift easier to detect during review and incident response.
- **Integrated Local Inspector Routing**: Admins can switch the Analyst Chat **Safeguard Provider** between backend-managed `LM_STUDIO` (`gpt-oss-safeguard-20b` at `http://192.168.0.183:1234/v1/chat/completions`) and hardcoded `OPENAI` defaults (`gpt-5.4-mini` at `https://api.openai.com/v1`, with no hardcoded key). Admins can also disable downstream **Responder Routing** while keeping the safeguard provider active. Clean prompts then follow `deterministic sanitizer -> Safeguard LLM judge -> LOCAL RESPONDER PASSTHROUGH`, which preserves safeguard evaluation without sending the cleared prompt to a responder model.
- **Fail-Closed Fallback**: If the backend, safeguard judge, or downstream responder is unavailable, the UI remains reviewable but clean prompts do not silently bypass the control plane. Safeguard failures stop forwarding before the responder, return structured `SHIELD_ERROR` state, mark the audit record `PENDING_REVIEW`, and activate Global System Pause. The browser also applies a 45s `/v1/intercept` abort as a second guard against hung backend calls. Responder failures are surfaced separately so operators can distinguish provider issues from local review behavior.
- **Overlay Hygiene**: Help/info icons use shared tooltip styling and are hidden behind active dialog overlays, while tooltip affordances inside the open dialog remain visible. This prevents background help icons from visually bleeding into modal review surfaces.

## 📦 Security Mitigations & Dependency Management

To ensure the integrity of the security operations platform, Counter-Spy.ai implements strict dependency governance:
- **React Server Components (RCE) Mitigation**: `react` and `react-dom` are pinned to `19.0.4` to mitigate CVE-2025-55182 and related DoS vulnerabilities.
- **Vite Dev Server Security**: Vite is upgraded to `^8.0.5` to mitigate arbitrary file read and path traversal vulnerabilities (CVE-2025-31125, CVE-2025-32395, CVE-2026-39363, GHSA-v2wj-q39q-566r, GHSA-4w7w-66w2-5vf9).
- **Stored XSS Prevention**: `react-markdown` is configured to explicitly disallow `rehype-raw`, preventing malicious HTML/JS injection from LLM outputs or compromised Firestore policy documents.
- **Frontend Secret Exposure Reduction**: Browser-side provider key injection has been removed. LLM credentials are expected to live in backend runtime configuration or a secret manager, not the React bundle.
- **Supply Chain Security**: Regular expression detection patterns have been internalized rather than sourced dynamically, and CLI tools like `shadcn` are strictly isolated to `devDependencies`.

## 📊 Key Features

- **Advanced Audit Trail**: Every interaction is logged with its entropy score, detection flags, and a unique Session ID. The audit table features **multi-column sorting**, optimized column spacing, and **Full Prompt Inspection**—allowing analysts to inspect the persisted sanitized prompt, recorded obfuscation telemetry, captured model response, Similarity Monitor evidence, token usage, and split latency details in a scrollable dialog rather than exposing raw sensitive payloads back to the browser. Modal backdrops use an intentionally dark scrim and strong blur so background controls and help icons do not distract from review content. Admins can also use **Purge Session** for local demo cleanup while preserving records still pending review.
- **Tightened Audit-Log Creates**: Direct client writes to `audit_logs` are limited by Firestore rules to a narrow expected field allowlist with owner/type/size checks. Backend-owned fields such as safeguard verdicts, gateway status, review state, and responder telemetry cannot be forged through client-side create requests.
- **Research-Ready Exports**: Audit log CSV exports now reserve fields for **MITRE ATLAS organizer labeling**, optional local archetypes, and analyst confidence/notes so longitudinal adversarial prompt analysis can evolve without another schema reset.
- **Anomaly Detection & Metrics Dashboard**: A dedicated dashboard for real-time threat velocity analysis. It compares current hourly threat rates against a 24-hour baseline to identify significant spikes in adversarial activity. Current Beta metrics include spike-ratio style threat velocity, alert severity rollups, a time-series chart for trend analysis, a `ReDoS Trips` resilience counter keyed off `ReDoS_ATTEMPT_DETECTED`, and a layered **Defense Funnel** summary that reports pre-inference block rate, Safeguard LLM intervention rate, and post-model escape rate. Formal Z-score incidenting and PagerDuty/Slack escalation are production deployment targets, not current repo functionality. The backend also emits structured `metric_increment` log events for `safeguard.schema` (`verdict`, `decision`, or `malformed`) and `safeguard.divergence` (`judgeVerdict`, `gatewayAction`, `divergent`) so orchestration-vs-judge drift can be converted into log-based metrics. The Metrics view now applies the same live entropy bands as the submit-time sanitizer instead of treating the threshold as a display-only control.
- **MITRE ATLAS Technique Heat Map**: The Metrics view uses the active 16-node MITRE ATLAS organizer taxonomy as its top-level structure so labeled prompt activity can be reviewed in the same corpus-driven layout used by the research dataset.
- **Analyst Review Workflow**: Administrators can review **all** interactions (including those marked as Clean) to catch false negatives. The workflow supports **Multi-Tier Review**, allowing analysts to re-edit and update the **Resultant Severity** at any time as new threat intelligence becomes available.
  - **False Negative Highlighting**: Logs pre-labeled as "Adversarial" (via the Bulk Ingestor) that are classified as "Clean" by the system are automatically highlighted with a red border and an **FN (False Negative)** badge, allowing for rapid identification of firewall bypasses.
  - *The platform automatically calculates both the False Positive Rate and False Negative Rate from reviewed analyst outcomes, ensuring the firewall's regex and entropy thresholds can be tuned against both overblocking and missed suspicious/adversarial prompts.*
- **Automated Golden Set Refinement**: Administrators can "Promote" specific audit logs to a **Golden Set** for future DPO (Direct Preference Optimization) fine-tuning. This captures the prompt, the AI's response, and a user-provided "Rejected" reason in a structured JSON format. Supports **one-click JSON export** of the entire set for training pipelines.
- **Dynamic Guardrails**: Administrators can toggle security features (PII Redaction, Entropy Filtering, Obfuscation Detection, Blocked Keywords, Forbidden Phrases, Similarity Monitor, Logging, etc.) on the fly. Disabling the Similarity Monitor sends `instructionSimilarityEnabled: false` to `/v1/intercept`, so the backend skips pgvector comparison instead of merely hiding UI evidence.
- **Configuration Library**: Admin-only workspace for System Configuration, the MCP / A2A Agent Safety reference, and Fine-Tuning Training Data. Counter-Spy.ai no longer serves as a general security policy lookup service or injects Knowledge Base policy excerpts into runtime prompts.
- **MCP / A2A Safety Detection**: The built-in MCP / A2A Agent Safety Policy contributes hard-block indicator phrases to the effective blocked-keyword set used by the live sanitization path and the Analyst Playground, helping detect instruction-override, approval-bypass, and exfiltration patterns common to tool-using agents.
- **MCP / A2A Guardrail Reference**: The recommended Guardrails Policy now explicitly tells the firewall baseline to review the MCP / A2A Agent Safety Policy when evaluating tool-use, routing, approval-bypass, or exfiltration patterns.
- **Analyst Mode**: A toggleable administrative view for managing system configurations and reviewing logs.
- **Analyst Playground**: A dedicated sandbox environment featuring the Syntactic Complexity Analyzer, allowing security teams to test and tune firewall thresholds against complex prompt injection attempts in real-time. Single-prompt Playground submissions can also be routed through the same live firewall path used by Analyst Chat, with audit provenance preserved as `playground`. It now includes a research-only **Feature Breakdown** above the Syntactic Score card so analysts can see instruction pressure, constraint density, syntax/wrapper pressure, obfuscation pressure, entropy pressure, and n-gram obfuscation signal without changing runtime enforcement. It also includes a manual **Normalize - Translate** pipeline so analysts can run browser-local spelling verification, either recover foreign-language prompts back into English or generate one foreign-language variant from English, and then hand the result into the obfuscation workflow.
- **Backend-Mediated Lara Translation**: The Playground translation stage now routes through the Counter-Spy.ai backend instead of calling translation providers directly from the browser. It is still intentionally manual and text-only: Lara Translate runs only when an analyst explicitly triggers the pipeline, supporting both auto-detect source -> English recovery and English -> analyst-selected foreign-language variant generation. Lara configuration is backend-managed only and fails closed when backend credentials are missing.
- **Sam Spade CTF Intake**: The Sam Spade home tab now includes a live question field backed by a dedicated backend session/message/solve API under a `ctf_chat` source. This keeps the noir CTF surface aligned with the same governed sanitization, review, and audit path as the rest of Counter-Spy.ai without treating Analyst Chat as the transport layer.
- **Dedicated Sam Spade API Path**: The Sam Spade surface now uses its own protected backend session/message/solve API (`/v1/ctf/sam-spade/...`) with separate frontend session state, owner-scoped local backend persistence, and authenticated caller checks on fetch/message/solve. Each Sam Spade submission is governed by the same local sanitizer and safeguard judge path under the `ctf_chat` source. Clean gameplay turns are forwarded to the configured downstream responder with backend-managed Sam Spade persona and scenario prompts when responder routing is enabled; otherwise they use local responder passthrough after safeguard approval. Blocked turns, including already-redacted sensitive placeholders such as `[REDACTED_CREDIT_CARD]`, remain out of the noir transcript, never reach the Sam Spade responder, and are masked as `Bad content.` on the CTF gameplay surface while the audit artifact keeps the sanitized review detail.
- **CTF Audit Filter**: Audit Logs now include a quick `CTF Chat` source filter so Sam Spade traffic can be isolated immediately without losing the broader audit trail view.
- **CTF Metrics Filter**: The Metrics view now includes a dedicated `CTF Chat` source filter so Sam Spade traffic can be isolated in charts and operational summaries without leaving the main telemetry surface.
- **Layered Defense Metrics**: The Metrics view now calculates three explicit funnel rates for governed traffic: **Pre-Inference Block Rate** (% blocked before the Safeguard LLM), **Model Intervention Rate** (% caught by the Safeguard LLM after reaching it), and **Post-Model Escape Rate** (% of likely malicious prompts that bypass both layers and still land clean/informational). Backend safeguard outcomes are carried as structured audit/metric fields (`backendGatewayStatus`, `backendSafeguardVerdict`, `backendSafeguardReasoning`, `backendReachedSafeguard`) plus split latency fields (`localPrecheckLatencyMs`, `backendSafeguardLatencyMs`, `backendGatewayLatencyMs`, `instructionEmbeddingDurationMs`, `responderLatencyMs`) so Bulk Ingest and Analyst Chat interceptions are attributed to the correct layer and runtime timing is not inferred from responder passthrough. The Metrics latency profile also summarizes instruction-monitor embedding average/P95/sample count when pgvector/Ollama timings are present. When present, bulk-ingest `expectedVerdict` labels are used to strengthen escape-rate calculations.
- **Detection Signal Rollups**: The Metrics **Detection Signals** card reports prompt counts by detection family rather than raw per-tag totals. It now uses shared aggregation logic for local-review and Firestore-backed metrics, counts `FORBIDDEN_TOPIC` and future `FORBIDDEN_PHRASE` records under **Forbidden Phrase Hits**, and treats **Obfuscation Hits** as any persisted obfuscation technique shown in prompt details rather than only the narrow `OBFUSCATED_INSTRUCTION` flag.
- **Local Docker Demo Stack**: A minimal `docker-compose.demo.yml` now brings up the backend, frontend, and a pgvector PostgreSQL container for an end-to-end local pass. The instruction-monitor database uses container tmpfs storage so a forced recreate starts from a clean database, while Sam Spade session state persists in a Docker-backed SQLite volume.
- **Obfuscation Lab**: The Prompt Playground includes an analyst-facing obfuscation workbench for generating test variants across encoding, cipher, unicode, structural-injection, and language-framing techniques. Analysts can generate a single variant, fan out an entire category, use **Analyze All Variants** to record a mini evaluation run into the research log, or **Submit All Variants** to create full firewall and audit-log coverage from one source prompt with adjustable replay delay and jitter. The intended augmentation order is now explicit in the UI: normalize, optionally translate, then add evasions.
- **Feature Pressure Metrics**: Each governed prompt submission records a pre-inference feature vector into the audit event alongside entropy, syntactic score, decode telemetry, and suspicious chunks. The Metrics view summarizes these live audit fields in a separate **Feature Pressure** card with the average 0-100 Feature Pressure score plus average instruction, constraint-density, syntax/wrapper, obfuscation, entropy, and n-gram pressures. The Analyst Playground can still record explicit browser-local snapshots for export, including prompt hashes, feature-vector breakdown, feature pressure, top pressure driver, trigram/Caesar n-gram obfuscation telemetry, optional normalization/translation metadata, and optional MITRE ATLAS organizer annotations. The research log exports in both **JSON** and **CSV** formats.
- **Cheap Upstream Triage**: The sanitization layer now treats obvious encodings and evasions as first-pass security signals, applies lightweight spelling recovery when it helps expose blocked policy language, performs heuristic foreign-language recovery for policy analysis, and elevates non-ASCII/symbol-heavy concealment patterns before traffic earns upstream tokens. It also includes deterministic detectors for forced response-prefix injection (`FORCED_PREFIX_INJECTION`), anti-sanitization clauses inside fictional framing (`ANTI_SANITIZATION_CLAUSE`), persona-plus-unrestricted-capability jailbreaks (`PERSONA_INJECTION`), and signal-only all-caps hyphenated persona handles (`ALLCAPS_PERSONA`). Foreign-language and spelling-recovery hits remain visible in Metrics and Audit Log detail views. Recognized decode/structural obfuscation drives an Adversarial outcome by itself; Pig Latin is signal-only review because its inverse transform is ambiguous and lossy.
- **Sensitive Data Alerting**: PII, credit-card, secret, and redacted-secret disclosures now surface as their own analyst-facing alert category instead of reading like generic suspicious chatter, which makes data-exposure review easier to distinguish from jailbreak-style prompting.
- **Policy Violation Labeling**: Blocked keywords, forbidden phrases, and regex-rule matches now emit a shared `POLICY_VIOLATION` signal so operator-facing responses, Audit Logs, and CSV exports distinguish explicit policy hits from generic suspicious traffic.
- **Obfuscation Metrics Visibility**: The Metrics tab breaks out obfuscation-oriented detections such as URL encoding, HTML entities, binary encoding, ASCII decimal, A1Z26, Pig Latin, leetspeak, ROT13, reverse text, NATO phonetic, Morse code, recursive decode chains, and structural wrappers, and now includes a stacked 24-hour obfuscation trend so key techniques can be compared in one view. Audit records also persist a compact `obfuscationSummary` field (`hasObfuscation`, `techniques`, `decodeTelemetry`) to simplify reporting without re-deriving everything from raw flag arrays. Audit Logs now support both saved family presets and specific-technique filtering, and prompt details surface the recorded obfuscation signal badges and stored decode telemetry for each entry.
- **Downstream Responder Tab**: Admin view exposes a dedicated responder runtime surface with provider, backend health, model/base URL, context-window configuration, responder key source, last forwarded prompt hash, split latency telemetry, token usage, prompt profile, and output-sanitization signals. Operators can keep Analyst Chat unchanged while choosing an OpenAI-compatible or Gemini downstream responder for clean traffic through backend env/config, or disable responder routing for safeguard-only local passthrough review. Browser-entered responder keys and system prompts are not sent to protected backend execution routes. When responder routing is disabled, OpenAI-compatible Safeguard LLM usage metadata from LM Studio or OpenAI-style responses is preserved as the audit token source so local passthrough records can still show prompt, completion, total, and context-utilization telemetry. Sam Spade CTF responder calls are identified with the `sam_spade_ctf` prompt profile without exposing the private scenario text in telemetry.
- **Responder Outcome Classification**: Non-standard downstream responses such as `BLOCK`, `FAIL_SECURE`, `QUEUE_FOR_REVIEW`, and explicit policy-violation strings are normalized back into Counter-Spy.ai severity labels so Audit Logs and Metrics reflect the final safeguarded outcome instead of assuming clean traffic.
- **Modular Sanitization Pipeline**: The TypeScript sanitization layer is now split into focused normalization, language-recovery, and obfuscation helper modules so the hot path stays easier to profile, test, and extend as the frontend firewall and future API boundary continue to grow.
- **Bulk Ingest Simulator**: A high-velocity ingestion utility for processing `.txt` files of prompts. Features operator-controlled delay, retry, and backoff settings with light jitter to simulate realistic traffic patterns while respecting API rate limits. It treats intentional `403` firewall/safeguard intercepts as governed results, stops on provider `429` rate limits, and retries transient `502`/`503`/`521` responder or gateway failures before stopping the run. Integrated with the **Screen Wake Lock API** to maintain session persistence during long-running batch operations.
  - **Flexible Prompt Parsing**: The simulator accepts one-line prompts, explicit `===PROMPT===` / `===END===` blocks, blank-line-separated multi-line prompts, and common numbered-entry layouts. The UI reports the parsed prompt count and parser mode at ingest start so operators can verify file shape before a long run.
  - **Multi-line Prompt Blocks**: In addition to one-line prompts, the simulator accepts `===PROMPT===` / `===END===` blocks so long or multi-line test payloads can be uploaded without manual escaping or JSON formatting.
  - **Selected File Visibility**: After upload, the UI displays the selected `.txt` filename beneath the app-rendered file chooser so operators can confirm which file was parsed even after the hidden native file input resets for re-selection.
  - **DPO Pre-labeling**: Supports optional `Batch ID` and `Expected Verdict` assignment during ingest, facilitating the collection of high-quality training data for model fine-tuning.

## 📋 Audit Log Schema

Every interaction is captured in Firestore with the following schema:

| Field | Type | Description |
| :--- | :--- | :--- |
| `userId` | `string` | Unique Firebase UID of the user. |
| `sessionId` | `string` | Unique identifier for the chat session. |
| `timestamp` | `timestamp` | Server-side creation time. |
| `promptHash` | `string` | SHA-256 prompt hash used for deduplication and longitudinal analysis. |
| `sanitizedPrompt` | `string` | The prompt after local PII/secret redaction plus any policy-triggered payload redaction needed for safe audit display. |
| `detectionFlags` | `string[]` | Types of security triggers detected (e.g., `EMAIL`, `AWS_KEY`). |
| `entropy` | `number` | Shannon entropy score of the input. |
| `featureVector` | `object` | Optional pre-inference Feature Pressure breakdown with normalized instruction, constraint-density, syntax/wrapper, obfuscation, entropy, and n-gram pressures. |
| `featurePressure` | `number` | Optional operator-facing 0-100 Feature Pressure score. During migration, records may also carry the legacy-compatible `researchSignal` field with the same value. |
| `topPressureDriver` | `string` | Optional top weighted Feature Pressure driver. During migration, records may also carry the legacy-compatible `topResearchDriver` field with the same value. |
| `detectionLevel` | `integer` | 0: Clean, 1: Info, 2: Suspicious, 3: Adversarial. |
| `escalationRecommended` | `boolean` | True if high-risk patterns were detected. |
| `reviewed` | `boolean` | Whether an analyst has reviewed the log. |
| `status` | `string` | The current status of the log (e.g., `PENDING_REVIEW`, `REVIEWED`). |
| `resultantSeverity` | `string` | Final severity assigned by an analyst (Clean to Adversarial). |
| `response` | `string` | The AI's generated response to the prompt. |
| `backendGatewayStatus` | `string` | Optional `/v1/intercept` gateway status: `CLEAN`, `INTERCEPTED`, `QUEUED`, or `SHIELD_ERROR`. Used for layered metrics attribution. |
| `backendSafeguardVerdict` | `string` | Optional safeguard judge verdict: `CLEAN`, `SUSPICIOUS`, or `ADVERSARIAL`. |
| `backendSafeguardReasoning` | `string` | Optional safeguard judge reasoning returned by the backend gateway. |
| `backendReachedSafeguard` | `boolean` | True when the prompt reached the backend safeguard judge, allowing Metrics to distinguish local pre-inference blocks from model/safeguard interventions. |
| `localPrecheckLatencyMs` | `number` | Optional deterministic backend precheck latency in milliseconds. Present only for prompts that reached `/v1/intercept`. |
| `backendSafeguardLatencyMs` | `number` | Optional pure Safeguard LLM latency in milliseconds, excluding local sanitizer and responder time. |
| `backendGatewayLatencyMs` | `number` | Optional total backend gateway latency for the `/v1/intercept` request. |
| `instructionEmbeddingDurationMs` | `number` | Optional duration of the backend instruction-monitor embedding request in milliseconds. Present for `/v1/intercept` and reviewed-adversarial ingest paths when backend embeddings are generated. |
| `SAFEGUARD_TIMEOUT` / `SAFEGUARD_ERROR` / `FAIL_SECURE` | `detectionFlags` values | Optional fail-secure flags emitted when the safeguard judge times out or fails before returning a usable verdict. These records use `backendGatewayStatus: SHIELD_ERROR`, `backendSafeguardVerdict: ADVERSARIAL`, and `status: PENDING_REVIEW`. |
| `INSTRUCTION_SIMILARITY_MATCH` / `INSTRUCTION_SIMILARITY_MEDIUM` / `INSTRUCTION_SIMILARITY_HIGH` | `detectionFlags` values | Optional instruction-memory flags emitted when exact hash, loose hash, SimHash, whole-embedding, or chunk-embedding comparison finds a match before safeguard forwarding. Hash/fingerprint matches against stored adversarial records remain adversarial blocks; semantic-only matches are suspicious review events. |
| `responderLatencyMs` | `number` | Optional downstream responder latency in milliseconds. Local passthrough records this as `0`. |
| `promptTokens` | `number` | Optional provider-reported prompt token count. For responder-routed traffic this comes from the downstream responder; for safeguard-only local passthrough it can come from the OpenAI-compatible safeguard judge usage payload. |
| `completionTokens` | `number` | Optional provider-reported completion token count from the responder or, when responder routing is disabled, the safeguard judge. |
| `totalTokens` | `number` | Optional total token count returned by the responder provider or safeguard judge. |
| `contextWindowLimit` | `number` | Optional browser-local max context window used for pre-submit gating and post-run utilization display. |
| `contextWindowUtilization` | `number` | Optional estimated percentage of the configured context window consumed by the responder call. |
| `promoted` | `boolean` | Whether the log has been added to the Golden Set. |
| `source` | `string` | Provenance of the record, such as `analyst_chat` or `bulk_ingest`. |
| `batchId` | `string` | Unique identifier for a specific bulk ingest run. |
| `expectedVerdict` | `string` | The pre-labeled expected outcome (e.g., `Adversarial`) for DPO analysis. |

## 🏗️ Deployment Architecture

- **Cloud Infrastructure**: Transitional local/Firebase alpha today, AWS target architecture next (ECS Fargate, API Gateway, Bedrock).
- **Containerization**: Docker (Multi-stage builds, non-root execution).
- **Inference Gateway**: Backend `/v1/intercept` gateway stub today, AWS-authenticated API Gateway/ECS path planned.

## 🛠️ Tech Stack

- **Frontend**: React 19, Vite, Tailwind CSS 4, Shadcn UI.
- **Charting**: Recharts (Composable React charting library).
- **UI/UX**: Modernized dark-themed interface with Geist typography, fluid animations, and an **auto-resizing chat input** with smart scrolling for lengthy prompts.
- **Backend/Database**: Firebase Authentication + Firestore for app records, an Express TypeScript backend gateway for secure intercept flow, and pgvector PostgreSQL for backend instruction-similarity memory in the local/demo path.
- **Inference Engine**: Browser-side inference disabled. The current product posture is firewall-and-forward, with clean prompts intended to route through the backend gateway to managed providers.
- **Animations**: Motion (Framer Motion).
- **Responsive Layout**: Optimized flexbox architecture ensuring sidebars and chat windows maintain visibility and scrollability during high-volume interactions.

## 🚀 Getting Started

### Environment Variables

> [!WARNING]
> Never commit `.env` to version control. For production deployments, 
> use AWS Secrets Manager as documented in the SBOM.

Create a `.env` file only for app-local values such as:
```env
VITE_API_BASE_URL=http://127.0.0.1:18080
```

### Installation
1. Clone the repository.
2. Install dependencies: `npm install`
3. Start the development server: `npm run dev`

For local review without Google authentication, use **Continue in Local Review Mode** on `localhost`. Direct browser-side inference is disabled so provider secrets do not ship in the client bundle. To route clean prompts through the local backend stub, start `APP_PORT=18080 npm run backend:dev` and run the frontend with `VITE_API_BASE_URL=http://127.0.0.1:18080 npm run dev`.

For the Docker demo stack on `http://localhost:3000`, the frontend uses same-origin proxying to reach the backend. Analyst Chat clean traffic still uses `/v1/intercept` even when `VITE_API_BASE_URL` is unset. That gateway requires the shared backend bearer token, runs local prechecks first, then calls the separately configured OpenAI-compatible safeguard judge, and only then forwards `CLEAN` prompts to the downstream responder. Browser clients cannot choose safeguard/responder provider endpoints, backend model base URLs, or backend-owned system prompts for protected execution paths; those values come from backend environment configuration such as `SAFEGUARDS_*`, `RESPONDER_*`, and `LLM_*`. The Analyst Runtime Settings modal intentionally allows a browser-memory-only Safeguard API Key for local LM Studio testing; when present, `/v1/intercept` forwards that key to the backend safeguard call, and leaving it blank falls back to `SAFEGUARDS_API_KEY`. If LM Studio requires API-token authentication and neither source is set, the backend returns `SHIELD_ERROR` / `SAFEGUARD_ERROR` / `FAIL_SECURE`, queues the audit item, activates Global System Pause, and does not forward to the responder. For OpenAI-compatible responders, set the backend provider to OpenAI-compatible and use an API root such as `https://api.openai.com/v1`; the backend will translate that into a `POST /v1/responses` call when applicable. For Gemini, set `RESPONDER_PROVIDER=gemini`, use a Gemini model ID such as `gemini-2.5-flash`, and leave `RESPONDER_API_BASE_URL` blank to use the Gemini API default. If you also set **Max Context Window**, the browser will estimate the forwarded request footprint and block over-limit submissions before they are sent.

For stable local demo secrets, the Docker stack now reads provider credentials and pgvector database secrets from a gitignored file at `.env.demo.local`. Set both `POSTGRES_PASSWORD` and `INSTRUCTION_MONITOR_DATABASE_URL` there, using the same password value, and start the stack with `docker compose --env-file .env.demo.local -f docker-compose.demo.yml up --build`. This keeps backend-only credentials stable across container recreates and laptop restarts without committing secrets to the repo.

The Docker demo also starts `counter-spy-postgres` on `127.0.0.1:15432` for the instruction monitor. The backend initializes the pgvector schema lazily and now defaults the demo embedding sidecar to Ollama at `http://192.168.0.183:11434/v1` with `nomic-embed-text` and `768`-dimension vectors. Any dedicated embedding provider must be local/private-network and OpenAI-compatible; public hosted endpoints such as OpenAI or Google are blocked for instruction-monitor embeddings so malicious prompt material is not sent to third-party embedding APIs. API callers may still supply `metadata.instructionEmbedding` or `metadata.instructionChunks`, but normal frontend submissions no longer require the browser to calculate embeddings. The demo Postgres data directory is tmpfs-backed, initialized with SCRAM authentication and data checksums, so recreating the container gives you a fresh instruction database by design.

For local translation testing, use Lara Translate through the local Counter-Spy.ai backend:

```bash
APP_PORT=18080 npm run backend:dev
VITE_API_BASE_URL=http://127.0.0.1:18080 npm run dev
```

Then set the backend env vars:

- `INTERCEPT_BEARER_TOKEN`
- `VITE_BACKEND_BEARER_TOKEN` with the same value for local browser clients
- `LARA_ACCESS_KEY_ID`
- `LARA_ACCESS_KEY_SECRET`
- optional `LARA_API_BASE_URL` if you are not using the default Lara host

Then open the Playground and use **Use Recommended Settings** in the Normalize - Translate panel. The current language pipeline is:

- Spell Verification: browser-local heuristic normalization for common typo recovery.
- Translation provider: `lara`
- Mode 1: auto-detect source -> `English`
- Mode 2: `English` -> analyst-selected foreign target language
- Credentials: backend environment only. Browser callers cannot route translation to caller-chosen Lara infrastructure.

Translation still runs only when you explicitly click **Run Normalize -> Translate** in the Playground. It is not executed on every prompt edit or submission.

For the Docker demo stack, place Lara credentials in `.env.demo.local`:

```env
LARA_ACCESS_KEY_ID=your_lara_access_key_id
LARA_ACCESS_KEY_SECRET=your_lara_access_key_secret
LARA_API_BASE_URL=https://api.laratranslate.com
```

That file is ignored by git and is the preferred stable local-demo path for Lara configuration. If Lara credentials are missing from the backend, `/v1/translate` fails closed instead of falling back to caller-supplied infrastructure.

### Customization
The branding shield is bundled at `public/brand/counter-spy-shield.png`, with the original source image preserved at `public/brand/counter-spy-shield-original.png`. To change the app chrome logo, replace the display PNG or update the `APP_LOGO_URL` constant in `src/App.tsx`.

## 🔒 Data Disclosure Detection

To detect and prevent unauthorized data disclosure, a unique **Canary Token** is embedded within the system's documentation. This token is strictly monitored and must not be disclosed within training data, audit logs, prompts, or AI responses.

Current documentation canary: `COUNTERSPY_CANARY_TOKEN_9d17d3b2-5d66-4a51-9adf-5d5bb0c4b799`.

The sanitization pipeline is configured to automatically redact this token if it appears in any system interaction.

Alongside the canary token, the System Configuration view computes a SHA-256 fingerprint for both the recommended effective safeguard prompt and the currently active effective safeguard prompt. This gives analysts and incident responders a quick way to detect prompt drift or unauthorized configuration changes without diffing long prompt text by hand.

## 📜 Governance Policy
This application is designed for security professionals. Bypass attempts are detected, blocked, and written to the governed audit trail for analyst review. Attempting to bypass the sanitization layer is a violation of the system's governance policy.

## 📎 Third-Party Attribution

- **Arcanum Prompt Obfuscator / Arcanum PI Taxonomy**
  - Attribution: Jason Haddix / Arcanum Information Security
  - Source basis noted in the original generated file header: "Arcanum Prompt Obfuscator" (`CC BY 4.0 — attribution required`)
  - Counter-Spy.ai modifications: refactored the generated obfuscation logic for browser-safe execution, reorganized technique metadata for Prompt Playground use, and selectively promoted high-signal techniques into the detection pipeline.

- **Regex Detection Pattern Lineage**
  - Attribution: regex prompt-injection pattern work originally sourced from `dimitritholen`
  - Counter-Spy.ai modifications: internalized the patterns into the local firewall, reformatted them for UI management, combined them with additional governance metadata, and extended their usage into tuning and review workflows.
