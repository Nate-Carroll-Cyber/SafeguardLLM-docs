### MITRE ATLAS Mapping: Safeguard LLM Defensive Capabilities

This document maps current Safeguard LLM controls to current MITRE ATLAS tactics and techniques. IDs are paired with their intended official concepts rather than inferred from older numeric offsets.

#### 1. Initial Access and Execution

| Safeguard LLM Feature | Defensive Relationship | ATLAS Mapping |
| :--- | :--- | :--- |
| **Local Sanitization Pipeline** | Detects direct/indirect prompt injection and normalizes concealed content before model execution. | `T0051` — LLM Prompt Injection; `T0068` — LLM Prompt Obfuscation |
| **Syntactic Complexity Analyzer** | Detects instruction stacking, wrappers, encoded strings, and probing structures. | `T0068` — LLM Prompt Obfuscation |
| **Curated Default Blocklist** | Intercepts known roleplay and anti-refusal jailbreak patterns. | `T0054` — LLM Jailbreak |
| **Anti-ReDoS Circuit Breaker** | Fails secure when sanitizer latency exceeds the governed boundary. | `T0029` — Denial of AI Service |
| **Global System Pause** | Stops automated inference and routes new work to review during an incident. | `TA0011` — Impact; `T0029` — Denial of AI Service |
| **OpenAI-Compatible Safeguard Judge** | Requires a structured policy verdict before responder forwarding. | `T0051` — LLM Prompt Injection |

#### 2. Defense Evasion and Obfuscation

| Safeguard LLM Feature | Defensive Relationship | ATLAS Mapping |
| :--- | :--- | :--- |
| **Sliding-Window Entropy Analysis** | Detects localized encoded or high-randomness payloads hidden in otherwise ordinary text. | `T0015` — Evade AI Model; `T0068` — LLM Prompt Obfuscation |
| **Normalization and Decode Inspection** | Recovers or flags leetspeak, Base64, hex, binary, URL encoding, vertical text, and other concealment forms. | `T0068` — LLM Prompt Obfuscation |
| **Instruction Similarity Monitor** | Finds reused adversarial instructions through hashes, SimHash, and pgvector similarity. | `T0051` — LLM Prompt Injection; `T0054` — LLM Jailbreak |

#### 3. Exfiltration and Impact

| Safeguard LLM Feature | Defensive Relationship | ATLAS Mapping |
| :--- | :--- | :--- |
| **PII and Secret Redaction** | Removes sensitive values before provider inference and sanitizes responder output. | `TA0010` — Exfiltration; `T0024` — Exfiltration via AI Inference API |
| **Forbidden-Phrase and Category Enforcement** | Applies deterministic phrase policy plus the reviewable Safeguard Effective Prompt. | `T0048` — External Harms; `T0051` — LLM Prompt Injection |
| **System-Prompt Confidentiality Controls** | Detects attempts to recover judge or responder instructions and prevents caller-supplied responder prompts. | `T0056` — Extract LLM System Prompt |
| **Fail-Secure Provider Boundary** | Prevents safeguard or responder outages from becoming a bypass path. | `TA0011` — Impact; `T0029` — Denial of AI Service |

#### 4. Reconnaissance and Discovery

| Safeguard LLM Feature | Defensive Relationship | ATLAS Mapping |
| :--- | :--- | :--- |
| **Sanitized Pass-Through Guarantee** | Limits probing with raw PII, secrets, or encoded payloads. | `TA0002` — Reconnaissance; `TA0010` — Exfiltration |
| **Ontology and Boundary-Probing Detection** | Flags requests intended to infer model capabilities, prompt structure, or policy boundaries. | `T0013` — Discover AI Model Ontology |
| **Repeated-Probe Telemetry** | Preserves session and audit evidence for model/API scanning patterns. | `T0006` — Active Scanning |

#### 5. Operations and Incident Response

| Safeguard LLM Feature | SOC / Incident Response Function |
| :--- | :--- |
| **Advanced Audit Trail** | Tracks session lineage, sanitized evidence, review status, safeguard attribution, and latency. |
| **Metrics Dashboard** | Reports threat velocity, layered defense rates, detection families, and review workload. |
| **Human-in-the-Loop Mode** | Queues suspicious traffic before responder execution. |
| **Reviewed-Adversarial Corpus** | Stores only reviewed adversarial instructions for controlled similarity comparison and seed export. |

#### 6. Additional Defensive Controls

| Safeguard LLM Feature | Defensive Relationship | ATLAS Mapping |
| :--- | :--- | :--- |
| **Shared Bearer Route Protection (Current Beta)** | Requires `INTERCEPT_BEARER_TOKEN` before protected backend work begins; production JWT/OIDC remains planned. | `TA0004` — Initial Access; `T0012` — Valid Accounts |
| **Strict Request Schemas** | Rejects browser-supplied provider endpoints, model IDs, responder prompts, and unknown protected metadata. | `T0081` — Modify AI Agent Configuration |
| **Fail-Closed Gateway Enforcement** | Refuses responder forwarding when safeguard execution does not produce a valid clean result. | `TA0005` — Execution; `T0051` — LLM Prompt Injection |
| **Policy Enforcement** | Applies deterministic forbidden phrases and structured safeguard decisions before response generation. | `T0048` — External Harms |
| **Safeguard Judge** | Evaluates normalized candidates for prompt-injection and policy evidence. | `T0051` — LLM Prompt Injection |

---

## Appendix — Key Operational Thresholds and Controls

- **Entropy bands:** `Allowed <= 3.8`, `Suspicious > 3.8 and <= configured Entropy Threshold`, `Adversarial > configured Entropy Threshold`
- **Syntactic bands:** scores at or above the configured threshold (default `65`, tunable `40–90`) contribute to `Suspicious`; scores `>= 90` are `Adversarial`
- **Sanitization order:** `Normalize` → `Decode/reflow` → `Redact and evaluate policy` → `Instruction similarity` → `Safeguard judge` → `Responder` → `Output filter`
- **Audit boundary:** persisted records use sanitized prompts and structured evidence; raw secrets are not intentionally restored for display.
