### MITRE ATLAS Mapping: Counter‑Spy.ai Defensive Capabilities

This mapping demonstrates how the platform's features align with mitigating specific adversarial tactics and techniques defined in the MITRE ATLAS matrix.

#### 1. Initial Access & Execution (Mitigating the Payload)
These features are designed to stop an attacker from successfully delivering a malicious payload to the OpenAI-compatible safeguard judge or the downstream responder model.

| Counter‑Spy Feature | MITRE ATLAS Threat Mitigated | Tactic / Technique ID |
| :--- | :--- | :--- |
| **Local Sanitization Pipeline (Regex & Normalization)** | Detects and blocks **Prompt Injection** attempts, including obfuscated (leetspeak) or break‑all formatting, before execution. | **AML.T0051** |
| **Syntactic Complexity Analyzer** | Detects instruction stacking, URL‑encoded strings, and heavy verbosity used to bypass semantic filters. | **AML.T0043** |
| **Curated Default Blocklist** | Intercepts known roleplay‑based injection templates and jailbreak corpora. | **AML.T0042** |
| **Anti‑ReDoS Circuit Breaker** | Prevents CPU lockup from catastrophic backtracking payloads via the chat interface. | **AML.T0029** |
| **Global System Pause (DEFCON 1)** | A "kill switch" to instantly halt inference during a coordinated, automated attack, routing traffic to manual review. | **AML.TA0008** |
| **OpenAI-Compatible Safeguard Judge** | Requires a structured firewall verdict before any clean prompt can be forwarded to the downstream responder. | **AML.T0053** |

#### 2. Defense Evasion (Mitigating Obfuscation)
Attackers frequently try to hide their payloads from security filters. Counter‑Spy.ai has specific countermeasures for these evasion tactics.

| Counter‑Spy Feature | MITRE ATLAS Threat Mitigated | Tactic / Technique ID |
| :--- | :--- | :--- |
| **Entropy Analysis (Sliding Window)** | Detects localized high‑entropy payloads (Base64, Hex) hidden within normal text, defeating token‑dilution attacks. | **AML.T0043** (Obfuscation) |
| **Normalization (Leetspeak Conversion)** | Prevents keyword bypasses by flattening obfuscated text back to standard English before regex evaluation. | **AML.T0043** (Evade Defenses) |

#### 3. Exfiltration & Impact (Mitigating Data Loss)
If an attacker successfully manipulates the model, these features prevent the model from leaking sensitive data back to the user.

| Counter‑Spy Feature | MITRE ATLAS Threat Mitigated | Tactic / Technique ID |
| :--- | :--- | :--- |
| **PII & Secret Redaction (Input)** | Strips API keys, passwords, and PII from the user's prompt before it reaches the LLM, preventing accidental exposure in the model's context window. | **AML.T0024** |
| **Output Sanitization Layer (PII & Keyword Redaction)** | Scans the LLM's response and masks sensitive data or blocked keywords (e.g., `[REDACTED_KEYWORD]`), preventing the model from returning stolen data. | **AML.T0024** |
| **Forbidden Phrases and Policy Category Enforcement** | Enforces operator-managed forbidden phrases locally and uses the visible Firewall Prompt's category/gibberish guidance during safeguard judging, preventing unauthorized content from reaching or being produced by the responder. | **AML.T0053** |
| **System Prompt Persona Constraints** | A strict system prompt forbids the model from revealing its internal configurations or system instructions. | **AML.T0054** |

#### 4. Reconnaissance & Discovery (Mitigating System Probing)
How the system limits an attacker's ability to learn about the defenses.

| Counter‑Spy Feature | MITRE ATLAS Threat Mitigated | Tactic / Technique ID |
| :--- | :--- | :--- |
| **Sanitized Pass‑through Guarantee** | Because only redacted prompts reach the model, an attacker cannot probe the LLM to test its reaction to raw secrets or specific PII. | **AML.T0012** (Discover ML Model Ontology) |
| **Syntactic Complexity Analyzer (Probing Detection)** | Actively detects and flags inputs that look like model reverse‑engineering or boundary probing. | **AML.T0016** (Active Scanning) |

#### 5. Operations & Incident Response (The "Counter‑Spy" Element)
While ATLAS primarily maps *threats*, Counter‑Spy includes features specifically designed for SOC analysts to investigate and respond to those threats.

| Counter‑Spy Feature | SOC / Incident Response Function |
| :--- | :--- |
| **Advanced Audit Trail (with Session IDs)** | Allows analysts to track an attacker's session history and understand their methodology over time. |
| **Anomaly Detection & Metrics Dashboard** | Uses real‑time Z‑Score calculations to detect velocity spikes indicative of automated attacks. |
| **Human‑in‑the‑Loop (HITL) Mode** | Automatically intercepts borderline traffic (Suspicious Entropy) for manual review before execution. |
| **Automated Golden Set Refinement (DPO)** | Allows analysts to export successfully blocked adversarial interactions to fine‑tune future security models. |

#### 6. Additional Defensive Controls (Per Technical Specifications)
Supplementary controls that further harden the platform.

| Counter‑Spy Feature | MITRE ATLAS Threat Mitigated | Tactic / Technique ID |
| :--- | :--- | :--- |
| **Shared Bearer Route Protection (Current Beta)** | Protected execution routes require the configured backend bearer credential. Production JWT/OIDC validation for `sub`, `aud`, and `exp` is a planned control, not current backend functionality. | **AML.TA0003**; **AML.T0012** |
| **Fail‑Closed Gateway Enforcement** | Prevents fail-open behavior by refusing to forward eligible clean prompts when the safeguard judge or downstream responder cannot complete. Governance sync failures retain the current in-memory/default state rather than silently bypassing the firewall. | **AML.TA0004**; **AML.T0051** |
| **Telemetry Anomaly Escalation (Planned Production Control)** | Current Beta metrics expose threat-velocity and alert-severity signals for manual escalation. Automated PagerDuty/Slack delivery is a production integration target, not current repo functionality. | **AML.TA0008**; **AML.T0029** |

---

## Appendix — Key Operational Thresholds and Controls
- **Entropy bands:** `Allowed <= 3.6`, `Suspicious > 3.6 and <= configured Entropy Threshold`, `Adversarial > configured Entropy Threshold`
- **Sanitization order:** `Normalize (NFKC)` → `Strip non-printables` → `Local sanitizer/entropy/regex checks` → `OpenAI-compatible safeguard judge` → `Downstream responder` → `Output filter`
- **Audit logging:** Current Beta audit records persist sanitized prompts, detection metadata, review state, and backend telemetry with Firestore RBAC. Dual raw/normalized records and immutable admin audit trails are planned production controls, not current repo functionality.
