### MITRE ATLAS Mapping: Safeguard LLM Defensive Capabilities

This mapping demonstrates how the platform's features align with mitigating specific adversarial tactics and techniques defined in the MITRE ATLAS matrix.

#### 1. Initial Access & Execution (Mitigating the Payload)
These features are designed to stop an attacker from successfully delivering a malicious payload to the OpenAI-compatible safeguard judge or the downstream responder model.

| Safeguard LLM Feature | MITRE ATLAS Threat Mitigated | Tactic / Technique ID |
| :--- | :--- | :--- |
| **Local Sanitization Pipeline (Regex & Normalization)** | Detects and blocks **Prompt Injection** attempts, including obfuscated (leetspeak) or break‑all formatting, before execution. | **T0051** |
| **Syntactic Complexity Analyzer** | Detects instruction stacking, URL‑encoded strings, and heavy verbosity used to bypass semantic filters. | **T0043** |
| **Curated Default Blocklist** | Intercepts known roleplay‑based injection templates and jailbreak corpora. | **T0054** |
| **Anti‑ReDoS Circuit Breaker** | Prevents CPU lockup from catastrophic backtracking payloads via the chat interface. | **T0029** |
| **Global System Pause (DEFCON 1)** | A "kill switch" to instantly halt inference during a coordinated, automated attack, routing traffic to manual review. | **T0029** |
| **OpenAI-Compatible Safeguard Judge** | Requires a structured firewall verdict before any clean prompt can be forwarded to the downstream responder. | **T0051** / **T0054** |

#### 2. Defense Evasion (Mitigating Obfuscation)
Attackers frequently try to hide their payloads from security filters. Safeguard LLM has specific countermeasures for these evasion tactics.

| Safeguard LLM Feature | MITRE ATLAS Threat Mitigated | Tactic / Technique ID |
| :--- | :--- | :--- |
| **Entropy Analysis (Sliding Window)** | Detects localized high‑entropy payloads (Base64, Hex) hidden within normal text, defeating token‑dilution attacks. | **T0031** / **T0043** |
| **Normalization (Leetspeak Conversion)** | Prevents keyword bypasses by flattening obfuscated text back to standard English before regex evaluation. | **T0031** |

#### 3. Exfiltration & Impact (Mitigating Data Loss)
If an attacker successfully manipulates the model, these features prevent the model from leaking sensitive data back to the user.

| Safeguard LLM Feature | MITRE ATLAS Threat Mitigated | Tactic / Technique ID |
| :--- | :--- | :--- |
| **PII & Secret Redaction (Input)** | Strips API keys, passwords, and PII before provider inference or downstream responder calls, preventing accidental exposure in an external model context window. | **TA0009** |
| **Output Sanitization Layer (PII & Keyword Redaction)** | Scans the LLM's response and masks sensitive data or blocked keywords (e.g., `[REDACTED_KEYWORD]`), preventing the model from returning stolen data. | **TA0009** |
| **Forbidden Phrases and Policy Category Enforcement** | Enforces operator-managed forbidden phrases locally and uses the visible Firewall Prompt's category/gibberish guidance during safeguard judging, preventing unauthorized content from reaching or being produced by the responder. | **T0048** / **T0051** |
| **System Prompt Persona Constraints** | A strict system prompt forbids the model from revealing its internal configurations or system instructions. | **T0051** / legacy **AML.T0056** |

#### 4. Reconnaissance & Discovery (Mitigating System Probing)
How the system limits an attacker's ability to learn about the defenses.

| Safeguard LLM Feature | MITRE ATLAS Threat Mitigated | Tactic / Technique ID |
| :--- | :--- | :--- |
| **Sanitized Pass‑through Guarantee** | Because sensitive prompts are redacted before provider inference or downstream responder calls, an attacker cannot probe the LLM to test its reaction to raw secrets or specific PII. | **TA0000** / **TA0009** |
| **Syntactic Complexity Analyzer (Probing Detection)** | Actively detects and flags inputs that look like model reverse‑engineering or boundary probing. | **TA0000** |

#### 5. Operations & Incident Response
While ATLAS primarily maps *threats*, Safeguard LLM includes features specifically designed for SOC analysts to investigate and respond to those threats.

| Safeguard LLM Feature | SOC / Incident Response Function |
| :--- | :--- |
| **Advanced Audit Trail (with Session IDs)** | Allows analysts to track an attacker's session history and understand their methodology over time. |
| **Anomaly Detection & Metrics Dashboard** | Uses real‑time Z‑Score calculations to detect velocity spikes indicative of automated attacks. |
| **Human‑in‑the‑Loop (HITL) Mode** | Automatically intercepts borderline traffic (Suspicious Entropy) for manual review before execution. |
| **Automated Golden Set Refinement (DPO)** | Allows analysts to export successfully blocked adversarial interactions to fine‑tune future security models. |

#### 6. Additional Defensive Controls (Per Technical Specifications)
Supplementary controls that further harden the platform.

| Safeguard LLM Feature | MITRE ATLAS Threat Mitigated | Tactic / Technique ID |
| :--- | :--- | :--- |
| **Shared Bearer Route Protection (Current Beta)** | Protected execution routes require the configured backend bearer credential. Production JWT/OIDC validation for `sub`, `aud`, and `exp` is a planned control, not current backend functionality. | **TA0006** |
| **Fail‑Closed Gateway Enforcement** | Prevents fail-open behavior by refusing to forward eligible clean prompts when the safeguard judge or downstream responder cannot complete. Governance sync failures retain the current in-memory/default state rather than silently bypassing the firewall. | **TA0005** / **T0051** |
| **Telemetry Anomaly Escalation (Planned Production Control)** | Current Beta metrics expose threat-velocity and alert-severity signals for manual escalation. Automated PagerDuty/Slack delivery is a production integration target, not current repo functionality. | **T0029** |

---

## Appendix — Key Operational Thresholds and Controls
- **Entropy bands:** `Allowed <= 3.8`, `Suspicious > 3.8 and <= configured Entropy Threshold`, `Adversarial > configured Entropy Threshold`
- **Sanitization order:** `Normalize (NFKC)` → `Strip non-printables` → `Local sanitizer/entropy/regex checks` → `OpenAI-compatible safeguard judge` → `Downstream responder` → `Output filter`
- **Audit logging:** Current Beta audit records persist sanitized prompts, detection metadata, review state, and backend telemetry with Firestore RBAC. Dual raw/normalized records and immutable admin audit trails are planned production controls, not current repo functionality.
