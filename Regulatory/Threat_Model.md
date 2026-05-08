### Counter‑Spy.ai: STRIDE + MITRE ATLAS Threat Model

#### Executive Summary for the CISO

Counter‑Spy.ai is well fortified against direct front‑door attacks such as prompt injection and service denial. The primary residual risks are at the edges:

1. **Output Edge** — advanced format shifting to bypass redaction.  
2. **Code Edge** — supply‑chain compromises silently degrading the local firewall.  
3. **Human Edge** — valid account abuse leveraging DPO/export features to poison downstream models.

**Recommended immediate actions:** require secondary authorization for data exports and enforce strict dependency pinning and SCA in CI/CD.

---

#### 1. Spoofing (Impersonation)
- **Threat:** **Rate‑Limit Evasion via Identity Spoofing**  
- **MITRE ATLAS Mapping:** `AML.TA0003` (Initial Access) / `AML.T0043` (Craft Adversarial Data)  
- **Target Component:** Human‑in‑the‑Loop (HITL) Queue / API Gateway  
- **Description:** Attackers may spoof IPs or rotate ephemeral authenticated sessions to make automated traffic appear organic and bypass rate limits.  
- **Proposed Mitigation:** Implement behavioral fingerprinting (typing cadence, interaction speed) and require CAPTCHA/challenge responses for sessions that trigger the `Suspicious` entropy band (`Entropy > 3.6` and at or below the configured adversarial cutoff) before entering HITL.

---

#### 2. Tampering (Data or Code Modification)
- **Threat:** **Filter Evasion via Semantic Padding & Unicode Obfuscation**  
- **MITRE ATLAS Mapping:** `AML.TA0005` (Defense Evasion) / `AML.T0043` (Craft Adversarial Data)  
- **Target Component:** Local Sanitization Pipeline (Entropy Scanner & Regex Engine)  
- **Description:** Attackers use semantic padding to lower Shannon entropy or inject homoglyphs and zero‑width characters to evade regex detection.  
- **Proposed Mitigation:**  
  - Deploy an auxiliary perplexity/intent classifier to detect semantic padding.  
  - Enforce Unicode normalization (NFKC) and strip non‑printable characters before entropy and regex evaluation.

---

#### 3. Repudiation (Hiding Tracks)
- **Threat:** **Log Obfuscation via Non‑Standard Encodings**  
- **MITRE ATLAS Mapping:** `AML.TA0005` (Defense Evasion) / `AML.T0043` (Obfuscation)  
- **Target Component:** Advanced Audit Trail (Firestore)  
- **Description:** Unicode obfuscation or right‑to‑left override characters can render logged prompts unreadable, break UI rendering, and evade keyword searches.  
- **Proposed Mitigation:** Store dual audit records: (1) the raw input escaped for safe UI rendering, and (2) a normalized ASCII‑stripped version for search and forensics.

---

#### 4. Information Disclosure (Unauthorized Exposure)
- **Threat:** **Canary Token / PII Leakage via Format Shifting**  
- **MITRE ATLAS Mapping:** `AML.TA0010` (Exfiltration) / `AML.T0024` (Exfiltration via Cyber Means) / `AML.T0054` (LLM Meta Prompt Extraction)  
- **Target Component:** Output Sanitization Layer  
- **Description:** The LLM may be induced to output sensitive values encoded (Base64, hex, tables) that bypass exact‑match sanitizers.  
- **Proposed Mitigation:** Apply sliding‑window entropy analysis and regex filtering to model outputs as well as inputs. Intercept outputs with abnormally high entropy or encoding patterns. Replace any explicit canary token references with a redacted placeholder such as `[REDACTED_CANARY_TOKEN]`.

---

#### 5. Denial of Service (Availability Impact)
- **Threat:** **Asymmetric SOC Flooding (Alert Fatigue)**  
- **MITRE ATLAS Mapping:** `AML.TA0008` (Impact) / `AML.T0029` (Denial of ML Service)  
- **Target Component:** Analyst Review Workflow / HITL Mode  
- **Description:** Attackers generate many borderline‑suspicious prompts (e.g., entropy ≈ 4.8) to flood `PENDING_REVIEW`, causing human analysts to miss real incidents.  
- **Proposed Mitigation:** Implement dynamic thresholding and queue‑based controls. If `PENDING_REVIEW` volume exceeds a threshold, automatically raise review thresholds or enable a temporary global pause mode and triage backlog with prioritized sampling.

---

#### 6. Elevation of Privilege (Unauthorized Capabilities)
- **Threat:** **System Prompt Override (Persona Hijacking / Jailbreak)**  
- **MITRE ATLAS Mapping:** `AML.TA0004` (Execution) / `AML.T0051` (Prompt Injection) / `AML.T0042` (Jailbreak) / `AML.T0053` (LLM Manipulation)  
- **Target Component:** Backend `/v1/intercept` gateway, OpenAI-compatible safeguard judge, and downstream responder
- **Description:** Attackers attempt to override the model persona using jailbreak patterns to bypass forbidden‑topic constraints.  
- **Proposed Mitigation:** Do not rely solely on the primary model. Use prompt wrapping (re‑assert constraints at the end of the prompt) and route outputs through a secondary evaluator model that classifies whether the primary model violated guardrails.

---

#### 7. Tampering / Elevation of Privilege (Supply Chain)
- **Threat:** **AI Supply Chain Compromise via Vulnerable Dependencies**  
- **MITRE ATLAS Mapping:** `AML.T0010` (AI Supply Chain Compromise)  
- **Target Component:** Local Sanitization Pipeline / Node.js Environment  
- **Description:** Compromised upstream packages could execute arbitrary code, disable sanitizers, or exfiltrate raw inputs before sanitization.  
- **Proposed Mitigation:**  
  - Maintain a strict SBOM.  
  - Enforce automated SCA in CI/CD to block builds with known CVEs.  
  - Apply strict network egress filtering on deployment containers to prevent compromised dependencies from calling external C2 endpoints.

---

#### 8. Information Disclosure / Tampering (Insider Threat)
- **Threat:** **Golden Set Poisoning & Unauthorized Exports via Valid Accounts**  
- **MITRE ATLAS Mapping:** `AML.T0012` (Valid Accounts) / `AML.T0039` (Data Poisoning)  
- **Target Component:** Analyst Operations Dashboard / Fine‑Tuning Pipeline  
- **Description:** Malicious insiders may promote adversarial prompts into the Golden Set or scrape audit logs for sensitive content, enabling poisoning of future models.  
- **Proposed Mitigation:**  
  - Planned production control: enforce a Two‑Person Rule for any Golden Set promotion and export.  
  - Planned production control: implement immutable admin audit trails that record who performed each analyst action.  
  - Planned production control: trigger DLP and SIEM alerts for anomalous internal access patterns and bulk exports.

---

#### 9. Repudiation (The "Forensic Gap")**
* **Threat:** **Evading Audit via TTL Mismatches**
* **MITRE ATLAS Mapping:** **AML.TA0005 (Defense Evasion)**
* **Description:** The spec explicitly notes a "Forensic Gap Awareness." Firestore audit logs and provider-side safeguard/responder logs may have different retention windows. If local TTL is shorter than the provider retention window, investigators can lose the local prompt lineage before provider records expire.
* **Mitigation:** The organization must mandate that Firestore TTL equals or exceeds the longest relevant safeguard or downstream responder provider retention window used in production.

---

#### 10. Denial of Service (The "Fail-Secure" Weaponization)**
* **Threat:** **Self-Inflicted DoS via Database Severance**
* **MITRE ATLAS Mapping:** **AML.T0029 (Denial of ML Service)**
* **Description:** Because the gateway fails closed when the safeguard judge or downstream responder cannot complete, an attacker can target provider egress or backend connectivity to prevent eligible clean prompts from being forwarded. Governance sync failures retain the current in-memory/default governance state rather than automatically forcing `isGlobalPause: true`.
* **Mitigation:** Ensure redundant provider egress, backend health monitoring, clear operator alerts, and documented manual pause/resume procedures for outages.

---

### Appendix — Key Operational Thresholds and Controls
- **Entropy bands:** `Allowed <= 3.6`, `Suspicious > 3.6 and <= configured Entropy Threshold`, `Adversarial > configured Entropy Threshold`
- **Sanitization order:** `Normalize (NFKC)` → `Strip non-printables` → `Local sanitizer/entropy/regex checks` → `OpenAI-compatible safeguard judge` → `Downstream responder` → `Output filter`
- **Audit logging:** Current Beta audit records persist sanitized prompts, detection metadata, review state, and backend telemetry with Firestore RBAC. Dual raw/normalized records and immutable admin audit metadata are planned production controls, not current repo functionality.

---
