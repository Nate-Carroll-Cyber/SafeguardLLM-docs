### Safeguard LLM: STRIDE + MITRE ATLAS Threat Model

#### Executive Summary for the CISO

Safeguard LLM is fortified against direct prompt injection and service-denial attempts, but material residual risks remain around provider boundaries, instruction-memory integrity, shared authentication, translation, and privileged analyst workflows.

**Recommended immediate actions:** add application-level rate limiting, replace the shared backend token with production identity validation, require secondary authorization for sensitive exports, and enforce strict dependency and corpus provenance controls.

---

#### 1. Spoofing (Impersonation)
- **Threat:** **Rate-Limit Evasion via Identity Spoofing**
- **MITRE ATLAS Mapping:** `TA0004` (Initial Access) / `T0043` (Craft Adversarial Data)
- **Target Component:** Express backend, HITL queue, and planned API Gateway/WAF boundary
- **Description:** Attackers may rotate authenticated identities or source addresses to make automated traffic appear organic. The current Express backend has no application-level request-rate limiter; its five-minute duplicate-hash retry window is retry telemetry, not a general rate limit. `ApiRateLimit` in `04-backend.yml` and `GlobalRateLimit` in `06-security.yml` apply only to the not-yet-deployed CloudFormation WAF path.
- **Proposed Mitigation:** Add backend rate limiting keyed by authenticated identity and network signals, then layer behavioral fingerprinting and challenge responses for sessions that trigger the `Suspicious` entropy band (`Entropy > 3.8` and at or below the configured adversarial cutoff).

---

#### 2. Tampering (Data or Code Modification)
- **Threat:** **Filter Evasion via Semantic Padding and Unicode Obfuscation**
- **MITRE ATLAS Mapping:** `TA0007` (Defense Evasion) / `T0043` (Craft Adversarial Data)
- **Target Component:** Local sanitization pipeline
- **Description:** Attackers use semantic padding, homoglyphs, and non-printable characters to reduce detection confidence or evade exact rules.
- **Proposed Mitigation:** Preserve NFKC normalization, non-printable stripping, decode telemetry, language-likelihood checks, and analyst review of low-confidence semantic-padding cases.

---

#### 3. Repudiation (Hiding Tracks)
- **Threat:** **Log Obfuscation via Non-Standard Encodings**
- **MITRE ATLAS Mapping:** `TA0007` (Defense Evasion) / `T0068` (LLM Prompt Obfuscation)
- **Target Component:** Firestore audit trail and prompt-detail rendering
- **Description:** Unicode direction controls or encoded text can make stored prompts difficult to review or search.
- **Proposed Mitigation:** Persist sanitized canonical text and decode telemetry, escape display content safely, and retain enough provenance to reconstruct the governed decision without re-exposing raw secrets.

---

#### 4. Information Disclosure (Unauthorized Exposure)
- **Threat:** **Canary Token, PII, or System-Prompt Leakage via Model Inference**
- **MITRE ATLAS Mapping:** `TA0010` (Exfiltration) / `T0024` (Exfiltration via AI Inference API) / `T0056` (Extract LLM System Prompt)
- **Target Component:** Safeguard judge, downstream responder, and output sanitizer
- **Description:** A model may be induced to reveal sensitive values or system instructions directly or through encoded output.
- **Proposed Mitigation:** Apply output redaction, canary detection, encoding inspection, provider logging controls, and prompt-extraction tests to every configured model path.

---

#### 5. Denial of Service (Availability Impact)
- **Threat:** **Asymmetric SOC Flooding and Alert Fatigue**
- **MITRE ATLAS Mapping:** `TA0011` (Impact) / `T0029` (Denial of AI Service)
- **Target Component:** Analyst review workflow and HITL mode
- **Description:** Attackers can generate borderline-suspicious prompts to flood `PENDING_REVIEW` and conceal higher-risk events in analyst backlog.
- **Proposed Mitigation:** Apply queue quotas, identity-aware throttling, priority scoring, backlog alerts, and documented Global System Pause procedures.

---

#### 6. Elevation of Privilege (Unauthorized Capabilities)
- **Threat:** **System-Prompt Override and Persona Hijacking**
- **MITRE ATLAS Mapping:** `TA0005` (Execution) / `T0051` (LLM Prompt Injection) / `T0054` (LLM Jailbreak)
- **Target Component:** `/v1/intercept`, safeguard judge, and downstream responder
- **Description:** Attackers attempt to replace governing instructions or induce the responder to ignore policy constraints.
- **Proposed Mitigation:** Preserve strict request schemas, backend-owned responder prompts, deterministic prechecks, the independent safeguard verdict, and fail-secure handling for malformed judge output.

---

#### 7. Tampering / Elevation of Privilege (Supply Chain)
- **Threat:** **AI Supply Chain Compromise via Vulnerable Dependencies**
- **MITRE ATLAS Mapping:** `T0010` (AI Supply Chain Compromise)
- **Target Component:** Node.js application, containers, and provider SDKs
- **Description:** A compromised dependency could disable sanitizers, change routing, or exfiltrate data before enforcement.
- **Proposed Mitigation:** Maintain the SBOM, pin and scan dependencies, verify container provenance, and restrict production network egress.

---

#### 8. Information Disclosure / Tampering (Insider Threat)
- **Threat:** **Golden-Set Poisoning and Unauthorized Exports via Valid Accounts**
- **MITRE ATLAS Mapping:** `TA0012` (Privilege Escalation) / `T0020` (Poison Training Data)
- **Target Component:** Analyst dashboard and training-data export
- **Description:** A malicious or compromised analyst account can promote mislabeled records or export sensitive audit material.
- **Proposed Mitigation:** Require two-person review for promotion/export, preserve immutable administrative attribution, and alert on anomalous bulk access.

---

#### 9. Repudiation (Forensic Gap)
- **Threat:** **Evading Audit via Retention Mismatch**
- **MITRE ATLAS Mapping:** `TA0007` (Defense Evasion)
- **Target Component:** Firestore and provider-side logs
- **Description:** Different retention windows can remove local prompt lineage before related provider evidence is investigated.
- **Proposed Mitigation:** Set local retention to meet or exceed the longest relevant provider window and regularly test cross-system correlation.

---

#### 10. Denial of Service (Fail-Secure Weaponization)
- **Threat:** **Self-Inflicted DoS via Provider or Database Severance**
- **MITRE ATLAS Mapping:** `T0029` (Denial of AI Service)
- **Target Component:** Safeguard provider, responder provider, and instruction-monitor database
- **Description:** Attacking provider egress or backend connectivity can prevent eligible clean prompts from being forwarded. The instruction monitor degrades to best-effort/hash behavior, while safeguard failure follows the structured fail-secure review path.
- **Proposed Mitigation:** Use redundant provider paths, health monitoring, operator alerts, and documented pause/resume and degraded-mode procedures.

---

#### 11. Tampering (Instruction-Memory Poisoning)
- **Threat:** **Poisoning the pgvector Similarity Corpus**
- **MITRE ATLAS Mapping:** `T0070` (RAG Poisoning)
- **Target Component:** PostgreSQL/pgvector instruction monitor and seed import/export workflow
- **Description:** A compromised analyst workflow or seed artifact can insert mislabeled adversarial records, causing false blocks or manipulating later similarity decisions.
- **Proposed Mitigation:** Preserve reviewed-`ADVERSARIAL` admission rules, seed hashes, immutable seed metadata, dual control for corpus promotion, database least privilege, and periodic corpus-drift review.

---

#### 12. Tampering / Elevation of Privilege (Client-Supplied Overrides)
- **Threat:** **Attempted Safeguard Runtime Reconfiguration**
- **MITRE ATLAS Mapping:** `T0081` (Modify AI Agent Configuration)
- **Target Component:** `/v1/intercept` and Sam Spade request schemas
- **Description:** A caller may attempt to inject provider endpoints, model IDs, responder prompts, or other backend-owned execution settings through request metadata.
- **Proposed Mitigation:** Keep security-sensitive Zod objects strict, reject unknown fields, retain the narrow documented exceptions for `safeguardApiKey` and `safeguardEffectivePrompt`, and regression-test rejected overrides.

---

#### 13. Tampering / Information Disclosure (Translation Path)
- **Threat:** **Lara Translation Supply-Chain or Credential Abuse**
- **MITRE ATLAS Mapping:** `T0010` (AI Supply Chain Compromise) / `T0055` (Unsecured Credentials)
- **Target Component:** Protected `/v1/translate` route and Lara SDK
- **Description:** Compromised translation dependencies, credentials, or upstream behavior could alter recovered text or expose material sent for translation.
- **Proposed Mitigation:** Keep translation backend-managed and authenticated, fail closed when Lara credentials are absent, minimize translated data, rotate credentials, and validate recovered text through the sanitizer before inference.

---

#### 14. Spoofing / Elevation of Privilege (Shared Authentication Secret)
- **Threat:** **Shared Static Bearer Token Theft or Replay**
- **MITRE ATLAS Mapping:** `T0012` (Valid Accounts) / `T0055` (Unsecured Credentials)
- **Target Component:** Protected backend routes using `INTERCEPT_BEARER_TOKEN`
- **Description:** The Beta uses one shared bearer secret rather than per-user JWT/OIDC validation. Compromise enables replay against protected execution routes and weakens caller attribution.
- **Proposed Mitigation:** Store the secret outside source control, rotate it, restrict its exposure, and replace it in production with per-request identity validation and scoped authorization.

---

### Appendix — Key Operational Thresholds and Controls

- **Entropy bands:** `Allowed <= 3.8`, `Suspicious > 3.8 and <= configured Entropy Threshold`, `Adversarial > configured Entropy Threshold`
- **Sanitization order:** `Normalize (NFKC)` → `Strip non-printables` → `Local sanitizer/entropy/regex checks` → `Instruction similarity` → `Safeguard judge` → `Downstream responder` → `Output filter`
- **Audit logging:** Current Beta records sanitized prompts, detection metadata, review state, and backend telemetry. Immutable administrative action logging remains a production control.
