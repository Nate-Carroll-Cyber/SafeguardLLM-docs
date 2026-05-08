# 🛡️ Analyst & Administrator Operations Guide
## Counter-Spy.ai

| Version | Date | Description |
| :--- | :--- | :--- |
| **v2.0** | 2026-04-21 | Promotion to Beta: stabilized local demo stack, guarded backend responder path, Lara translation modes, Sam Spade governed intake, and layered defense funnel metrics. |

---

## 1. Operational Overview

Counter-Spy.ai is an **Adversary-Aware Security Gateway**. It sits between untrusted user input and Large Language Models (LLMs) to provide a deterministic security layer. Unlike traditional firewalls, it does not simply block known bad patterns — it analyzes the **intent, complexity, and randomness** of incoming traffic to identify zero-day prompt injections and model reverse-engineering attempts. In the current Beta, deterministic enforcement and model guidance are both present: exact policy hits remain phrase-based, while the saved firewall prompt also steers the decision model across the operator-managed forbidden categories.

As an Analyst or Administrator, you are the final decision-maker in the **Human-in-the-Loop (HITL)** cycle. Your primary goal is to maintain the balance between **System Resilience** (blocking attacks) and **User Experience** (minimizing false positives).

---

## 2. Daily Operations Checklist

Analysts should perform these tasks at the start of every shift:

- [ ] **Baseline Check:** Verify the 24h Threat Velocity is within ±15% of the weekly mean.
- [ ] **Queue Triage:** Clear all `PENDING_REVIEW` logs.
- [ ] **False Positive Audit:** Randomly sample 20 "Clean" logs to check for missed injections (False Negatives).
- [ ] **Knowledge Base Sync:** Ensure active guardrails match the current organization security policy.

---

## 3. Monitoring Dashboard

The **Metrics** tab is the primary interface for real-time situational awareness and your early-warning system for separating noise from targeted attacks.

### 3.1 Threat Velocity & Spike Indicators

The dashboard tracks the rate of threats (Suspicious or Adversarial logs) over a rolling 24-hour window.

**Threat Velocity** is expressed as a percentage change from the 24-hour baseline. A value of **+500%** indicates that current threat activity is five times higher than the recent baseline.

**Current Beta note:** The Metrics surface provides real-time threat velocity and alert-severity visibility from audit records. The local anomaly helper currently computes a rolling spike ratio against a 24-hour hourly baseline, not a production incidenting service with PagerDuty/Slack delivery. If your deployment uses formal Z-score thresholds, calculate and alert on those in the production telemetry pipeline.

**Production target:** A Z-score can measure how many standard deviations the current threat rate is from the mean:

$$Z = \frac{x - \mu}{\sigma}$$

| Symbol | Definition |
| :--- | :--- |
| $x$ | Current observed threat rate |
| $\mu$ | Mean threat rate over the previous 24 hours |
| $\sigma$ | Standard deviation of the threat rate |

**Alert Thresholds:**

| Indicator | Status | Required Action |
| :--- | :--- | :--- |
| Low | Normal | No action required. |
| Elevated | Active Interest | Monitor for repeated payloads from a single `userId`. |
| Significant | Statistically Significant | Increase monitoring cadence. |
| Critical | **Coordinated Incident** | Evaluate Global System Pause. Notify Lead Architect. |

> [!IMPORTANT]
> **Notification Escalation:** PagerDuty/Slack incident creation is a planned production integration, not current repo functionality. In the current Beta, operators should treat high spike indicators as a manual escalation trigger.

> [!TIP]
> Use the **Hide Simulated** toggle to filter out bulk ingest and test data, ensuring metrics reflect real-world user intent only.

### 3.2 Entropy Analysis

The system calculates **Shannon Entropy** to detect obfuscation and encoding attacks:

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_b P(x_i)$$

| Metric | Description | High Score Indicates |
| :--- | :--- | :--- |
| **Global Entropy** | Randomness of the entire prompt | Word salad or incoherent noise injection |
| **Max Window Entropy** | Peak randomness in a 35-character sliding window | Base64, Hex, or encrypted payloads hidden within normal text |

**Configured Thresholds:**

| Guardrail | Suspicious | Adversarial | Purpose |
| :--- | :--- | :--- | :--- |
| **Entropy** | `> 3.2` | `> configured Entropy Threshold` | Shared entropy policy used by submit-time sanitization, Audit Logs, and Metrics |
| **Syntactic Complexity** | 50 | 90 | Catching instruction stacking |

Operator note: entropy now has two roles. First, it contributes a direct verdict band: above `3.2` is `Suspicious`, and above the configured threshold is `Adversarial`. Second, it still acts as supporting concealment telemetry in Prompt Details and Metrics. Recognized obfuscation families remain adversarial by policy even when the entropy score alone would not cross the configured ceiling.

Operator note: `Blocked Topics` metrics currently count normalized phrase-family hits, not a separate semantic topic classifier. If a request is semantically close to a forbidden category but does not literally match one of the configured topic phrases after supported recovery or normalization, it may still be influenced by the firewall prompt without incrementing `Topic Hits`.

---

## 4. Incident Review Workflow (HITL)

**Human-in-the-Loop (HITL)** mode intercepts borderline traffic for manual verification. When the system is uncertain, it holds the prompt in a `REVIEW` state. The end user sees a Security Verification spinner while an analyst decides the outcome.

### 4.1 Review Process

1. **Identify:** Locate logs with the purple `REVIEW` status in the queue.
2. **Inspect:** Use the **Full Prompt Inspection** dialog to view the persisted sanitized prompt, response, detection flags, obfuscation telemetry, and backend timing fields. Raw un-redacted prompt storage is not enabled in the current Beta.
3. **Cross-Reference:** Check the **Session ID** to identify whether this user has had multiple previous interceptions.
4. **Verdict:** Assign a **Resultant Severity** using the Decision Tree below.

### 4.2 Decision Tree

```mermaid
graph TD
    A[Review Prompt] --> B{Contains PII or Secrets?}
    B -->|Yes| C[Block: ADVERSARIAL]
    B -->|No| D{Instruction Injection?}
    D -->|Yes| E{Malicious Intent?}
    E -->|Yes| C
    E -->|No| F[Flag: SUSPICIOUS]
    D -->|No| G{High Entropy or Code?}
    G -->|Yes| H[Tag: INFORMATIONAL]
    G -->|No| I[Approve: CLEAN]

    style C fill:#991b1b,color:#fff
    style F fill:#92400e,color:#fff
    style H fill:#1e40af,color:#fff
    style I fill:#065f46,color:#fff
```

### 4.3 Verdict Policy

| Verdict | User Impact | Backend Impact | Typical Use Case |
| :--- | :--- | :--- | :--- |
| **Clean** | Released to AI | Logged as OK | Confirmed false positives |
| **Informational** | Released to AI | Logged as Flagged | Code samples or unusual but harmless content |
| **Suspicious** | Blocked | User Flagged | Policy probing or light roleplay attempts |
| **Adversarial** | Blocked | User/IP Blocked | Clear injection, PII exfiltration, or DoS attempts |

---

## 5. Crisis Protocols (HOTL)

**Global System Pause** is the platform kill switch and should be treated as a DEFCON 1 event.

> [!CAUTION]
> Activating the **Global System Pause** prevents new automated inference in the Analyst Chat path and routes subsequent prompts into `PENDING_REVIEW`. The request that triggered an automatic pause is blocked before inference; later traffic is queued until operators resume service.

### 5.1 Activation Criteria

Activate the Global System Pause when **any** of the following conditions are met:

1. **Critical spike indicator** sustained for more than 10 minutes.
2. **Canary Token Trigger:** The system detects `COUNTERSPY_CANARY_TOKEN` in a log, indicating a System Instruction breach.
3. **Third-Party Outage:** AWS Bedrock or Gemini is experiencing a degraded state (503 errors).
4. **Automatic ReDoS Trigger:** Sanitization latency exceeds 1,000ms, which blocks the triggering prompt, logs `ReDoS_ATTEMPT_DETECTED`, and flips `isGlobalPause` on for subsequent traffic.

### 5.2 Recovery Protocol

> [!WARNING]
> Unpausing is more operationally dangerous than pausing. Do not skip steps.

1. **Purge:** Clear the `PENDING_REVIEW` queue of all malicious payloads accumulated during the pause.
2. **Verify:** Confirm that the attack vector (e.g., a specific regex bypass) has been patched in the **Knowledge Base**.
3. **Tune:** Adjust Entropy or Complexity thresholds to catch the pattern that triggered the pause.
4. **Resume:** Toggle the Global System Pause to **OFF**.
5. **Monitor:** Remain on the Metrics tab and observe threat velocity for a minimum of 15 minutes to confirm new thresholds are holding.

---

## 6. DPO Workflow: The Golden Set

The **Golden Set** is the ground truth dataset for future model fine-tuning via Direct Preference Optimization (DPO). Use the **Promote to KB** feature in the Audit Log to nominate a log entry.

### 6.1 Quality Bar for Promotion

Only promote logs that meet at least one of the following criteria:

| Criterion | Description |
| :--- | :--- |
| **Failed Safety** | An injection that passed the shield but failed in production inference |
| **Obfuscation** | Clever encoding techniques such as Token Dilution, LeetSpeak, or Base64 embedding |
| **Novel Vector** | An attack pattern not represented in the current Knowledge Base |

**Required Metadata:** Every promoted log must include a clear **Rejected Reason** for the training pipeline. Entries without a reason will be excluded from the DPO batch.

---

## 7. Detection Flag Glossary

| Flag | Severity | Technical Detail |
| :--- | :--- | :--- |
| `ReDoS_ATTEMPT_DETECTED` | **Critical** | Sanitization latency exceeded 1,000ms. The triggering request was blocked before inference, logged as adversarial, and automatic Global System Pause was activated for subsequent traffic. |
| `TOKEN_DILUTION` | **High** | High local entropy spike in sliding window. Obfuscated payload buried in noise text. |
| `SYNTACTIC_PROBE` | **Medium** | Elevated density of imperative verbs (e.g., "forget," "ignore," "must"). Indicates system override attempt. |
| `PII_LEAK` | **Variable** | Detection of SSN, email addresses, or AWS keys. Verify whether redaction succeeded before releasing. |
| `CANARY_EXFIL` | **Critical** | Prompt or response contained the unique `COUNTERSPY_CANARY_TOKEN`. Indicates System Instruction breach — activate HOTL immediately. |

## Obfuscation Posture

Counter-Spy.ai currently operates as a plain-text English chatbot control plane. Under that posture:

- Any recognized obfuscation signal is treated as `Adversarial`.
- Analysts should not expect leetspeak, ROT13, symbol substitution, coordinate ciphers, recursive decode chains, or similar concealment patterns to remain merely `Suspicious`.
- Alphabetic substitution gibberish that scores as low-English-likeness under the local trigram / bounded Caesar-shift heuristic is also treated as an obfuscation-family adversarial signal, even if it contains only letters and spaces.
- If a prompt is already carrying a local obfuscation-family `Adversarial` verdict, the user-facing response should be a local detection banner, not `Backend Error`. Treat any backend-availability message on a clearly obfuscated prompt as a routing bug worth investigation.
- Position-style or indexed vertical text layouts may still under-detect compared with simpler one-character-per-line vertical text. Treat those misses as detector-coverage gaps rather than as evidence that the obfuscation policy itself is disabled.
