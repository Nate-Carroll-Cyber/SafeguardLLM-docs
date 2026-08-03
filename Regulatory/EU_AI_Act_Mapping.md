# Safeguard LLM — EU AI Act Compliance Mapping

**Revised 2026-08-03.** This revision reflects two changes since the prior
version: the **Digital Omnibus on AI**, which materially altered the compliance
calendar, and the target-state AWS architecture, which changes what several of
these claims can honestly assert.

---

## 1. What changed in the law

The prior version was written against the original AI Act timeline, under which
2 August 2026 was the enforcement date for high-risk obligations. That date moved.

<cite index="20-1">The EU adopted the final text of the Digital Omnibus on AI — Parliament on 16 June 2026, Council on 29 June 2026, with entry into force in July 2026.</cite> <cite index="18-1">High-risk obligations for stand-alone Annex III systems are deferred to 2 December 2027; for AI embedded in regulated products under Annex I, to 2 August 2028. A new prohibition on AI-generated non-consensual intimate imagery and child sexual abuse material was introduced into Article 5.</cite>

**Revised calendar:**

| Date | Obligation | Status |
|---|---|---|
| 2 Aug 2025 | GPAI model obligations (Art. 53, 55) | In force |
| **2 Aug 2026** | **Article 50 transparency obligations** | **In force — as of yesterday** |
| 2 Dec 2026 | Art. 50(2) machine-readable marking for systems already on the market; new Art. 5 prohibitions | Pending |
| 2 Aug 2027 | Member State AI regulatory sandboxes; Commission delegated acts for Annex I | Pending |
| **2 Dec 2027** | **Chapter III high-risk obligations, Annex III (stand-alone)** | Deferred from 2 Aug 2026 |
| 2 Aug 2028 | Chapter III high-risk, Annex I (embedded in regulated products) | Deferred from 2 Aug 2027 |

**The consequence for this document.** Every article the prior version mapped to
— Articles 9, 10, 12, 14, and 15 — sits in **Chapter III** and applies to
high-risk systems. Those obligations were deferred to **2 December 2027**. The
prior version's framing, that these capabilities are "legally required to operate
an enterprise generative AI system within the European Union" as of August 2026,
is no longer accurate.

<cite index="25-1">Article 50 was left out of that deferral: its core transparency and disclosure duties applied on schedule from 2 August 2026, and national market surveillance authorities can enforce them from that date.</cite> Article 50 does not appear anywhere in the prior version. **It is the obligation that is live now, and it is the one this document should lead with.**

---

## 2. Executive Summary for the Compliance Officer

An enterprise deploying an LLM without an intermediary gateway carries EU AI Act
obligations directly on the model and the application around it. Safeguard LLM is
a **control layer that supplies evidence** for several of those obligations — it
does not discharge them, and no wrapper can.

Three things are worth stating plainly to a compliance officer:

**The urgent obligation is Article 50, not Chapter III.** <cite index="32-1">Article 50 requires disclosure of four things: that someone is talking to an AI, that a piece of content is synthetic, that a system recognises emotions or categorises biometric data, and that an image, audio, video or text is a deepfake or otherwise AI-generated. The duties are shared between the provider (which develops) and the deployer (which uses the system) — an organisation with no high-risk AI can still have obligations simply by operating a chatbot or publishing generated content.</cite> This applied on 2 August 2026.

**The high-risk obligations are sixteen months out, not imminent.** That is
breathing room, not a reprieve — the deferral was granted because <cite index="17-1">implementation faced significant delays, particularly around the designation of national competent authorities and the finalisation of harmonised standards and compliance tools</cite>, and the standards those obligations depend on are still being written.

**Safeguard LLM supplies evidence for Articles 9, 12, 14, and 15; it does not
supply the systems those articles require.** Article 9 requires a *risk
management system* — a documented, iterative process. Configurable guardrails are
an input to that process, not the process. Article 12 requires *automatically
recorded logs ensuring traceability*; an audit trail that a privileged operator
can silently edit is not yet traceable in the sense the Article means. The
distinctions matter more now, not less, because there is time to close them
properly before December 2027.

---

## 3. Article 50 — Transparency *(live; new in this revision)*

<cite index="26-1">These obligations extend to providers and deployers of open-source AI systems, which are not exempt. Transparency obligations are not limited to systems classified as "high-risk": they apply to any AI system used in the four situations the Article covers.</cite>

### 3.1 Where Safeguard LLM sits

Safeguard LLM is **not the provider of the underlying model** — OpenAI, Google,
and the open-weight judge hosts are. It is, however, **in the response path**,
which gives it a role no policy document can occupy: it can *verify and enforce*
transparency at runtime rather than assert it in a manual.

| Art. 50 duty | Falls on | Safeguard LLM's role |
|---|---|---|
| 50(1) — disclose the user is interacting with AI | Provider of the interacting system | **Enforcement point.** The gateway sits between user and model and can require the disclosure to be present in the response envelope |
| 50(2) — machine-readable marking of synthetic output | Provider of the generative system | **Verification point.** The gateway sees every response before the user does and can assert that marking is present, log its absence, and fail closed |
| 50(3) — inform persons exposed to emotion recognition / biometric categorisation | Deployer | Not applicable — no such component evidenced |
| 50(4) — disclose deepfakes and AI-generated public-interest text | Deployer | Audit trail supports the deployer's own record |

**The 50(2) enforcement capability is the strongest new claim available to this
product**, and it is not yet built. A gateway that inspects every model response
is the natural place to assert that a machine-readable mark exists — and to
detect when a provider silently stops applying one. That is a control neither the
model provider nor the deploying enterprise can easily implement themselves.

### 3.2 What is already present

- **Output sanitization layer** — inspects every response before display. The insertion point for 50(2) verification already exists; the check does not.
- **Audit trail** — records per-decision metadata that would evidence a deployer's 50(4) disclosure practice.
- **Sam Spade CTF scenario** — an NPC elicitation exercise where a user interacts with a persona. Under 50(1) the AI nature of that interaction must be disclosed unless obvious from the circumstances. **This warrants explicit review**: a governed CTF scenario is arguably "obvious," but the exemption is narrow and the burden of showing it sits with the provider.

### 3.3 What is not present

- No verification that responder output carries a machine-readable mark
- No disclosure enforcement in the response envelope
- No record of *which* transparency obligation was satisfied per interaction

### 3.4 Deadline

<cite index="27-1">A limited grace period is envisaged only for AI systems placed on the market before 2 August 2026 and only as regards the marking and detection obligation in Article 50(2); providers of such systems must comply from 2 December 2026. Content generated prior to 2 August 2026 does not need to be labelled retroactively.</cite>

---

## 4. Chapter III articles — now applicable 2 December 2027

These map as the prior version described. Each entry now separates what is
**evidenced** from what is **claimed**, because the independent MAESTRO and
governance assessments of this system found several of the prior version's
claims to be partial.

### 4.1 Article 14 — Human Oversight

*High-risk systems must be designed so natural persons can effectively oversee
them, including the ability to intervene, disregard, or halt the system.*

**Evidenced:**
- **HITL review queue** — borderline traffic above the suspicious entropy floor routes to `PENDING_REVIEW`.
- **Global System Pause (DEFCON 1)** — halts automated forwarding, routes new prompts to manual review, stops Bulk Ingest replay. This is a genuine "stop button" and is the strongest Article 14 evidence the system produces.
- **Analyst review workflow** — authorized personnel can override verdicts and update `resultantSeverity`.

**Gap, corrected from the prior version:** the review queue is an **operational/display state, not an enforced gate**. The governance assessment found human supervision present and *special authorization* absent — an operator can see that something requires review and still act. Article 14 requires the ability to intervene; it also anticipates that oversight is effective, which a soft gate does not establish.

**To close before Dec 2027:** hard-gate high-consequence actions (Golden Set promotion, adversarial labelling, verdict override) behind out-of-band approval. Distinguish global pause from per-session pause so oversight does not require halting the service.

### 4.2 Article 15 — Accuracy, Robustness, Cybersecurity

*Resilience against errors, faults, and malicious actions including adversarial
attacks, prompt injection, and data poisoning.*

**Evidenced — this is the article Safeguard LLM supports best:**
- Defense-in-depth sanitization (regex, entropy, syntactic complexity, obfuscation strict-mode)
- Instruction-similarity monitoring against a reviewed-adversarial corpus
- Output sanitization
- Anti-ReDoS circuit breaker
- Fail-secure defaults throughout
- Dependency governance with pinned CVE-mitigating versions

**Gap:** Article 15 requires resilience, and the accompanying standards work will
require it to be *demonstrated*. No adversarial evaluation, red-team result, or
false-negative measurement is evidenced. Detector efficacy is currently inferred
from intervention volume, which moves with attack volume rather than with control
effectiveness.

**To close:** a fixed adversarial evaluation corpus, run on a schedule and on
every threshold change, tracking absolute detection rate. This is also the
artifact a conformity assessment will ask for.

### 4.3 Article 12 — Record-Keeping

*Automatic recording of events throughout the lifecycle, ensuring traceability.*

**Evidenced:**
- Structured audit schema capturing `userId`, `sessionId`, `timestamp`, `entropy`, `detectionFlags`
- SHA-256 prompt hashes rather than raw prompt bodies — a good scoping decision that makes the trail useful without creating a secondary disclosure surface
- Firestore rules preventing client-side forgery of backend-owned security fields
- Metrics dashboard exposing threat velocity, alert severity, review status

**Gap, corrected from the prior version:** the trail is **not tamper-evident**.
Firestore rules stop *client* forgery; nothing stops a privileged operator or a
compromised backend credential from selectively editing records. Article 12's
purpose is traceability and post-incident investigation, both of which assume the
record cannot be altered by the party being investigated.

A second gap the prior version did not name: audit attribution rests on a
**client-asserted user header**, not a verified identity. A traceability record
whose subject the caller chose is not traceable to a person.

**To close:** WORM/immutable audit sink separate from the execution environment;
per-request verified identity as the attribution source.

### 4.4 Article 10 — Data and Data Governance

*Appropriate data governance and management practices, including examination for
bias.*

**Evidenced:**
- **PII and secret redaction** before any provider call — enforces data minimisation, and is the clearest GDPR-alignment claim the product has
- **Golden Set curation** — analyst-reviewed interactions exported in structured form for future fine-tuning
- Egress restriction of embeddings to a private network, so adversarial prompt material never reaches a third-party embedding API

**Gap:** Article 10 requires examination for possible biases. The system's
language heuristics (`FOREIGN_LANGUAGE`, `MIXED_LANGUAGE`) can over-block
legitimate non-English and dialectal input, and **no disparate-impact testing is
evidenced**. This is the highest-exposure gap in the document — it is a
requirement of Article 10, an obligation under Colorado SB 24-205, and the kind
of finding that is difficult to remediate retroactively because it requires
historical data to measure.

**Note on the Omnibus:** the same package adjusted the GDPR position on
processing special-category data for bias detection. If the bias testing above
requires such data, that change is relevant and should be reviewed with counsel
rather than assumed either way.

### 4.5 Article 9 — Risk Management System

*A continuous iterative process to identify, estimate, and evaluate risks to
health, safety, and fundamental rights.*

**Evidenced:**
- Dynamic guardrails — administrators can toggle blocked keywords, forbidden phrases, entropy filtering, obfuscation detection, regex rules, and judge enforcement at runtime
- Editable Safeguard Effective Prompt with a tracked drift hash
- MITRE ATLAS threat organizer
- Operations Guide and SOPs

**Gap, and the most significant reframe in this revision:** Article 9 requires a
*system* — a documented, iterative, recurring process with defined ownership and
review cadence. Configurable controls are an **input** to that process, not the
process itself. The independent assessments found no evidenced risk register, no
component registry with owners, no periodic policy review, and no access review.

Runtime configurability without a review cadence is arguably worse than static
configuration for Article 9 purposes: thresholds can be adjusted to reduce false
positives with no record of who changed what or why, which is precisely the drift
Article 9 exists to catch.

**To close:** a documented risk management process with named owners, a change
log for guardrail configuration treated as security-relevant, and a review
cadence. This is a governance artifact, not a feature.

---

## 5. Provider or deployer?

The prior version did not draw this distinction, and Article 50 makes it
consequential. <cite index="29-1">Under Article 50, the provider is the entity that develops or places the AI system on the market, while the deployer is the entity that uses the system under its own authority. Both roles carry different obligations.</cite>

| Scenario | Safeguard LLM's operator is | Obligations |
|---|---|---|
| Sold as a product to enterprises | **Provider** of the gateway | 50(1) design duties for any interactive surface; Chapter III if the gateway itself is later classified high-risk |
| Run internally in front of an enterprise's own LLM | **Deployer** | 50(4) disclosure for published output; Article 26 deployer duties from Dec 2027 |
| Both | Both, per deployment | Document which role applies to which deployment |

<cite index="29-1">Article 50 may also be relevant when you purchase AI systems: as a deployer you have your own obligations regardless of whether you developed the system or purchased it.</cite> A customer deploying Safeguard LLM does not inherit compliance from it — which is worth stating explicitly in any customer-facing version of this document, because the prior version's "instantly gains" framing invites the opposite reading.

---

## 6. What Safeguard LLM does not provide

Stated because a compliance mapping that omits this is not usable in an audit.

- **Conformity assessment** — a Chapter III procedure the deployer or provider performs; no tool discharges it
- **Technical documentation (Annex IV)** — the audit trail supplies evidence for it; it is not the document
- **Registration in the EU database** — an obligation on the provider of a high-risk system
- **Fundamental rights impact assessment** (Art. 27) — applies to certain deployers; requires analysis, not telemetry
- **Post-market monitoring plan** (Art. 72) — the metrics dashboard is an input
- **Bias and fairness assessment** — not present, see §4.4
- **AI literacy** (Art. 4, in force since Feb 2025) — an organisational obligation on providers and deployers

---

## 7. Recommended sequence

| Priority | Action | Driver | Deadline |
|---|---|---|---|
| P0 | Determine provider/deployer role per deployment; document it | Art. 50 scoping | Immediate — obligation is live |
| P0 | Review Sam Spade and any interactive surface against Art. 50(1); add disclosure where the "obvious from the circumstances" exemption does not clearly apply | Art. 50(1) | Immediate |
| P1 | Build Art. 50(2) marking verification into the output sanitization layer; log and alert on absence | Art. 50(2) — differentiating capability | Before 2 Dec 2026 |
| P1 | Bias / disparate-impact testing of the language heuristics | Art. 10; CO SB 24-205 | Start now — needs historical data |
| P1 | Immutable audit sink, separate from the execution environment; verified identity as the attribution source | Art. 12 | Before 2 Dec 2027 |
| P2 | Hard-gate high-consequence actions behind out-of-band approval | Art. 14 | Before 2 Dec 2027 |
| P2 | Fixed adversarial evaluation corpus with scheduled runs | Art. 15 | Before 2 Dec 2027 |
| P2 | Documented risk management process, component registry, review cadence | Art. 9 | Before 2 Dec 2027 |
| P2 | Confirm the system is not in scope for the new Art. 5 prohibitions | Art. 5 | Before 2 Dec 2026 |
| P3 | Third-party model training-data disclosures; provider DPAs and AI-CAIQ responses | Art. 10; CA AB 2013 | Before 2 Dec 2027 |

---

## 8. Standing caveats

**This is a requirements-traceability mapping, not a conformity assertion.**
Nothing here states that Safeguard LLM makes a deploying organisation compliant.

**Classification is unresolved.** Whether any deployment of this system is
high-risk under Annex III depends on the *use case it fronts*, not on the gateway.
A gateway in front of a recruitment assistant inherits an Annex III context; the
same gateway in front of an internal documentation search does not. Until the
deployment context is stated, Chapter III applicability is undetermined.

**The timeline is still moving.** The Omnibus was adopted in June 2026 and entered
into force in July; implementing guidance, harmonised standards, and the
transparency Code of Practice continue to develop. <cite index="26-1">The specific technical standards for machine-readable marking are being developed through the Code of Practice and complementary EU standardisation work.</cite> Re-verify dates against the Official Journal text and the Commission's published guidelines before relying on this table.

**Several claims in this document are corrections to the prior version**, not new
gaps. They were surfaced by independent MAESTRO and governance assessments of the
same system. A compliance mapping that reports a capability the threat model
records as partial is the failure mode this revision exists to correct.
