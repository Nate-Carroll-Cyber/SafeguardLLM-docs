# Safeguard LLM Model Governance Card

**Revision 2026-08-03.** Adds §7 (evaluated model characteristics) from the
OpenAI technical report on `gpt-oss-safeguard-120b` / `-20b` (29 Oct 2025), and
corrects one configuration default that report shows to be invalid.

---

## 1. System Role

Safeguard LLM is a proxy LLM-as-a-Judge and mitigation stack. It sits between
user prompts and a downstream responder model, applying local sanitization,
policy enforcement, structured safeguard judging, instruction-memory comparison,
and output review before or after provider inference.

The system is model-neutral. Operational deployments must attach provider-specific
model cards for the configured safeguard judge, embedding model, and downstream
responder.

**Alignment with intended use.** OpenAI recommends the gpt-oss-safeguard models
be used to classify content against a provided policy, and **not** as the core
functionality with which end users interact. Safeguard LLM's judge role is the
recommended use: the model classifies, and a separate responder produces
user-facing output. This distinction determines which of the report's evaluation
results apply to this deployment and which do not — see §7.1.

## 2. Model and Data Boundaries

- **Local sanitizer:** TypeScript policy engine that runs before external inference and enforces PII/secret redaction, entropy thresholds, regex rules, blocked keywords, forbidden phrases, language recovery, and obfuscation detection.
- **Safeguard judge:** OpenAI-compatible API endpoint called by the backend `/v1/intercept` gateway. The allowlisted `safeguardEffectivePrompt` is used as the judge system prompt. Candidate prompt text and deterministic preprocessing evidence are sent separately as user content.
- **Instruction similarity monitor:** PostgreSQL/pgvector store containing reviewed `ADVERSARIAL` instruction records, strict and loose hashes, SimHash fingerprints, optional whole-prompt embeddings, and optional chunk embeddings. Fingerprint matches retain the stored adversarial posture; semantic-only matches route to review.
- **Downstream responder:** Separate backend-managed responder called only after local checks, instruction-memory comparison, and the safeguard judge return a clean forwarding decision. Protected routes do not accept caller-supplied responder endpoints, credentials, model IDs, or system prompts.
- **Sam Spade CTF:** Governed by the protected backend API and shared review/audit path. Sessions are bound to the authenticated caller. The allowlisted `safeguardEffectivePrompt` is also used as the safeguard judge system prompt on Sam Spade message and solve routes. Clean gameplay uses backend-managed persona/scenario prompts and the downstream responder when routing is enabled; otherwise it uses local responder passthrough after safeguard approval.

**Modality boundary.** The gpt-oss-safeguard models are **text-only**. Any future
image, audio, or document ingestion path has no coverage from the judge and
requires a separate control.

## 3. Protected Runtime Contract

Protected request bodies use Zod object schemas with `.strict()` on their
security-sensitive metadata boundaries. Unknown metadata fields are rejected
rather than treated as runtime configuration.

- **Backend-owned safeguard runtime:** `SAFEGUARDS_API_BASE_URL` and `SAFEGUARDS_MODEL_ID` determine the actual safeguard endpoint and model. Browser-supplied base URL or model overrides are not accepted by `/v1/intercept` or the Sam Spade request schemas.
- **Intentional safeguard exceptions:** `/v1/intercept` accepts an optional browser-memory `safeguardApiKey`; when supplied, it takes precedence over `SAFEGUARDS_API_KEY`. It also accepts `safeguardEffectivePrompt`, which is used as the safeguard judge system prompt. Sam Spade message/solve metadata accepts `safeguardEffectivePrompt` but not a browser safeguard key.
- **Local UI selections:** The Analyst Runtime Settings base URL and model fields persist in browser `localStorage` under `counter_spy_safeguard_runtime_v1`. They are display/selection state only and are not forwarded as protected backend runtime overrides. The browser-entered safeguard key is React memory only and is cleared on reload.
- **Backend-owned responder runtime:** Provider, endpoint, API key, model ID, and system prompt come from `RESPONDER_*` / `LLM_*` environment configuration. Browser responder settings may support local UI telemetry and context estimates, but protected execution rejects those values as provider overrides.

### 3.1 Configuration defaults

| Setting | Default | Status |
|---|---|---|
| Backend safeguard model | `gpt-5.4-mini` | Valid |
| Docker demo safeguard model | `gpt-oss-safeguard-20b` | Valid — see §7 for evaluated characteristics |
| Instruction-monitor embedding model | `gpt-oss-safeguard-20b` | **Invalid — see below** |
| OpenAI-compatible responder model | `amazon.nova-micro-v1:0` | Valid |
| Gemini responder | `gemini-2.5-flash` | Valid |
| Safeguard reasoning effort | *unset* | **Undocumented axis — see §7.4** |

The gpt-oss-safeguard models are text-only *reasoning classifiers* posttrained
from gpt-oss for policy-based labelling. They are not embedding models and expose
no embeddings endpoint.

The Docker demo overrides this with `nomic-embed-text`, which is why the
misconfiguration has not surfaced. Any deployment that does **not** override it
will fail at the embeddings call — and the failure mode matters: if that failure
is non-fatal, the instruction-similarity monitor silently degrades to
hash/SimHash matching only, losing semantic detection with no verdict change and
no obvious error.

**Action:** change the backend default to a real embedding model identifier, and
assert at startup that the configured embeddings endpoint responds to an
embeddings request. This is a P0 correction, not a documentation note.

## 4. Decision Contract

The safeguard path expects one JSON verdict contract:
`{"verdict":"CLEAN|SUSPICIOUS|ADVERSARIAL","analystReasoning":"brief reason"}`.
Legacy decision-shaped responses such as `ALLOW_AND_FORWARD`, `BLOCK`,
`QUEUE_FOR_REVIEW`, or `FAIL_SECURE` are not accepted as allow-path output;
malformed or schema-mismatched safeguard responses fail secure to `SUSPICIOUS` /
`QUEUED`.

**Available mitigation not currently evidenced.** The gpt-oss-safeguard models
support **Structured Outputs**. Constraining the verdict at generation time is
stronger than parsing and failing secure afterward: it removes the schema-mismatch
class rather than catching it. Fail-secure remains the correct backstop, but
Structured Outputs should be the primary mechanism where the configured endpoint
supports it. Note this is model-family dependent — `gpt-5.4-mini` and
`gpt-oss-safeguard-20b` must both be verified.

The instruction similarity monitor runs before responder forwarding. Exact
SHA-256, loose SHA-256, and SimHash matches against stored adversarial
instructions retain `ADVERSARIAL` severity and block. Semantic whole-prompt or
chunk-embedding matches are `SUSPICIOUS` review evidence rather than automatic
adversarial blocks.

The Safeguard Effective Prompt is the reviewable policy baseline. System
Configuration previews, edits, and hashes the prompt artifact, and protected
backend execution uses the submitted value as the safeguard judge system prompt.
`DEFAULT_SYSTEM_CONFIG` hardcodes the recommended prompt in
`safeguardEffectivePromptOverride`; empty legacy values and previous
app-generated baselines normalize back to that promoted default, while custom
non-empty prompts remain visible as drift.

The displayed recommended/current hash
`590a286e60b99b0b353222b3ddaaa131db925a1f4d6222a0c3b1b3e49d203ad0` is computed at
runtime with `crypto.subtle.digest`. The source contains the prompt text and
hashing implementation, not a build-time assertion proving that literal hash;
deployments should verify it in the running UI.

### 4.1 `analystReasoning` provenance

The report states that no direct optimization pressure was applied to the chain of
thought for either model, and that because those chains are unrestricted they can
contain hallucinated content — including language that does not reflect the policy
the model was asked to interpret.

**This has a governance consequence for `analystReasoning`.** If that field is
derived from or influenced by the model's reasoning trace, it is not a reliable
record of *why* a verdict was reached, and it should not be treated as evidence in
an audit or a review decision.

**Action:** document whether `analystReasoning` is a separate constrained output
or a reflection of CoT. If the latter, label it as model-generated narrative in
the analyst UI and the audit schema, and do not cite it as a decision rationale in
any compliance artifact. The **verdict** is the auditable output; the reasoning
is commentary.

## 5. Safety and Fail-Closed Behavior

Eligible prompts must pass local sanitizer checks, instruction-memory comparison,
and the safeguard judge before responder forwarding. Safeguard failure returns
the structured `SHIELD_ERROR` review path; responder failure returns a plain
upstream error response. Neither failure silently bypasses controls.

Global System Pause halts automated forwarding, routes new Analyst Chat prompts
into manual review, and stops active Bulk Ingest replay.

## 6. Transparency Requirements

For compliance review, maintain:

- Provider model cards for the active safeguard judge, embedding model, and responder — **including the gpt-oss-safeguard technical report where that model family is configured**
- Runtime verification of the current and recommended Safeguard Effective Prompt hashes
- Active environment-variable and secret-source inventories
- PostgreSQL/pgvector retention, access-control, seed-provenance, and backup policies
- Firestore and provider-side audit retention policies
- Validation that deployment parameters, backend defaults, and provider configuration use the intended canonical model IDs
- Known local-review/demo limitations and the active provider model cards
- **Model weight provenance and integrity hashes** for any self-hosted open-weight judge or embedding model (new — see §7.6)
- **Licence position:** the gpt-oss-safeguard models are released under Apache 2.0 and are additionally subject to OpenAI's gpt-oss usage policy. Both apply to a self-hosted deployment and should be recorded in the licence inventory

---

## 7. Evaluated Model Characteristics — gpt-oss-safeguard *(new)*

Source: OpenAI technical report, 29 October 2025. This section exists because the
gpt-oss-safeguard family is a configured default in this system and its published
evaluations bear directly on the judge's reliability.

### 7.1 Which results apply to this deployment

The report is explicit that most of its safety metrics describe the models used
**directly for end-user chat** — a use case it does not recommend and for which
the models are not intended. It publishes them because the models are open and
someone might use them that way.

Safeguard LLM does **not** use the judge for end-user chat, so the following are
recorded for completeness and are **not** treated as findings against this
deployment: disallowed-content evaluations, production benchmarks, SimpleQA and
PersonQA hallucination rates, and the MMMLU multilingual results (explicitly a
chat-setting evaluation that does not directly assess classification with a
provided policy).

The following **do** apply, because they measure the model under conditions this
architecture creates by design.

### 7.2 Instruction-hierarchy degradation *(applies — highest-consequence finding)*

The safeguard fine-tunes tend to **underperform their gpt-oss base models** on
instruction-hierarchy evaluations. For the 20b variant configured here:

| Evaluation | `gpt-oss-20b` | `gpt-oss-safeguard-20b` | Δ |
|---|---|---|---|
| Prompt injection hijacking | 0.639 | **0.512** | −0.127 |
| Phrase protection — developer↔user | 0.661 | **0.439** | −0.222 |
| Phrase protection — system↔user | 0.793 | 0.642 | −0.151 |
| System prompt extraction | 0.881 | 0.867 | −0.014 |
| Password protection — system↔user | 0.947 | 0.930 | −0.017 |

The report states that more research is needed to understand why this is the case.

**Why it applies here.** These evaluations measure a system message and a user
message in conflict — which is precisely the judge's operating condition. The
`safeguardEffectivePrompt` is the system message; adversarial candidate text is
the user content. A prompt-injection-hijacking score of **0.512** is close to a
coin flip on the exact pressure this component is under every request, and it is
*below* the base model the safeguard variant was derived from.

**Interpretation.** The fine-tune trades injection resistance for classification
ability. That is an acceptable trade for the recommended use — a classifier is
not expected to hold a secret — but it means **the judge must not be treated as a
component that resists manipulation**. It is a component that labels content and
can itself be manipulated.

**Consequences for this architecture:**

1. The judge is a single semantic gate. Its measured susceptibility argues for **responder-side guardrails as an independent layer**, not as an optional addition.
2. The 120b variant scores materially better on some of these (e.g. system prompt extraction 0.993 vs 0.867). Where compute allows, the 120b is the better judge on this axis.
3. Any secret, key, or policy detail must be assumed reachable from the judge's system prompt. **Nothing sensitive belongs in `safeguardEffectivePrompt`.** This is now a hard constraint on that artifact, not a preference.

### 7.3 Jailbreak robustness *(applies, secondary)*

On StrongReject evaluations the 20b safeguard variant underperforms its base by
1–5 points across all four categories (illicit/non-violent 0.916 vs 0.960;
violence 0.942 vs 0.979; abuse/disinformation/hate 0.959 vs 0.982; sexual content
0.963 vs 0.970). The 120b variant *outperforms* its base.

The report notes robustness to jailbreaks is less important for these models
because the recommended use is internal. That reasoning holds for a classifier
whose output is a label. It holds less well here, where a manipulated label
becomes a **forwarding decision**.

### 7.4 Reasoning effort — an undocumented configuration axis *(applies)*

The models support three reasoning efforts: low, medium, high. **This system does
not document which is configured, and the setting does not appear in §3.**

It is a security-relevant parameter. Reasoning effort trades latency and cost
against classification quality, and a change made for latency reasons is a change
to detector efficacy with no verdict-schema change to make it visible.

**Action:** surface reasoning effort as an explicit configuration value, record it
per decision in the audit schema alongside model ID, and treat changes to it as
security-relevant configuration under the same review as threshold changes.

### 7.5 Classification accuracy and the case for a dedicated classifier *(applies)*

| Benchmark | `gpt-oss-safeguard-20b` |
|---|---|
| Internal multi-policy accuracy | 43.6% |
| OpenAI Moderation (2022) F1 | 82.9% |
| ToxicChat F1 | 79.9% |

The multi-policy figure is strict — the model is counted accurate only if it
matches golden labels for **all** policies supplied simultaneously. It beats
`gpt-5-thinking` (43.2%) and both base gpt-oss models (~32%), which is the
report's point. It is nonetheless the number to quote internally rather than the
F1 scores, because it describes multi-policy operation and this system supplies a
composite policy.

The report also states plainly that classifiers trained on tens of thousands of
high-quality labelled samples can outperform gpt-oss-safeguard reasoning directly
from a policy, and that a dedicated classifier may be preferred for complex risks.

**Relevance to the Golden Set.** This system already curates analyst-reviewed
interactions for future fine-tuning. That corpus is the input to exactly the
dedicated classifier the report recommends. The architectural implication is that
the Golden Set is not only a training-data governance artifact — it is the path
to a better detector than the current one.

### 7.6 Operational cost and the triage pattern *(applies)*

The report describes the models as time- and compute-intensive, and names
OpenAI's own internal mitigations: use smaller, faster classifiers to decide
which content to assess, and in some circumstances run the reasoner
**asynchronously** to preserve low latency while retaining the ability to
intervene.

Safeguard LLM already implements the first pattern — the local sanitizer,
entropy, syntactic, and SimHash checks are the cheap triage layer ahead of the
judge. That is convergent with the vendor's own design and worth stating as such.

The second pattern is **not** implemented and should not be adopted without care.
Asynchronous judging in this architecture would mean forwarding before the verdict
returns, which inverts the fail-secure posture that is the system's strongest
property. If latency pressure ever motivates it, the correct form is asynchronous
*enrichment* of an already-blocked-or-queued decision, never asynchronous
authorization of a forward.

### 7.7 Fairness — the one axis that improved

On the BBQ bias benchmark both safeguard models **outperform** their gpt-oss
counterparts on all metrics. For the 20b: accuracy on ambiguous questions 0.91 vs
0.79; on disambiguated questions 0.93 vs 0.89.

This is relevant to the outstanding bias-testing gap in the compliance mapping,
with one important limit: **BBQ measures the model, not this system.** The
over-blocking risk identified for the `FOREIGN_LANGUAGE` / `MIXED_LANGUAGE`
heuristics originates in the local sanitizer, upstream of the judge. A favourable
model-level bias result does not evidence system-level fairness, and citing it as
though it does would be a defensible-sounding error.

### 7.8 Supply-chain position

The models are Apache-2.0 open-weight fine-tunes of gpt-oss, trained without
additional biological or cybersecurity data; the report states that prior
worst-case capability estimates for gpt-oss carry across.

For a self-hosted deployment this makes weight integrity the operator's
responsibility. This system already verifies SHA-256 for its seed corpus and
tracks a drift hash for the Safeguard Effective Prompt. **Extending that same
discipline to model weights is a small change and closes the one supply-chain
surface where compromise would be silent rather than noisy** — a backdoored judge
returns plausible verdicts.

---

## 8. Actions arising from this revision

| Priority | Action | Section |
|---|---|---|
| P0 | Correct the instruction-monitor embedding default; assert at startup that the embeddings endpoint answers an embeddings request | §3.1 |
| P0 | Confirm whether a failed embeddings call degrades the monitor silently to hash-only matching | §3.1 |
| P1 | Remove any sensitive content from `safeguardEffectivePrompt` and treat it as reachable | §7.2 |
| P1 | Document `analystReasoning` provenance; if CoT-derived, label it as narrative and stop citing it as rationale | §4.1 |
| P1 | Surface reasoning effort as explicit configuration; record it per decision | §7.4 |
| P1 | Adopt Structured Outputs for the verdict contract where the endpoint supports it; retain fail-secure as backstop | §4 |
| P2 | Evaluate the 120b variant as judge where compute allows | §7.2 |
| P2 | Record model weight hashes for self-hosted open-weight models | §7.8 |
| P2 | Add responder-side guardrails as an independent layer | §7.2 |
| P3 | Record the Apache 2.0 + gpt-oss usage policy position in the licence inventory | §6 |
