# Adversarial Prompt Analysis Plan

## Purpose

This document defines a practical research plan for turning Counter-Spy.ai prompt traffic into defensive insights without redistributing harmful material irresponsibly.

The goal is not just to store prompts, but to:

- identify attack patterns over time
- evaluate detection effectiveness across the current firewall pipeline
- surface failure cases that should improve system design
- generate a defensible write-up for engineering, security, and portfolio use

## Scope

This analysis should focus on prompts observed or generated in defensive testing contexts, including:

- `analyst_chat`
- `playground`
- `bulk_ingest`
- `ctf_chat`

Whenever possible, raw prompt content should remain restricted to authorized reviewers. Published outputs should prefer hashes, summaries, pattern labels, and sanitized excerpts over full prompt redistribution.

## Research Questions

### 1. Attack Pattern Taxonomy

How should prompts be grouped into meaningful adversarial categories?

Initial taxonomy:

- role-play jailbreaks
- instruction override (`ignore previous instructions`, `disregard prior system prompt`, etc.)
- encoding / obfuscation
- multi-step coercion
- tool / agent exploitation
- data exfiltration
- indirect policy evasion
- staged prompt chaining

### 2. Trend Analysis

What is changing over time?

Key trend questions:

- which attack classes are increasing month-over-month
- whether prompts are becoming longer or more obfuscated
- whether attacks are shifting from direct override to indirect manipulation
- whether `bulk_ingest`, `playground`, and `analyst_chat` show different pattern distributions

### 3. Entropy vs Attack Type

How well does entropy correlate with specific adversarial techniques?

Key questions:

- do high-entropy prompts correlate with successful evasion
- which attack classes are well-captured by entropy thresholds
- which low-entropy attacks still bypass or under-trigger the pipeline

### 4. Detection Effectiveness

How often does each control catch adversarial traffic?

Measure:

- caught by keyword filtering
- caught by topic filtering
- caught by regex rules
- caught by entropy
- caught by syntactic analyzer
- caught only after decode / obfuscation normalization
- missed entirely

### 5. Failure Cases

Which prompts bypassed or under-triggered the system, and why?

Each failure case should capture:

- attack category
- expected severity
- observed severity
- why the prompt worked
- which controls failed
- what mitigation was added or recommended

## Proposed Dataset Schema

The current audit log already captures much of what we need. For analysis, derive or preserve the following schema:

| Field | Type | Notes |
| :--- | :--- | :--- |
| `id` | `string` | Unique record ID |
| `timestamp` | `datetime` | Event timestamp |
| `source` | `enum` | `analyst_chat`, `playground`, `bulk_ingest`, `ctf_chat` |
| `promptHash` | `string` | SHA-256 of raw or canonicalized prompt |
| `isRetry` | `boolean?` | True when the backend has seen the same sanitized prompt hash in the recent retry window |
| `retryOfHash` | `string?` | Prompt hash pointer for recent duplicate/replay submissions |
| `sanitizedPrompt` | `string` | Restricted-use only |
| `promptLength` | `number` | Character count |
| `lineCount` | `number` | Number of lines |
| `wordCount` | `number` | Number of tokens/words, approximate is fine |
| `entropy` | `number` | Max entropy observed |
| `globalEntropy` | `number` | Whole-prompt entropy |
| `syntacticScore` | `number` | Constraint/probing heuristic score |
| `decodeTelemetry` | `enum` | `plain_text`, `single_hop_decode`, `recursive_decode` |
| `detectionFlags` | `string[]` | Full detection/redaction flags |
| `detectionLevel` | `enum` | Clean, Informational, Suspicious, Adversarial |
| `status` | `string` | e.g. `PENDING_REVIEW`, reviewed |
| `resultantSeverity` | `enum?` | Analyst-reviewed severity when present |
| `expectedVerdict` | `enum?` | Especially useful for `bulk_ingest` |
| `batchId` | `string?` | Bulk ingest campaign grouping |
| `backendGatewayStatus` | `enum?` | `/v1/intercept` outcome: `CLEAN`, `INTERCEPTED`, `QUEUED`, or `SHIELD_ERROR` |
| `backendSafeguardVerdict` | `enum?` | Backend safeguard judge verdict when the prompt reached that layer |
| `backendSafeguardReasoning` | `string?` | Safeguard judge or fail-secure reason surfaced by the backend |
| `safeguardSchemaShape` | `enum?` | Runtime safeguard output shape: `verdict`, `decision`, or `malformed` from structured gateway logs |
| `safeguardDivergent` | `boolean?` | True when the gateway action diverged from the expected verdict-to-action mapping |
| `safeguardRawReasoningTrace` | `string?` | Optional provider-exposed reasoning trace lifted into structured gateway logs for security review |
| `backendReachedSafeguard` | `boolean?` | True when the local layer allowed the prompt into the backend safeguard path |
| `localPrecheckLatencyMs` | `number?` | Backend deterministic precheck latency for prompts that reached `/v1/intercept` |
| `backendSafeguardLatencyMs` | `number?` | Pure safeguard judge call latency, excluding local precheck and responder time |
| `backendGatewayLatencyMs` | `number?` | Total backend gateway latency for the intercept request |
| `instructionEmbeddingDurationMs` | `number?` | Backend instruction-monitor embedding duration for pgvector/Ollama requests |
| `responderLatencyMs` | `number?` | Downstream responder latency; local responder passthrough records `0` |
| `failSecureFlags` | `string[]?` | Derived from `SAFEGUARD_TIMEOUT`, `SAFEGUARD_ERROR`, `FAIL_SECURE`, and `ReDoS_ATTEMPT_DETECTED` flags |
| `atlasTactic` | `string?` | Active MITRE ATLAS organizer shown in the UI |
| `atlasTechniqueId` | `string?` | Canonical ATLAS organizer node ID |
| `atlasTechniqueName` | `string?` | Canonical ATLAS organizer node label |
| `localArchetype` | `string?` | Optional analyst shorthand |
| `taxonomyConfidence` | `number?` | Optional analyst confidence |
| `taxonomyNotes` | `string?` | Optional analyst rationale |
| `isFailureCase` | `boolean` | Marked when pipeline missed or under-classified |
| `failureReason` | `string?` | Brief analyst summary |

## Labeling Strategy

Use a staged approach rather than trying to label everything perfectly upfront.

Canonical labels should be anchored to **MITRE ATLAS** wherever possible. For the active organizer taxonomy now used by the app and research workflow, see [MITRE ATLAS Organizer Mapping](./MITRE_ATLAS_MAPPING.md).

### Phase 1: Heuristic Pre-Labeling

Use existing signals to propose labels:

- blocked keyword hits -> instruction override
- `OBFUSCATED_INSTRUCTION` or decode telemetry -> encoding / obfuscation
- `BINARY_ENCODING`, `ASCII_DECIMAL`, `A1Z26`, `PIG_LATIN`, `VERTICAL_TEXT`, or recursive decode telemetry -> encoding / structural obfuscation
- `SAFEGUARD_TIMEOUT`, `SAFEGUARD_ERROR`, or `FAIL_SECURE` -> safeguard resilience / fail-secure event
- MCP / A2A hard-block phrases -> tool / agent exploitation
- excessive verbosity + roleplay markers -> role-play jailbreak

### Phase 2: Analyst Review

Add a manual label for high-value samples:

- adversarial detections
- suspicious detections
- false negatives
- high-latency / ReDoS cases

### Phase 3: Curated Research Set

Promote representative samples into a smaller high-confidence set for:

- charts
- write-ups
- threshold tuning
- future model evaluation

## Metrics to Generate

### Core Counts

- total prompts by month
- prompts by source
- prompts by detection level
- prompts by taxonomy label

### Detection Metrics

- keyword catch rate
- topic catch rate
- regex catch rate
- entropy catch rate
- syntactic catch rate
- decode-assisted catch rate
- backend safeguard/model-intervention catch rate
- overall miss rate

### Review Metrics

- false positive rate
- false negative rate
- analyst disagreement rate
- top upgrade paths (`Suspicious -> Adversarial`, etc.)

### Complexity Metrics

- average prompt length by taxonomy
- average entropy by taxonomy
- average syntactic score by taxonomy
- decode telemetry distribution by taxonomy

## Charts to Produce

Start simple. Two to five good charts are enough.

### Recommended Initial Charts

1. **Attack Category Volume Over Time**
   - x-axis: month
   - y-axis: count
   - series: taxonomy labels

2. **Detection Coverage by Control**
   - bar chart
   - keyword / topic / regex / entropy / syntactic / decode-assisted / safeguard judge / missed

3. **Entropy vs Attack Type**
   - box plot or grouped bar chart
   - compare average/max entropy across categories

4. **Failure Case Distribution**
   - stacked bar
   - by taxonomy label and miss / under-classification type

5. **Prompt Complexity Trend**
   - average prompt length and syntactic score over time

## Current Playground Workflow

The Prompt Playground now supports a deliberate language pipeline for defensive testing:

1. optional spelling normalization for garbled natural-language prompts
2. foreign-language translation of the normalized prompt
3. post-translation evasions and wrappers

The intended order is:

`garbled prompt -> normalize -> translate -> add evasions`

Do not normalize or translate already-encoded payloads. Those transforms should stay in the natural-language stage only.

## Implementation Plan

### Phase A: Data Readiness

1. confirm audit export path
2. add any missing derived fields needed for research
3. preserve prompt hashes for longitudinal comparison

### Phase B: Taxonomy

1. define canonical taxonomy labels
2. create heuristic pre-labeling rules
3. add analyst-reviewed labeling workflow for high-value samples

### Phase C: Analysis Pipeline

1. compute summary tables
2. compute detection effectiveness metrics
3. identify failure cases
4. generate charts

### Phase D: Reporting

1. create a short write-up
2. summarize findings
3. document limitations and handling rules

## Handling and Safety Rules

This research should be framed as defensive analysis.

Rules:

- do not publish raw harmful prompts unless explicitly required and appropriately redacted
- prefer hashes, taxonomy summaries, and sanitized excerpts
- restrict access to raw datasets
- document whether examples are synthetic, red-teamed, or observed in analyst workflow
- clearly distinguish manually reviewed labels from heuristic labels

## Suggested Repo Deliverables

Recommended outputs:

- `Technical/ADVERSARIAL_PROMPT_ANALYSIS.md` (this plan)
- `Technical/research/analysis-report.md` or similar
- exported chart images or notebook outputs
- sanitized CSV/JSON summaries

## Draft Write-Up Outline

Suggested report title:

**Emerging Patterns in LLM Jailbreak Prompts: A Longitudinal Defensive Analysis**

Suggested sections:

1. **Executive Summary**
   - key findings
   - major trends
   - most important failure modes

2. **Dataset Description**
   - sources
   - timeframe
   - inclusion / exclusion criteria
   - safety handling approach

3. **Methodology**
   - taxonomy design
   - labeling process
   - detection pipeline used
   - limitations

4. **Attack Taxonomy**
   - category definitions
   - representative sanitized examples

5. **Trend Analysis**
   - charts
   - changes over time

6. **Detection Effectiveness**
   - what each control catches
   - what each control misses

7. **Failure Cases**
   - bypasses
   - under-classifications
   - recommended mitigations

8. **Design Implications**
   - threshold tuning
   - new heuristics
   - future product changes

9. **Conclusion**
   - what the data suggests about evolving jailbreak behavior

## Recommended First Milestone

To keep this tractable, the first milestone should be:

1. define taxonomy labels
2. export a defensible sample dataset
3. generate:
   - attack category counts
   - detection coverage by control
   - three curated failure cases
4. write a one-page findings summary

That is enough to produce an initial research artifact without overbuilding the pipeline.
