# MITRE ATLAS Organizer Mapping

## Purpose

This document records the current **MITRE ATLAS organizer taxonomy** used by Safeguard LLM for prompt research, heat-map visualization, and analyst labeling.

The taxonomy is now driven by the accumulated test corpus rather than the earlier smaller candidate set.

## Corpus Snapshot

- **Total example prompts:** 569
- **Sections containing prompts:** 97
- **Average prompts per section:** 5.9
- **Max prompts in a single section:** 10
- **Min prompts in a single section:** 5

## Labeling Model

Use the following fields in research exports and future analyst workflows:

| Field | Type | Purpose |
| :--- | :--- | :--- |
| `atlasTactic` | `string` | Top-level ATLAS organizer shown in the UI |
| `atlasTechniqueId` | `string` | Canonical organizer node ID |
| `atlasTechniqueName` | `string` | Canonical organizer node label |
| `localArchetype` | `string?` | Optional analyst shorthand for a more specific attack pattern |
| `taxonomyConfidence` | `number?` | Confidence in the selected mapping |
| `taxonomyNotes` | `string?` | Analyst notes on ambiguity, rationale, or prompt-specific nuance |

## Active Organizer Set

The current corpus is organized around **16 top-level MITRE ATLAS tactics/techniques**:

| ATLAS Node | Organizer Label | What's mapped there |
| :--- | :--- | :--- |
| `TA0000` | `Reconnaissance` | API Enumeration, Tool Enumeration, Model Fingerprinting |
| `TA0004` | `ML Model Access` | API Request input vector, API Query Stealing |
| `TA0005` | `Execution` | Attack External/Internal Systems, Code Execution, Malicious Workflows, Fraudulent Use |
| `TA0006` | `Privilege Escalation` | Unauthorized Access, Token Manipulation, Protocol Manipulation |
| `TA0007` | `Persistence` | Memory System Persistence, Config Persistence, Replay Exploitation |
| `TA0009` | `Exfiltration` | Data/Info Disclosure, Attack External/Internal Users, Eavesdropping |
| `T0020` | `Poison Training Data` | Data Poisoning, Reinforcement Biasing, Backdoors/Trojans |
| `T0024` | `Invert/Infer Model` | Test Bias, Inversion, CoT Introspection, Model Extraction |
| `T0029` | `Denial of Service` | DoS intent, Cognitive Overload, disruption subtechniques |
| `T0031` | `Evade ML Model` | Environment-Aware Evasion, Truncation/Misspell, Synonyms |
| `T0043` | `Adversarial Attack` | Gradient Attacks such as GCG, AutoDAN, PAIR, TAP |
| `T0048` | `External Harms` | Unauthorized professional advice, business integrity, discuss-harm patterns, 15.x subtechniques |
| `T0051` | `Prompt Injection` | Direct/indirect injection intents, techniques, input vectors, and encoding-based evasions |
| `T0054` | `LLM Jailbreak` | Jailbreak, CBRNE, Narrative Injection, Anti-Refusal, Priming, Bijection |
| `T0055` | `Plugin Compromise` | Tool Exploitation, Dependency Compromise, Fusion Payload Split |
| `T0058` | `Exfiltration via Tool` | Tool-mediated exfiltration attempts |

## Guidance

### 1. Label by the Organizer That Best Matches the Prompt's Primary Adversarial Goal

Choose the single ATLAS organizer that best captures the prompt's main behavior or intended outcome.

### 2. Use `localArchetype` for Finer-Grained Research Labels

The organizer taxonomy is intentionally coarse enough to power heat maps and trend reporting.

Use `localArchetype` for narrower internal distinctions such as:

- `api_enumeration`
- `tool_enumeration`
- `model_fingerprinting`
- `gradient_attacks`
- `cognitive_overload`
- `token_manipulation`
- `plugin_compromise`
- `tool_exfiltration`

### 3. Preserve Legacy Labels for Backward Compatibility

Older Playground snapshots and experimental annotations may still contain the earlier ATLAS set (for example `AML.T0068`, `AML.T0086`, or `AML.T0110`).

Those values remain accepted by schema validation so historical local data is not silently dropped, but the **16-node organizer set above is the active taxonomy going forward**.

## Implementation Note

The app currently uses these organizers as the active set for:

1. MITRE ATLAS annotation selection in the Prompt Playground
2. Metrics heat-map layout
3. Audit/export taxonomy fields

This keeps research labeling, UI review, and exported data aligned to the same corpus-driven structure.
