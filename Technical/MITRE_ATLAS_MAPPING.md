# MITRE ATLAS Organizer Mapping

## Purpose

This document records the MITRE ATLAS organizer taxonomy used by Safeguard LLM for prompt research, heat-map visualization, and analyst labeling. Organizer labels remain stable for stored UI records, while IDs and official names track the current ATLAS nodes represented by those organizers.

## Corpus Snapshot

The 569-prompt taxonomy snapshot is an **external research corpus and is not included in this repository**. It is separate from the bundled 319-record pgvector `core` seed pack.

- **Total example prompts:** 569
- **Sections containing prompts:** 97
- **Average prompts per section:** 5.9
- **Max prompts in a single section:** 10
- **Min prompts in a single section:** 5

## Labeling Model

| Field | Type | Purpose |
| :--- | :--- | :--- |
| `atlasTactic` | `string` | Stable organizer label shown in the UI and stored records |
| `atlasTechniqueId` | `string` | Current ATLAS tactic or technique ID |
| `atlasTechniqueName` | `string` | Official ATLAS name for that ID |
| `localArchetype` | `string?` | Optional narrower analyst shorthand |
| `taxonomyConfidence` | `number?` | Confidence in the selected mapping |
| `taxonomyNotes` | `string?` | Analyst notes on ambiguity or rationale |

## Active Organizer Set

| ATLAS Node | Organizer Label | Official ATLAS Name | What's mapped there |
| :--- | :--- | :--- | :--- |
| `TA0002` | `Reconnaissance` | `Reconnaissance` | API Enumeration, Tool Enumeration, Model Fingerprinting |
| `TA0000` | `ML Model Access` | `AI Model Access` | API Request input vector, API Query Stealing |
| `TA0005` | `Execution` | `Execution` | Attack External/Internal Systems, Code Execution, Malicious Workflows, Fraudulent Use |
| `TA0012` | `Privilege Escalation` | `Privilege Escalation` | Unauthorized Access, Token Manipulation, Protocol Manipulation |
| `TA0006` | `Persistence` | `Persistence` | Memory System Persistence, Config Persistence, Replay Exploitation |
| `TA0010` | `Exfiltration` | `Exfiltration` | Data/Info Disclosure, Attack External/Internal Users, Eavesdropping |
| `T0020` | `Poison Training Data` | `Poison Training Data` | Data Poisoning, Reinforcement Biasing, Backdoors/Trojans |
| `T0024` | `Invert/Infer Model` | `Exfiltration via AI Inference API` | Test Bias, Inversion, CoT Introspection, Model Extraction |
| `T0029` | `Denial of Service` | `Denial of AI Service` | DoS intent, Cognitive Overload, disruption subtechniques |
| `T0015` | `Evade ML Model` | `Evade AI Model` | Environment-Aware Evasion, Truncation/Misspell, Synonyms |
| `T0043` | `Adversarial Attack` | `Craft Adversarial Data` | Gradient attacks such as GCG, AutoDAN, PAIR, TAP |
| `T0048` | `External Harms` | `External Harms` | Unauthorized professional advice, business integrity, discuss-harm patterns, 15.x subtechniques |
| `T0051` | `Prompt Injection` | `LLM Prompt Injection` | Direct/indirect injection intents, input vectors, encoding-based evasions |
| `T0054` | `LLM Jailbreak` | `LLM Jailbreak` | Jailbreak, CBRNE, Narrative Injection, Anti-Refusal, Priming, Bijection |
| `T0053` | `Plugin Compromise` | `AI Agent Tool Invocation` | Tool Exploitation, Dependency Compromise, Fusion Payload Split |
| `T0086` | `Exfiltration via Tool` | `Exfiltration via AI Agent Tool Invocation` | Tool-mediated exfiltration attempts |

## Guidance

Choose the organizer that best captures the prompt's primary adversarial goal. Use `localArchetype` for narrower internal distinctions such as `api_enumeration`, `gradient_attacks`, `token_manipulation`, `plugin_compromise`, or `tool_exfiltration`.

Organizer labels intentionally remain unchanged where changing them would break historical UI and export continuity. The official name column is the source of truth for the selected current ATLAS ID.

### Legacy Annotation Values

Older Playground snapshots may contain locally namespaced values such as `AML.T0068`, `AML.T0086`, or `AML.T0110`. The unprefixed techniques `T0068`, `T0086`, and `T0110` are valid current ATLAS techniques; **legacy** here describes Safeguard LLM's older local annotation representation, not the validity of those ATLAS techniques. The historical values remain accepted so browser-local data is not silently dropped.

## Implementation Note

`src/lib/atlasTaxonomy.ts` drives annotation selection, Metrics heat-map layout, and audit/export taxonomy fields. The active table above mirrors that code exactly.
